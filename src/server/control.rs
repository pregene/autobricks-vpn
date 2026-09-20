use super::decrypt::create_stateless_acceptor;
use super::session::Session;
use super::{poll, StopOnDrop, UdpDatagram, HANDSHAKE_TIMEOUT, RUNNING, SESSION_IDLE_TIMEOUT};
use autobricks_vpn::base::queue::Queue;
use autobricks_vpn::{panic_gate, parse_ini_entries, validate_client_bindings, Config, Dtls};
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::io;
use std::io::{Read, Write};
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(super) struct ControlSocket {
    listener: UnixListener,
    wake_reader: UnixDatagram,
    wake_writer: Arc<ControlWake>,
    pending: Vec<PendingCommand>,
    path: String,
    watchers: Vec<Watcher>,
    last_identity: String,
    identity_scratch: String,
}

struct PendingCommand {
    stream: UnixStream,
    bytes: [u8; 256],
    len: usize,
    accepted_at: Instant,
}

struct Watcher {
    stream: UnixStream,
    pending: Vec<u8>,
    written: usize,
    next: Option<Vec<u8>>,
}

impl Watcher {
    fn new(stream: UnixStream, snapshot: Vec<u8>) -> Self {
        Self {
            stream,
            pending: snapshot,
            written: 0,
            next: None,
        }
    }

    fn enqueue_latest(&mut self, snapshot: &[u8]) {
        if self.pending.is_empty() {
            self.pending.extend_from_slice(snapshot);
            self.written = 0;
        } else {
            self.next = Some(snapshot.to_vec());
        }
    }

    fn flush(&mut self) -> bool {
        loop {
            if self.written == self.pending.len() {
                if let Some(next) = self.next.take() {
                    self.pending = next;
                    self.written = 0;
                } else {
                    self.pending.clear();
                    self.written = 0;
                    return true;
                }
            }
            match self.stream.write(&self.pending[self.written..]) {
                Ok(0) => return false,
                Ok(count) => self.written += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return true,
                Err(_) => return false,
            }
        }
    }
}

pub(super) struct ControlWake(UnixDatagram);

impl ControlWake {
    pub(super) fn notify(&self) {
        // A full nonblocking socket already contains a wake-up; no producer waits.
        let _ = self.0.send(&[1]);
    }
}

impl ControlSocket {
    pub(super) fn bind(path: String) -> io::Result<Self> {
        match UnixStream::connect(&path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "control socket is already active",
                ))
            }
            Err(error)
                if error.kind() == io::ErrorKind::ConnectionRefused
                    || error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if std::path::Path::new(&path).exists() {
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
        listener.set_nonblocking(true)?;
        let (wake_reader, wake_writer) = UnixDatagram::pair()?;
        wake_reader.set_nonblocking(true)?;
        wake_writer.set_nonblocking(true)?;
        Ok(Self {
            listener,
            wake_reader,
            wake_writer: Arc::new(ControlWake(wake_writer)),
            pending: Vec::new(),
            path,
            watchers: Vec::new(),
            last_identity: String::new(),
            identity_scratch: String::with_capacity(4096),
        })
    }

    pub(super) fn wake_handle(&self) -> Arc<ControlWake> {
        Arc::clone(&self.wake_writer)
    }

    pub(super) fn process(&mut self, sessions: &mut Vec<Session>) -> io::Result<()> {
        loop {
            let (stream, _) = match self.listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            };
            stream.set_nonblocking(true)?;
            if self.pending.len() < 64 {
                self.pending.push(PendingCommand {
                    stream,
                    bytes: [0; 256],
                    len: 0,
                    accepted_at: Instant::now(),
                });
            }
        }
        for mut pending in mem::take(&mut self.pending) {
            if pending.accepted_at.elapsed() >= Duration::from_secs(3) {
                continue;
            }
            let mut complete = false;
            loop {
                if pending.len == pending.bytes.len() {
                    complete = true;
                    break;
                }
                match pending.stream.read(&mut pending.bytes[pending.len..]) {
                    Ok(0) => {
                        complete = true;
                        break;
                    }
                    Ok(count) => {
                        pending.len += count;
                        if pending.bytes[..pending.len].contains(&b'\n') {
                            complete = true;
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        complete = true;
                        break;
                    }
                }
            }
            if complete {
                let command = String::from_utf8_lossy(&pending.bytes[..pending.len]);
                self.handle_command(pending.stream, command.trim(), sessions);
            } else {
                self.pending.push(pending);
            }
        }
        self.publish_if_changed(sessions);
        Ok(())
    }

    fn handle_command(
        &mut self,
        mut stream: UnixStream,
        command: &str,
        sessions: &mut Vec<Session>,
    ) {
        if command == "WATCH" {
            let mut snapshot = session_snapshot(sessions).into_bytes();
            snapshot.push(b'\n');
            let mut watcher = Watcher::new(stream, snapshot);
            if watcher.flush() {
                self.watchers.push(watcher);
            }
        } else if command == "STATUS" {
            let snapshot = session_snapshot(sessions);
            let _ = stream.write_all(snapshot.as_bytes());
            let _ = stream.write_all(b"\n");
        } else if let Some(address) = command.strip_prefix("DISCONNECT ") {
            let Ok(address) = address.parse::<Ipv4Addr>() else {
                let _ = stream.write_all(b"{\"ok\":false,\"error\":\"invalid_vpn_address\"}\n");
                return;
            };
            let before = sessions.len();
            sessions.retain_mut(|session| {
                if session.established && session.address == address {
                    session.disconnect_reason = "web_disconnect";
                    false
                } else {
                    true
                }
            });
            let removed = before - sessions.len();
            let _ = stream
                .write_all(format!("{{\"ok\":true,\"disconnected\":{removed}}}\n").as_bytes());
        } else {
            let _ = stream.write_all(b"{\"ok\":false,\"error\":\"invalid_command\"}\n");
        }
    }

    fn publish_if_changed(&mut self, sessions: &[Session]) {
        self.identity_scratch.clear();
        write_session_identity(&mut self.identity_scratch, sessions);
        if self.identity_scratch != self.last_identity {
            mem::swap(&mut self.identity_scratch, &mut self.last_identity);
            let message = format!("{}\n", session_snapshot(sessions));
            for watcher in &mut self.watchers {
                watcher.enqueue_latest(message.as_bytes());
            }
        }
        self.watchers.retain_mut(Watcher::flush);
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub(super) struct ControlContext {
    pub(super) udp_rx_queue: Arc<Queue<UdpDatagram>>,
    pub(super) control: ControlSocket,
    pub(super) sessions: Arc<Mutex<Vec<Session>>>,
    pub(super) path: String,
    pub(super) fd: RawFd,
    pub(super) config: Arc<Config>,
    pub(super) cookie_secret: [u8; 32],
    pub(super) bindings: HashMap<Ipv4Addr, String>,
    pub(super) vpn_address: Ipv4Addr,
    pub(super) vpn_network: String,
    pub(super) next_config_reload: Instant,
    pub(super) config_reload_interval: Duration,
    pub(super) max_session_lifetime: Duration,
    pub(super) active: Arc<AtomicBool>,
    pub(super) reload_sender: mpsc::Sender<(HashMap<Ipv4Addr, String>, Dtls)>,
}

pub(super) fn spawn(context: ControlContext) -> io::Result<JoinHandle<io::Result<()>>> {
    thread::Builder::new()
        .name("avpn-server-session-control".to_string())
        .spawn(move || {
            let _stop = StopOnDrop(Arc::clone(&context.active));
            run(context)
        })
}

fn run(context: ControlContext) -> io::Result<()> {
    let ControlContext {
        udp_rx_queue,
        mut control,
        sessions,
        path,
        fd,
        config,
        cookie_secret,
        mut bindings,
        vpn_address,
        vpn_network,
        mut next_config_reload,
        config_reload_interval,
        max_session_lifetime,
        active,
        reload_sender,
    } = context;
    while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
        let now = Instant::now();
        {
            let mut list = sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            control.process(&mut list)?;
            let mut index = 0;
            while index < list.len() {
                if !list[index].established
                    && list[index]
                        .dtls_deadline
                        .is_some_and(|deadline| deadline <= now)
                {
                    if let Err(error) = panic_gate("DTLS retransmission", || {
                        list[index].dtls.with(|dtls| dtls.handle_timeout())
                    }) {
                        eprintln!("[server] DTLS retransmission failed: {error}");
                        list[index].disconnect_reason = "handshake_timeout_error";
                        list.swap_remove(index);
                        continue;
                    }
                    let timeout = list[index].dtls.with(|dtls| dtls.current_timeout());
                    list[index].dtls_deadline = Some(Instant::now() + timeout);
                }
                index += 1;
            }
            list.retain_mut(|session| {
                let idle_valid = session.last_activity.elapsed() < if session.established { SESSION_IDLE_TIMEOUT } else { HANDSHAKE_TIMEOUT };
                let lifetime_valid = !session.established_at.is_some_and(|started| started.elapsed() >= max_session_lifetime);
                if idle_valid && !lifetime_valid {
                    session.disconnect_reason = "max_session_lifetime";
                    eprintln!("[server] maximum session lifetime reached for {}; reauthentication required", session.address);
                }
                if !idle_valid && session.established { session.disconnect_reason = "idle_timeout"; }
                idle_valid && lifetime_valid
            });
            control.publish_if_changed(&list);
        }
        if now >= next_config_reload {
            let reload = parse_ini_entries(&path, "client")
                .and_then(|entries| validate_client_bindings(entries, vpn_address, &vpn_network))
                .and_then(|new_bindings| {
                    create_stateless_acceptor(fd, &config, &cookie_secret)
                        .map(|acceptor| (new_bindings, acceptor))
                });
            match reload {
                Ok((new_bindings, acceptor)) => {
                    let changed = bindings != new_bindings;
                    {
                        let mut list = sessions
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        list.retain_mut(|session| {
                            if !session.established {
                                return false;
                            }
                            let authorized = session.fingerprint.as_ref().is_some_and(|actual| {
                                new_bindings.get(&session.address) == Some(actual)
                            });
                            if !authorized {
                                session.disconnect_reason = "binding_revoked";
                                eprintln!(
                                    "[server] client {} removed by binding reload",
                                    session.address
                                );
                            }
                            authorized
                        });
                        control.publish_if_changed(&list);
                    }
                    bindings = new_bindings.clone();
                    if reload_sender.send((new_bindings, acceptor)).is_err() {
                        break;
                    }
                    udp_rx_queue.notify_change();
                    if changed {
                        eprintln!("[server] client fingerprint bindings reloaded");
                    }
                }
                Err(error) => eprintln!(
                    "[server] configuration reload rejected; keeping current state: {error}"
                ),
            }
            next_config_reload = Instant::now() + config_reload_interval;
        }
        let deadline = sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .flat_map(|session| {
                let idle = session.last_activity
                    + if session.established {
                        SESSION_IDLE_TIMEOUT
                    } else {
                        HANDSHAKE_TIMEOUT
                    };
                let lifetime = session
                    .established_at
                    .map(|started| started + max_session_lifetime);
                [session.dtls_deadline, Some(idle), lifetime]
                    .into_iter()
                    .flatten()
            })
            .min();
        let next_wake = deadline.map_or(next_config_reload, |deadline| {
            deadline.min(next_config_reload)
        });
        let next_wake = control
            .pending
            .iter()
            .map(|pending| pending.accepted_at + Duration::from_secs(3))
            .min()
            .map_or(next_wake, |deadline| deadline.min(next_wake));
        let timeout = next_wake.saturating_duration_since(Instant::now());
        let mut descriptors = vec![
            libc::pollfd {
                fd: control.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: control.wake_reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        descriptors.extend(control.pending.iter().map(|pending| libc::pollfd {
            fd: pending.stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }));
        descriptors.extend(control.watchers.iter().map(|watcher| libc::pollfd {
            fd: watcher.stream.as_raw_fd(),
            events: if watcher.pending.is_empty() {
                0
            } else {
                libc::POLLOUT
            },
            revents: 0,
        }));
        poll(&mut descriptors, timeout)?;
        if descriptors[1].revents & libc::POLLIN != 0 {
            let mut wake = [0u8; 64];
            while control.wake_reader.recv(&mut wake).is_ok() {}
        }
        let mut watcher_index = 2 + control.pending.len();
        control.watchers.retain(|_| {
            let revents = descriptors[watcher_index].revents;
            watcher_index += 1;
            revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0
        });
    }
    Ok(())
}

fn write_session_identity(output: &mut String, sessions: &[Session]) {
    for session in sessions.iter().filter(|session| session.established) {
        let _ = write!(
            output,
            "{}:{}|",
            session.address,
            session.fingerprint.as_deref().unwrap_or("")
        );
    }
}

fn session_snapshot(sessions: &[Session]) -> String {
    let mut output = String::with_capacity(256 + sessions.len() * 256);
    output.push_str("{\"type\":\"sessions\",\"sessions\":[");
    let mut first = true;
    for session in sessions.iter().filter(|session| session.established) {
        if !first {
            output.push(',');
        }
        first = false;
        let _ = write!(
            output,
            "{{\"vpnAddress\":\"{}\",\"fingerprint\":\"{}\",\"connectedSeconds\":{},\"bytesTx\":{},\"bytesRx\":{},\"packetsTx\":{},\"packetsRx\":{}}}",
            session.address,
            session.fingerprint.as_deref().unwrap_or(""),
            session.established_at.map(|value| value.elapsed().as_secs()).unwrap_or(0),
            session.bytes_tx,
            session.bytes_rx,
            session.packets_tx,
            session.packets_rx
        );
    }
    output.push_str("]}");
    output
}

#[cfg(test)]
mod tests {
    use super::{ControlSocket, Watcher};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn control() -> ControlSocket {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = format!("/tmp/avpn-control-{}-{nonce}.sock", std::process::id());
        ControlSocket::bind(path).unwrap()
    }

    #[test]
    fn incomplete_command_does_not_block_session_control() {
        let mut control = control();
        let mut client = UnixStream::connect(&control.path).unwrap();
        let mut sessions = Vec::new();
        control.process(&mut sessions).unwrap();
        assert_eq!(control.pending.len(), 1);

        client.write_all(b"STA").unwrap();
        control.process(&mut sessions).unwrap();
        assert_eq!(control.pending.len(), 1);

        client.write_all(b"TUS\n").unwrap();
        control.process(&mut sessions).unwrap();
        assert!(control.pending.is_empty());
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert_eq!(response, "{\"type\":\"sessions\",\"sessions\":[]}\n");
    }

    #[test]
    fn invalid_disconnect_command_does_not_stop_control_socket() {
        let mut control = control();
        let mut client = UnixStream::connect(&control.path).unwrap();
        client.write_all(b"DISCONNECT invalid\n").unwrap();
        control.process(&mut Vec::new()).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert_eq!(
            response,
            "{\"ok\":false,\"error\":\"invalid_vpn_address\"}\n"
        );
    }

    #[test]
    fn watcher_preserves_current_frame_before_latest_update() {
        let (server, mut client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        let mut watcher = Watcher::new(server, b"old\n".to_vec());
        watcher.enqueue_latest(b"new\n");
        assert!(watcher.flush());
        assert!(watcher.pending.is_empty());
        let mut received = [0u8; 8];
        client.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"old\nnew\n");
    }
}
