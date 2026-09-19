use autobricks_vpn::{
    base::queue::Queue,
    base::worker::{QueueWorker, WorkerSignal},
    ipv4_destination, ipv4_in_cidr, ipv4_is_broadcast, ipv4_packet_addresses, is_keepalive_packet,
    panic_gate, parse_ini_entries, parse_ini_section, parse_ipv4_cidr, validate_client_bindings,
    validate_datagram_write, Config, Dtls, DtlsIo, EncryptedDatagram, ForwardingGuard,
    IpRateLimiter, RateLimitDecision, SynchronizedDtls, Tun, TunErrorAction, KEEPALIVE_PACKET,
};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::mem;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

mod session;
mod socket;
mod tun;
use session::Session;
use socket::{peer_ipv4, poll, receive_peer, same_peer, send_encrypted_datagram, socket_fd};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("vpn-server supports Linux and macOS only");

static RUNNING: AtomicBool = AtomicBool::new(true);
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_PER_IP: usize = 2;
const SERVER_QUEUE_CAPACITY: usize = 4096;
const SESSION_TX_QUEUE_CAPACITY: usize = 256;
const SESSION_PACKET_TTL: Duration = Duration::from_secs(2);

struct UdpDatagram {
    peer: libc::sockaddr_storage,
    peer_size: libc::socklen_t,
    packet: Vec<u8>,
}

#[cfg(unix)]
extern "C" fn stop(_signal: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}

#[cfg(unix)]
fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
    }
}

#[cfg(not(unix))]
fn install_signal_handlers() {}

struct ControlSocket {
    listener: UnixListener,
    path: String,
    watchers: Vec<UnixStream>,
    last_identity: String,
    identity_scratch: String,
}

impl ControlSocket {
    fn bind(path: String) -> io::Result<Self> {
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
        Ok(Self {
            listener,
            path,
            watchers: Vec::new(),
            last_identity: String::new(),
            identity_scratch: String::with_capacity(4096),
        })
    }

    fn process(&mut self, sessions: &mut Vec<Session>) -> io::Result<()> {
        loop {
            let (mut stream, _) = match self.listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            };
            let mut command = [0u8; 256];
            let count = stream.read(&mut command)?;
            let command = String::from_utf8_lossy(&command[..count]);
            let command = command.trim();
            if command == "WATCH" {
                let snapshot = session_snapshot(sessions);
                stream.write_all(snapshot.as_bytes())?;
                stream.write_all(b"\n")?;
                stream.set_nonblocking(true)?;
                self.watchers.push(stream);
            } else if command == "STATUS" {
                let snapshot = session_snapshot(sessions);
                stream.write_all(snapshot.as_bytes())?;
                stream.write_all(b"\n")?;
            } else if let Some(address) = command.strip_prefix("DISCONNECT ") {
                let address = address.parse::<Ipv4Addr>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid VPN address")
                })?;
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
                stream.write_all(
                    format!("{{\"ok\":true,\"disconnected\":{removed}}}\n").as_bytes(),
                )?;
            } else {
                stream.write_all(b"{\"ok\":false,\"error\":\"invalid_command\"}\n")?;
            }
        }
        self.publish_if_changed(sessions);
        Ok(())
    }

    fn publish_if_changed(&mut self, sessions: &[Session]) {
        self.identity_scratch.clear();
        write_session_identity(&mut self.identity_scratch, sessions);
        if self.identity_scratch == self.last_identity {
            return;
        }
        mem::swap(&mut self.identity_scratch, &mut self.last_identity);
        let message = format!("{}\n", session_snapshot(sessions));
        self.watchers
            .retain_mut(|stream| match stream.write_all(message.as_bytes()) {
                Ok(()) => true,
                Err(error) => error.kind() == io::ErrorKind::WouldBlock,
            });
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
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

fn create_stateless_acceptor(fd: RawFd, config: &Config, cookie_secret: &[u8]) -> io::Result<Dtls> {
    let peer = unsafe { mem::zeroed() };
    let peer_size = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let io = DtlsIo::new(fd, peer, peer_size);
    let mut dtls = Dtls::new(config)?;
    dtls.set_socket(fd)?;
    dtls.set_nonblocking(true);
    dtls.set_io(io)?;
    dtls.set_cookie_secret(cookie_secret)?;
    Ok(dtls)
}

fn generate_cookie_secret() -> io::Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut secret)?;
    Ok(secret)
}

fn value(values: &HashMap<String, String>, key: &str, default: &str) -> String {
    values
        .get(key)
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn required_value(values: &HashMap<String, String>, key: &str) -> io::Result<String> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{key} is required and must not be empty"),
            )
        })
}

fn duration_value(
    values: &HashMap<String, String>,
    key: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> io::Result<Duration> {
    let seconds: u64 = value(values, key, &default.to_string())
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid {key}")))?;
    if !(minimum..=maximum).contains(&seconds) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{key} must be between {minimum} and {maximum} seconds"),
        ));
    }
    Ok(Duration::from_secs(seconds))
}

fn boolean_value(values: &HashMap<String, String>, key: &str, default: bool) -> io::Result<bool> {
    let Some(value) = values.get(key) else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{key} must be true or false"),
        )),
    }
}

enum SendPacketResult {
    Sent,
    Retry,
    RemoveSession,
}

fn drain_encrypted_queue(
    queue: &Queue<EncryptedDatagram>,
    mut send: impl FnMut(&[u8]) -> io::Result<usize>,
) -> io::Result<bool> {
    loop {
        let front = match queue.try_peek() {
            Ok(front) => front,
            Err(_) => return Ok(false),
        };
        if front.value().enqueued_at.elapsed() >= SESSION_PACKET_TTL {
            front.pop();
            continue;
        }
        match send(&front.value().bytes) {
            Ok(written) if written == front.value().bytes.len() => {
                front.pop();
            }
            Ok(written) => {
                let expected = front.value().bytes.len();
                front.pop();
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("partial UDP datagram write: {written}/{expected}"),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                drop(front);
                return Ok(true);
            }
            Err(error) => return Err(error),
        }
    }
}

fn send_tunnel_packet(session: &mut Session, packet: &[u8]) -> SendPacketResult {
    match panic_gate("server DTLS write", || {
        session.dtls.with(|dtls| dtls.write(packet))
    }) {
        Ok(written) if written == packet.len() => {
            session.last_activity = Instant::now();
            session.bytes_tx = session.bytes_tx.saturating_add(written as u64);
            session.packets_tx = session.packets_tx.saturating_add(1);
            SendPacketResult::Sent
        }
        Ok(written) => {
            eprintln!(
                "[server] partial DTLS write: {written}/{} bytes",
                packet.len()
            );
            session.disconnect_reason = "partial_dtls_write";
            SendPacketResult::RemoveSession
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => SendPacketResult::Retry,
        Err(error) => {
            eprintln!("[server] DTLS session failed: {error}; removing client");
            session.disconnect_reason = "dtls_write_error";
            SendPacketResult::RemoveSession
        }
    }
}

fn drain_session_plain(session: &mut Session) -> SendPacketResult {
    while let Some((packet, queued_at)) = session.pending_plain.pop_front() {
        if queued_at.elapsed() >= SESSION_PACKET_TTL {
            continue;
        }
        match send_tunnel_packet(session, &packet) {
            SendPacketResult::Sent => {}
            SendPacketResult::Retry => {
                session.pending_plain.push_front((packet, queued_at));
                return SendPacketResult::Retry;
            }
            SendPacketResult::RemoveSession => return SendPacketResult::RemoveSession,
        }
    }
    SendPacketResult::Sent
}

fn queue_session_plain(session: &mut Session, packet: Vec<u8>) {
    if session.pending_plain.len() == SESSION_TX_QUEUE_CAPACITY {
        session.pending_plain.pop_front();
    }
    session.pending_plain.push_back((packet, Instant::now()));
}

pub(crate) fn run(path: &str) -> io::Result<()> {
    RUNNING.store(true, Ordering::Relaxed);
    install_signal_handlers();
    eprintln!("[server] loading config: {path}");
    let server = parse_ini_section(path, "server")?;
    let clients = parse_ini_entries(path, "client")?;
    eprintln!("[server] config loaded: {} client bindings", clients.len());
    let max_clients: usize = value(&server, "max_clients", "64")
        .parse()
        .map_err(|_| io::Error::other("invalid max_clients"))?;
    if !(1..=1024).contains(&max_clients) {
        return Err(io::Error::other("max_clients must be between 1 and 1024"));
    }
    let max_pending_handshakes: usize = value(&server, "max_pending_handshakes", "16")
        .parse()
        .map_err(|_| io::Error::other("invalid max_pending_handshakes"))?;
    if !(1..=256).contains(&max_pending_handshakes) {
        return Err(io::Error::other(
            "max_pending_handshakes must be between 1 and 256",
        ));
    }
    let port: u16 = value(&server, "port", "4433")
        .parse()
        .map_err(|_| io::Error::other("invalid port"))?;
    let listen: Ipv4Addr = value(&server, "listen_address", "0.0.0.0")
        .parse()
        .map_err(|_| io::Error::other("invalid listen_address"))?;
    let certificate_file = value(&server, "certificate_file", "server-cert.pem");
    let private_key_file = value(&server, "private_key_file", "server-key.pem");
    let ca_file = Some(required_value(&server, "ca_file")?);
    let crl_file = server
        .get("crl_file")
        .filter(|value| !value.trim().is_empty())
        .cloned();
    let ocsp_url = server
        .get("ocsp_url")
        .filter(|value| !value.trim().is_empty())
        .cloned();
    let ocsp_enabled = boolean_value(&server, "ocsp_enabled", true)?;
    let mtu: u16 = value(&server, "mtu", "1200")
        .parse()
        .map_err(|_| io::Error::other("invalid mtu"))?;
    let verify_client_san_ip = boolean_value(&server, "verify_client_san_ip", false)?;
    let allow_broadcast = boolean_value(&server, "allow_broadcast", false)?;
    let allow_multicast = boolean_value(&server, "allow_multicast", false)?;
    let max_session_lifetime = duration_value(&server, "max_session_lifetime", 3600, 60, 604_800)?;
    let config_reload_interval = duration_value(&server, "config_reload_interval", 30, 5, 3600)?;
    let control_socket_path = value(&server, "control_socket", "/var/run/autobricks-vpn.sock");
    let mut control = ControlSocket::bind(control_socket_path.clone())?;
    eprintln!("[server] control socket listening at {control_socket_path}");
    let socket = std::net::UdpSocket::bind(SocketAddr::from((listen, port)))?;
    eprintln!("[server] UDP bound to {listen}:{port}");
    socket.set_nonblocking(true)?;
    let fd = socket_fd(&socket);
    let vpn_address_text = value(&server, "vpn_address", "10.8.1.1");
    let vpn_address: Ipv4Addr = vpn_address_text
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid vpn_address"))?;
    let vpn_network = value(&server, "vpn_network", "10.8.1.0/24");
    let (network_address, network_prefix) = parse_ipv4_cidr(&vpn_network)?;
    if !ipv4_in_cidr(vpn_address, network_address, network_prefix) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vpn_address is outside vpn_network",
        ));
    }
    let mut bindings = validate_client_bindings(clients, vpn_address, &vpn_network)?;
    let tun = Arc::new(Tun::open(&value(&server, "tun_name", "autobricks0"))?);
    eprintln!("[server] TUN opened: {}", tun.name());
    tun.configure_mtu(mtu)?;
    tun.configure_ipv4(&vpn_address_text, &vpn_address_text, &vpn_network)?;
    eprintln!("[server] TUN configured: {vpn_address}, route {vpn_network}, MTU {mtu}");
    let _forwarding = ForwardingGuard::enable(tun.name(), &vpn_network)?;
    eprintln!("[server] client forwarding enabled for {vpn_network}");
    let config = Config {
        server: true,
        certificate_file,
        private_key_file,
        ca_file,
        crl_file,
        ocsp_enabled,
        ocsp_url,
        mtu,
    };
    // Validate credentials and the wolfSSL setup before accepting untrusted packets.
    drop(Dtls::new(&config)?);
    let cookie_secret = generate_cookie_secret()?;
    let mut stateless_acceptor = create_stateless_acceptor(fd, &config, &cookie_secret)?;
    let sessions = Arc::new(Mutex::new(Vec::<Session>::with_capacity(max_clients)));
    let mut handshake_limiter =
        IpRateLimiter::new(30, Duration::from_secs(60), Duration::from_secs(600));
    let mut next_config_reload = Instant::now() + config_reload_interval;
    let encrypted_queue = Arc::new(
        Queue::new(SERVER_QUEUE_CAPACITY).map_err(|error| io::Error::other(error.to_string()))?,
    );
    let plain_queue = Arc::new(
        Queue::new(SERVER_QUEUE_CAPACITY).map_err(|error| io::Error::other(error.to_string()))?,
    );
    let dtls_progress = Arc::new(WorkerSignal::new());
    let active = Arc::new(AtomicBool::new(true));
    let encrypted_drops = Arc::new(AtomicU64::new(0));
    let plain_drops = Arc::new(AtomicU64::new(0));
    let (error_sender, error_receiver) = mpsc::channel::<io::Error>();

    let udp_reader_socket = socket.try_clone()?;
    let udp_reader_queue = Arc::clone(&encrypted_queue);
    let udp_reader_active = Arc::clone(&active);
    let udp_reader_drops = Arc::clone(&encrypted_drops);
    let udp_reader_errors = error_sender.clone();
    let udp_reader_progress = Arc::clone(&dtls_progress);
    let udp_reader = thread::Builder::new()
        .name("avpn-server-udp-read".to_string())
        .spawn(move || {
            let reader_fd = socket_fd(&udp_reader_socket);
            while RUNNING.load(Ordering::Acquire) && udp_reader_active.load(Ordering::Acquire) {
                let mut descriptor = libc::pollfd {
                    fd: reader_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                if let Err(error) = poll(
                    std::slice::from_mut(&mut descriptor),
                    Duration::from_millis(100),
                ) {
                    udp_reader_active.store(false, Ordering::Release);
                    let _ = udp_reader_errors.send(error);
                    udp_reader_queue.close();
                    return;
                }
                if descriptor.revents & libc::POLLIN == 0 {
                    continue;
                }
                loop {
                    match receive_peer(reader_fd) {
                        Ok((peer, peer_size, packet)) => {
                            let datagram = UdpDatagram {
                                peer,
                                peer_size,
                                packet,
                            };
                            match udp_reader_queue.push(datagram) {
                                Ok(Some(_)) => {
                                    udp_reader_drops.fetch_add(1, Ordering::Relaxed);
                                }
                                Ok(None) => {}
                                Err(_) => return,
                            }
                            udp_reader_progress.notify();
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) =>
                        {
                            break;
                        }
                        Err(error) => {
                            udp_reader_active.store(false, Ordering::Release);
                            let _ = udp_reader_errors.send(error);
                            udp_reader_queue.close();
                            return;
                        }
                    }
                }
            }
        })?;

    let tun_reader = tun::spawn_tun_reader(
        Arc::clone(&tun),
        Arc::clone(&plain_queue),
        Arc::clone(&active),
        Arc::clone(&plain_drops),
        error_sender.clone(),
    )?;

    let writer_sessions = Arc::clone(&sessions);
    let writer_active = Arc::clone(&active);
    let writer_encrypted_queue = Arc::clone(&encrypted_queue);
    let writer_signal = Arc::clone(&dtls_progress);
    let mut encrypt_worker = QueueWorker::spawn(
        "avpn-server-encrypt",
        Arc::clone(&plain_queue),
        move |packet| {
            if !writer_active.load(Ordering::Acquire) {
                return;
            }
            let Some(destination) = ipv4_destination(&packet) else {
                return;
            };
            let broadcast = ipv4_is_broadcast(destination, network_address, network_prefix);
            let multicast = destination.is_multicast();
            let mut sessions = writer_sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if (broadcast && allow_broadcast) || (multicast && allow_multicast) {
                for session in sessions.iter_mut() {
                    if session.established {
                        queue_session_plain(session, packet.clone());
                    }
                }
            } else if !broadcast && !multicast {
                if let Some((index, _)) = sessions
                    .iter()
                    .enumerate()
                    .filter(|(_, session)| session.established && session.address == destination)
                    .max_by_key(|(_, session)| session.last_activity)
                {
                    queue_session_plain(&mut sessions[index], packet);
                }
            }
            writer_signal.notify();
            if !writer_active.load(Ordering::Acquire) {
                writer_encrypted_queue.close();
            }
        },
    )?;

    let tx_socket = socket.try_clone()?;
    let tx_sessions = Arc::clone(&sessions);
    let tx_active = Arc::clone(&active);
    let tx_signal = Arc::clone(&dtls_progress);
    let udp_writer = thread::Builder::new()
        .name("avpn-server-udp-write".to_string())
        .spawn(move || {
            let fd = socket_fd(&tx_socket);
            while RUNNING.load(Ordering::Acquire) && tx_active.load(Ordering::Acquire) {
                let observed = tx_signal.generation();
                let mut sent_any = false;
                let mut socket_blocked = false;
                let mut remove = Vec::new();
                {
                    let mut sessions = tx_sessions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    for (index, session) in sessions.iter_mut().enumerate() {
                        if matches!(
                            drain_session_plain(session),
                            SendPacketResult::RemoveSession
                        ) {
                            remove.push(index);
                            continue;
                        }
                        let queue_was_nonempty = !session.tx_queue.is_empty();
                        match drain_encrypted_queue(&session.tx_queue, |packet| {
                            send_encrypted_datagram(fd, &session.peer, session.peer_size, packet)
                        }) {
                            Ok(blocked) => {
                                socket_blocked |= blocked;
                                sent_any |= queue_was_nonempty && !blocked;
                            }
                            Err(error) => {
                                eprintln!(
                                    "[server] UDP send failed for {}: {error}; removing client",
                                    session.address
                                );
                                session.disconnect_reason = "udp_write_error";
                                remove.push(index);
                            }
                        }
                    }
                    for index in remove.into_iter().rev() {
                        sessions.swap_remove(index);
                    }
                }

                if socket_blocked {
                    let mut descriptor = libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    let _ = poll(std::slice::from_mut(&mut descriptor), SESSION_PACKET_TTL);
                } else if !sent_any {
                    let encrypted_pending = tx_sessions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .iter()
                        .any(|session| !session.tx_queue.is_empty());
                    if !encrypted_pending
                        && RUNNING.load(Ordering::Acquire)
                        && tx_active.load(Ordering::Acquire)
                    {
                        tx_signal.wait(observed);
                    }
                }
            }
        })?;
    println!(
        "Rust multi-client VPN hub listening on {listen}:{port} through {}",
        tun.name()
    );
    let mut result = Ok(());
    'server: while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
        {
            let mut session_list = sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            control.process(&mut session_list)?;
        }
        let now = Instant::now();
        handshake_limiter.purge(now);
        if now >= next_config_reload {
            let reload = parse_ini_entries(path, "client")
                .and_then(|clients| validate_client_bindings(clients, vpn_address, &vpn_network))
                .and_then(|new_bindings| {
                    create_stateless_acceptor(fd, &config, &cookie_secret)
                        .map(|acceptor| (new_bindings, acceptor))
                });
            match reload {
                Ok((new_bindings, new_acceptor)) => {
                    let bindings_changed = bindings != new_bindings;
                    bindings = new_bindings;
                    stateless_acceptor = new_acceptor;
                    let mut sessions = sessions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    sessions.retain_mut(|session| {
                        if !session.established {
                            return false;
                        }
                        let still_authorized = session
                            .fingerprint
                            .as_ref()
                            .is_some_and(|actual| bindings.get(&session.address) == Some(actual));
                        if !still_authorized {
                            session.disconnect_reason = "binding_revoked";
                            eprintln!(
                                "[server] client {} removed by binding reload",
                                session.address
                            );
                        }
                        still_authorized
                    });
                    if bindings_changed {
                        eprintln!("[server] client fingerprint bindings reloaded");
                    }
                }
                Err(error) => {
                    eprintln!(
                        "[server] configuration reload rejected; keeping current state: {error}"
                    )
                }
            }
            next_config_reload = Instant::now() + config_reload_interval;
        }
        let poll_timeout = {
            let sessions = sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            sessions
                .iter()
                .filter_map(|session| session.dtls_deadline)
                .map(|deadline| deadline.saturating_duration_since(now))
                .min()
                .unwrap_or(Duration::from_secs(1))
                .min(Duration::from_secs(1))
        };
        if let Ok(error) = error_receiver.try_recv() {
            result = Err(error);
            break;
        }
        let now = Instant::now();
        let mut session_list = sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut session_index = 0;
        while session_index < session_list.len() {
            let deadline_expired = session_list[session_index]
                .dtls_deadline
                .is_some_and(|deadline| deadline <= now);
            if !session_list[session_index].established && deadline_expired {
                if let Err(error) = panic_gate("DTLS retransmission", || {
                    session_list[session_index]
                        .dtls
                        .with(|dtls| dtls.handle_timeout())
                }) {
                    eprintln!("[server] DTLS retransmission failed: {error}");
                    session_list[session_index].disconnect_reason = "handshake_timeout_error";
                    session_list.swap_remove(session_index);
                    continue;
                }
                let timeout = session_list[session_index]
                    .dtls
                    .with(|dtls| dtls.current_timeout());
                session_list[session_index].dtls_deadline = Some(Instant::now() + timeout);
            }
            session_index += 1;
        }
        session_list.retain_mut(|session| {
            let idle_valid = session.last_activity.elapsed()
                < if session.established {
                    SESSION_IDLE_TIMEOUT
                } else {
                    HANDSHAKE_TIMEOUT
                };
            // Keep compatibility with the Ubuntu 22.04 Rust 1.75 toolchain.
            #[allow(clippy::unnecessary_map_or)]
            let lifetime_valid = session.established_at.map_or(true, |established_at| {
                established_at.elapsed() < max_session_lifetime
            });
            if idle_valid && !lifetime_valid {
                session.disconnect_reason = "max_session_lifetime";
                eprintln!(
                    "[server] maximum session lifetime reached for {}; reauthentication required",
                    session.address
                );
            }
            if !idle_valid && session.established {
                session.disconnect_reason = "idle_timeout";
            }
            idle_valid && lifetime_valid
        });
        drop(session_list);
        if let Some(UdpDatagram {
            peer,
            peer_size,
            packet: incoming,
        }) = encrypted_queue.pop_timeout(poll_timeout)
        {
            let mut packet = [0u8; 2048];
            let mut sessions = sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let index = sessions
                .iter()
                .position(|session| same_peer(&session.peer, &peer));
            let new_session = index.is_none();
            let index = match index {
                Some(index) => index,
                None => {
                    let Some(peer_ip) = peer_ipv4(&peer) else {
                        continue;
                    };
                    if handshake_limiter.check_ban(peer_ip, Instant::now()) {
                        continue;
                    }
                    if let Err(error) =
                        stateless_acceptor.set_incoming_peer(peer, peer_size, incoming.clone())
                    {
                        eprintln!("[server] unable to prepare stateless DTLS accept: {error}");
                        stateless_acceptor =
                            match create_stateless_acceptor(fd, &config, &cookie_secret) {
                                Ok(acceptor) => acceptor,
                                Err(error) => {
                                    result = Err(error);
                                    break 'server;
                                }
                            };
                        continue;
                    }
                    let cookie_valid = match panic_gate("stateless DTLS accept", || {
                        stateless_acceptor.accept_stateless()
                    }) {
                        Ok(valid) => valid,
                        Err(error) => {
                            eprintln!("[server] stateless DTLS accept failed: {error}");
                            stateless_acceptor =
                                match create_stateless_acceptor(fd, &config, &cookie_secret) {
                                    Ok(acceptor) => acceptor,
                                    Err(error) => {
                                        result = Err(error);
                                        break 'server;
                                    }
                                };
                            continue;
                        }
                    };
                    if !cookie_valid {
                        continue;
                    }
                    match handshake_limiter.record_attempt(peer_ip, Instant::now()) {
                        RateLimitDecision::Allowed => {}
                        RateLimitDecision::BannedNow => {
                            eprintln!(
                                "[server] {peer_ip} banned for 10 minutes after 30 handshake attempts"
                            );
                            sessions.retain(|session| {
                                session.established || peer_ipv4(&session.peer) != Some(peer_ip)
                            });
                            continue;
                        }
                        RateLimitDecision::Banned => continue,
                    }
                    let established_count = sessions
                        .iter()
                        .filter(|session| session.established)
                        .count();
                    if established_count >= max_clients {
                        eprintln!("maximum client count ({max_clients}) reached");
                        continue;
                    }
                    let pending_from_ip = sessions
                        .iter()
                        .filter(|session| {
                            !session.established && peer_ipv4(&session.peer) == Some(peer_ip)
                        })
                        .count();
                    if pending_from_ip >= MAX_PENDING_PER_IP {
                        eprintln!("too many pending handshakes from {peer_ip}");
                        continue;
                    }
                    let pending_count = sessions
                        .iter()
                        .filter(|session| !session.established)
                        .count();
                    if pending_count >= max_pending_handshakes {
                        if let Some((oldest, _)) = sessions
                            .iter()
                            .enumerate()
                            .filter(|(_, session)| !session.established)
                            .min_by_key(|(_, session)| session.last_activity)
                        {
                            sessions.swap_remove(oldest);
                        }
                    }
                    eprintln!("[server] DTLS cookie verified; creating session");
                    let replacement = match create_stateless_acceptor(fd, &config, &cookie_secret) {
                        Ok(acceptor) => acceptor,
                        Err(error) => {
                            result = Err(error);
                            break 'server;
                        }
                    };
                    let mut dtls = mem::replace(&mut stateless_acceptor, replacement);
                    let tx_queue = Arc::new(
                        Queue::new(SESSION_TX_QUEUE_CAPACITY)
                            .map_err(|error| io::Error::other(error.to_string()))?,
                    );
                    dtls.use_queued_send(Arc::clone(&tx_queue), Arc::clone(&dtls_progress))?;
                    let session = Session {
                        dtls: SynchronizedDtls::new(dtls),
                        peer,
                        peer_size,
                        address: Ipv4Addr::UNSPECIFIED,
                        fingerprint: None,
                        established: false,
                        established_at: None,
                        last_activity: Instant::now(),
                        dtls_deadline: None,
                        bytes_tx: 0,
                        bytes_rx: 0,
                        packets_tx: 0,
                        packets_rx: 0,
                        disconnect_reason: "server_shutdown",
                        tx_queue,
                        pending_plain: VecDeque::with_capacity(SESSION_TX_QUEUE_CAPACITY),
                    };
                    sessions.push(session);
                    sessions.len() - 1
                }
            };
            let established_before_processing = sessions
                .iter()
                .filter(|session| session.established)
                .count();
            let session = &mut sessions[index];
            if !new_session {
                if let Err(error) = session.dtls.with(|dtls| dtls.push_incoming(incoming)) {
                    eprintln!("[server] unable to queue client datagram: {error}");
                    sessions.swap_remove(index);
                    continue;
                }
            }
            if !session.established {
                eprintln!("[server] processing DTLS handshake for peer session");
                let handshake_complete = match panic_gate("client DTLS handshake", || {
                    session.dtls.with(|dtls| dtls.handshake())
                }) {
                    Ok(complete) => complete,
                    Err(error) => {
                        eprintln!("[server] DTLS handshake rejected: {error}");
                        sessions.swap_remove(index);
                        continue;
                    }
                };
                if handshake_complete {
                    eprintln!("[server] DTLS handshake complete; reading certificate");
                    let fingerprint = match panic_gate("client certificate", || {
                        session.dtls.with(|dtls| dtls.fingerprint())
                    }) {
                        Ok(fingerprint) => fingerprint,
                        Err(error) => {
                            eprintln!("[server] unable to authenticate peer: {error}");
                            sessions.swap_remove(index);
                            continue;
                        }
                    };
                    let Some((address, _)) = bindings
                        .iter()
                        .find(|(_, expected)| **expected == fingerprint)
                    else {
                        eprintln!("unassigned client certificate {fingerprint}");
                        sessions.swap_remove(index);
                        continue;
                    };
                    if verify_client_san_ip {
                        let san_matches = match panic_gate("client SAN IP verification", || {
                            session
                                .dtls
                                .with(|dtls| dtls.peer_certificate_has_san_ip(*address))
                        }) {
                            Ok(matches) => matches,
                            Err(error) => {
                                eprintln!("[server] unable to verify client SAN IP: {error}");
                                sessions.swap_remove(index);
                                continue;
                            }
                        };
                        if !san_matches {
                            eprintln!(
                                "[server] client certificate SAN IP does not match assigned VPN IP {address}"
                            );
                            sessions.swap_remove(index);
                            continue;
                        }
                    }
                    session.address = *address;
                    session.fingerprint = Some(fingerprint.clone());
                    session.established = true;
                    session.established_at = Some(Instant::now());
                    session.dtls_deadline = None;
                    let connected_peer = session.peer;
                    let connected_address = session.address;
                    let replaces_existing = sessions.iter().any(|candidate| {
                        candidate.established
                            && candidate.address == connected_address
                            && !same_peer(&candidate.peer, &connected_peer)
                    });
                    if established_before_processing >= max_clients && !replaces_existing {
                        eprintln!("maximum client count ({max_clients}) reached after handshake");
                        sessions[index].disconnect_reason = "max_clients";
                        sessions.swap_remove(index);
                        continue;
                    }
                    println!("[server] client {fingerprint} connected as {connected_address}");
                    autobricks_vpn::syslog_connection_event(&format!(
                        "client connected vpn_ip={connected_address} fingerprint={fingerprint}"
                    ));
                    let mut duplicate_index = 0;
                    while duplicate_index < sessions.len() {
                        let duplicate = sessions[duplicate_index].established
                            && sessions[duplicate_index].address == connected_address
                            && !same_peer(&sessions[duplicate_index].peer, &connected_peer);
                        if duplicate {
                            eprintln!(
                                "[server] replacing previous session for {connected_address}"
                            );
                            sessions[duplicate_index].disconnect_reason = "replaced";
                            sessions.swap_remove(duplicate_index);
                        } else {
                            duplicate_index += 1;
                        }
                    }
                } else {
                    let timeout = session.dtls.with(|dtls| dtls.current_timeout());
                    session.dtls_deadline = Some(Instant::now() + timeout);
                }
            } else {
                let read_result = panic_gate("client DTLS read", || {
                    session.dtls.with(|dtls| dtls.read(&mut packet))
                });
                // A pending write may be waiting for this DTLS input to advance.
                dtls_progress.notify();
                let count = match read_result {
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) => {
                        eprintln!("[server] client DTLS session failed: {error}");
                        session.disconnect_reason = "dtls_read_error";
                        sessions.swap_remove(index);
                        continue;
                    }
                };
                if is_keepalive_packet(&packet[..count]) {
                    session.last_activity = Instant::now();
                    if let Err(error) = panic_gate("keepalive response", || {
                        let written = session.dtls.with(|dtls| dtls.write(KEEPALIVE_PACKET))?;
                        validate_datagram_write(written, KEEPALIVE_PACKET.len())
                    }) {
                        if error.kind() != io::ErrorKind::WouldBlock {
                            eprintln!("[server] keepalive response failed: {error}");
                            session.disconnect_reason = "keepalive_write_error";
                            sessions.swap_remove(index);
                        }
                    }
                    continue;
                }
                if let Some((source, destination)) = ipv4_packet_addresses(&packet[..count]) {
                    let broadcast = ipv4_is_broadcast(destination, network_address, network_prefix);
                    let multicast = destination.is_multicast();
                    let destination_allowed = (!broadcast && !multicast)
                        || (broadcast && allow_broadcast)
                        || (multicast && allow_multicast);
                    if source == session.address && destination_allowed {
                        session.bytes_rx = session.bytes_rx.saturating_add(count as u64);
                        session.packets_rx = session.packets_rx.saturating_add(1);
                        match tun.write_packet(&packet[..count]) {
                            Ok(written) if written == count => {
                                session.last_activity = Instant::now();
                            }
                            Ok(written) => eprintln!(
                                "[server] partial TUN write: {written}/{count} bytes; packet dropped"
                            ),
                            Err(error) => match autobricks_vpn::classify_tun_error(&error) {
                                TunErrorAction::Retry | TunErrorAction::DropPacket => {}
                                TunErrorAction::Fatal => {
                                    result = Err(error);
                                    break 'server;
                                }
                            },
                        }
                    }
                }
            }
        }
    }
    active.store(false, Ordering::Release);
    dtls_progress.notify();
    encrypted_queue.close();
    plain_queue.close();
    let _ = encrypt_worker.stop();
    let _ = udp_writer.join();
    let _ = udp_reader.join();
    let _ = tun_reader.join();
    let encrypted_drops = encrypted_drops.load(Ordering::Relaxed);
    let plain_drops = plain_drops.load(Ordering::Relaxed);
    if encrypted_drops > 0 || plain_drops > 0 {
        eprintln!(
            "[server] queue overflow drops: encrypted_rx={encrypted_drops}, plain_tx={plain_drops}"
        );
    }
    eprintln!("[server] shutting down; client forwarding rule removed");
    result
}

#[cfg(test)]
mod tests {
    use super::{drain_encrypted_queue, EncryptedDatagram, Queue};
    use std::io;
    use std::time::Instant;

    fn packet(value: u8) -> EncryptedDatagram {
        EncryptedDatagram {
            bytes: vec![value],
            enqueued_at: Instant::now(),
        }
    }

    #[test]
    fn blocked_session_does_not_block_another_session_queue() {
        let blocked = Queue::new(2).unwrap();
        let ready = Queue::new(2).unwrap();
        blocked.push(packet(1)).unwrap();
        ready.push(packet(2)).unwrap();

        assert!(drain_encrypted_queue(&blocked, |_| {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        })
        .unwrap());

        let mut sent = Vec::new();
        assert!(!drain_encrypted_queue(&ready, |bytes| {
            sent.extend_from_slice(bytes);
            Ok(bytes.len())
        })
        .unwrap());

        assert_eq!(blocked.len(), 1);
        assert!(ready.is_empty());
        assert_eq!(sent, vec![2]);
    }
}
