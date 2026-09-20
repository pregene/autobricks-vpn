mod decrypt;
mod encrypt;
mod queues;
mod tun_read;
mod tun_write;
mod udp_read;
mod udp_write;

use autobricks_vpn::{
    base::worker::WorkerSignal, ipv4_socket_addr_size, panic_gate, parse_ini_section,
    socket_addr_storage, Config, DnsGuard, Dtls, DtlsIo, SynchronizedDtls, Tun, KEEPALIVE_PACKET,
};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use udp_read::wait_for_udp;

static RUNNING: AtomicBool = AtomicBool::new(true);
const SERVER_LIVENESS_TIMEOUT: Duration = Duration::from_secs(23);
const HEALTH_PROBE_INTERVAL: Duration = Duration::from_secs(20);
const HEALTH_PROBE_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const RETRY_DELAY: Duration = Duration::from_secs(3);

#[derive(Default)]
pub(super) struct ClientDiagnostics {
    pub(super) udp_read: AtomicU64,
    pub(super) tun_read: AtomicU64,
    pub(super) dtls_read_ok: AtomicU64,
    pub(super) dtls_read_want_read: AtomicU64,
    pub(super) dtls_read_want_write: AtomicU64,
    pub(super) dtls_read_other: AtomicU64,
    pub(super) tun_write: AtomicU64,
    pub(super) icmp_echo_reply: AtomicU64,
    pub(super) dtls_write_ok: AtomicU64,
    pub(super) dtls_write_want_read: AtomicU64,
    pub(super) dtls_write_want_write: AtomicU64,
}

fn effective_keepalive_interval(configured: Duration) -> Duration {
    configured.min(HEALTH_PROBE_INTERVAL)
}

fn reconnect_delay(error: &io::Error) -> Duration {
    if error.kind() == io::ErrorKind::TimedOut {
        Duration::ZERO
    } else {
        RETRY_DELAY
    }
}

#[cfg(unix)]
extern "C" fn stop(_signal: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}

#[cfg(unix)]
fn install_signal_handlers() -> io::Result<()> {
    unsafe {
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
    }
    Ok(())
}

#[cfg(windows)]
extern "system" fn console_handler(signal: u32) -> i32 {
    if matches!(signal, 0 | 1 | 2 | 5 | 6) {
        RUNNING.store(false, Ordering::Relaxed);
        1
    } else {
        0
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
}

#[cfg(windows)]
fn install_signal_handlers() -> io::Result<()> {
    if unsafe { SetConsoleCtrlHandler(Some(console_handler), 1) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn socket_fd(socket: &std::net::UdpSocket) -> i32 {
    socket.as_raw_fd()
}

#[cfg(windows)]
fn socket_fd(socket: &std::net::UdpSocket) -> usize {
    socket.as_raw_socket() as usize
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

fn connect(
    server: Ipv4Addr,
    port: u16,
    config: &Config,
    verify_server_san_ip: bool,
) -> io::Result<(std::net::UdpSocket, Dtls)> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(SocketAddr::from((server, port)))?;
    socket.set_nonblocking(true)?;
    eprintln!("[client] UDP connected to {server}:{port}");

    let mut dtls = Dtls::new(config)?;
    dtls.set_socket(socket_fd(&socket))?;
    dtls.set_nonblocking(true);
    let server_peer = socket_addr_storage(SocketAddr::from((server, port)));
    dtls.set_peer(&server_peer, ipv4_socket_addr_size())?;
    let io = DtlsIo::new_client(
        socket_fd(&socket),
        server_peer,
        ipv4_socket_addr_size() as _,
    );
    dtls.set_io(io)?;
    eprintln!("[client] sending ClientHello");
    let handshake_deadline = Instant::now() + Duration::from_secs(30);
    while RUNNING.load(Ordering::Relaxed) {
        if dtls.handshake()? {
            break;
        }
        let remaining = handshake_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DTLS handshake timed out",
            ));
        }
        let retransmit_timeout = dtls.current_timeout().min(remaining);
        if !wait_for_udp(&socket, retransmit_timeout)? {
            dtls.handle_timeout()?;
        }
    }
    if !RUNNING.load(Ordering::Relaxed) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "client shutdown requested",
        ));
    }
    if verify_server_san_ip && !dtls.peer_certificate_has_san_ip(server)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("server certificate SAN IP does not match {server}"),
        ));
    }
    eprintln!("[client] DTLS handshake complete");
    Ok((socket, dtls))
}

fn run_connection(
    server: Ipv4Addr,
    port: u16,
    config: &Config,
    tun: &Arc<Tun>,
    keepalive_interval: Duration,
    verify_server_san_ip: bool,
) -> io::Result<()> {
    let (socket, mut dtls) = connect(server, port, config, verify_server_san_ip)?;
    let queues = queues::ClientQueues::new()?;
    let encrypted_queue = Arc::clone(&queues.encrypted_rx);
    let plain_queue = Arc::clone(&queues.raw_tx);
    let keepalive_interval = effective_keepalive_interval(keepalive_interval);
    // Established-session datagrams are supplied by the decrypt worker via inject().
    dtls.disable_callback_receive();
    let udp_write_progress = Arc::new(WorkerSignal::new());
    dtls.use_queued_send(Arc::clone(&queues.enc_tx), Arc::clone(&udp_write_progress))?;
    let dtls = Arc::new(SynchronizedDtls::new(dtls));
    println!(
        "Rust VPN client connected to {server}:{port} through {}",
        tun.name()
    );
    let dtls_progress = Arc::new(WorkerSignal::new());
    let active = Arc::new(AtomicBool::new(true));
    let encrypted_drops = Arc::new(AtomicU64::new(0));
    let plain_drops = Arc::new(AtomicU64::new(0));
    let diagnostics = Arc::new(ClientDiagnostics::default());
    let diagnostic_enabled = std::env::var_os("AVPN_DIAG").is_some();
    let last_server_activity = Arc::new(Mutex::new(Instant::now()));
    let (error_sender, error_receiver) = mpsc::channel::<io::Error>();

    let udp_reader = udp_read::spawn(
        socket.try_clone()?,
        Arc::clone(&encrypted_queue),
        Arc::clone(&active),
        Arc::clone(&encrypted_drops),
        Arc::clone(&dtls_progress),
        Arc::clone(&diagnostics),
        error_sender.clone(),
    )?;
    let tun_reader = tun_read::spawn(
        Arc::clone(tun),
        Arc::clone(&plain_queue),
        Arc::clone(&active),
        Arc::clone(&plain_drops),
        Arc::clone(&diagnostics),
        error_sender.clone(),
    )?;
    let decrypt_worker = decrypt::spawn(decrypt::DecryptContext {
        queue: Arc::clone(&encrypted_queue),
        tun_write_queue: Arc::clone(&queues.tun_write),
        dtls: Arc::clone(&dtls),
        active: Arc::clone(&active),
        activity: Arc::clone(&last_server_activity),
        progress: Arc::clone(&dtls_progress),
        diagnostics: Arc::clone(&diagnostics),
        errors: error_sender.clone(),
    })?;
    let tun_writer = tun_write::spawn(
        Arc::clone(tun),
        Arc::clone(&queues.tun_write),
        Arc::clone(&active),
        Arc::clone(&diagnostics),
        error_sender.clone(),
    )?;
    let mut encrypt_worker = encrypt::spawn(
        Arc::clone(&plain_queue),
        Arc::clone(&encrypted_queue),
        Arc::clone(&dtls),
        Arc::clone(&active),
        Arc::clone(&dtls_progress),
        Arc::clone(&diagnostics),
        error_sender.clone(),
    )?;
    let udp_writer = udp_write::spawn(
        socket.try_clone()?,
        Arc::clone(&queues.enc_tx),
        Arc::clone(&active),
        Arc::clone(&dtls_progress),
        error_sender.clone(),
    )?;
    let mut last_keepalive = Instant::now();
    let mut last_probe = Instant::now();
    let mut probing = false;
    let mut last_diagnostic = Instant::now();
    let mut result = Ok(());
    while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
        if diagnostic_enabled && last_diagnostic.elapsed() >= Duration::from_secs(1) {
            let (incoming, callback_pop, callback_empty, callback_oversize) = dtls.with(|dtls| {
                let incoming = dtls.queued_incoming_len();
                let (pop, empty, oversize) = dtls.receive_callback_stats();
                (incoming, pop, empty, oversize)
            });
            eprintln!(
                "[client-diag] udp_rx={} tun_rx={} encrypted_q={} encrypted_drop={} dtls_incoming={} callback_pop={} callback_empty={} callback_oversize={} dtls_read_ok={} read_want_read={} read_want_write={} read_error={} tun_tx={} icmp_reply={} plain_q={} plain_drop={} dtls_write_ok={} write_want_read={} write_want_write={}",
                diagnostics.udp_read.load(Ordering::Relaxed),
                diagnostics.tun_read.load(Ordering::Relaxed),
                encrypted_queue.len(),
                encrypted_drops.load(Ordering::Relaxed),
                incoming,
                callback_pop,
                callback_empty,
                callback_oversize,
                diagnostics.dtls_read_ok.load(Ordering::Relaxed),
                diagnostics.dtls_read_want_read.load(Ordering::Relaxed),
                diagnostics.dtls_read_want_write.load(Ordering::Relaxed),
                diagnostics.dtls_read_other.load(Ordering::Relaxed),
                diagnostics.tun_write.load(Ordering::Relaxed),
                diagnostics.icmp_echo_reply.load(Ordering::Relaxed),
                plain_queue.len(),
                plain_drops.load(Ordering::Relaxed),
                diagnostics.dtls_write_ok.load(Ordering::Relaxed),
                diagnostics.dtls_write_want_read.load(Ordering::Relaxed),
                diagnostics.dtls_write_want_write.load(Ordering::Relaxed),
            );
            last_diagnostic = Instant::now();
        }
        let server_idle = last_server_activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .elapsed();
        if server_idle >= SERVER_LIVENESS_TIMEOUT {
            result = Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "server did not respond to keepalive",
            ));
            break;
        }
        if server_idle < HEALTH_PROBE_INTERVAL {
            probing = false;
        }
        let probe_due = server_idle >= HEALTH_PROBE_INTERVAL
            && (!probing || last_probe.elapsed() >= HEALTH_PROBE_RETRY_INTERVAL);
        let keepalive_due = !probing && last_keepalive.elapsed() >= keepalive_interval;
        if probe_due || keepalive_due {
            match plain_queue.push(KEEPALIVE_PACKET.to_vec()) {
                Ok(dropped) => {
                    if dropped.is_some() {
                        plain_drops.fetch_add(1, Ordering::Relaxed);
                    }
                    last_keepalive = Instant::now();
                    if probe_due {
                        probing = true;
                        last_probe = Instant::now();
                    }
                }
                Err(_) => {
                    result = Err(io::Error::other("client raw TX queue closed"));
                    break;
                }
            }
        }
        match error_receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(error) => {
                result = Err(error);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    active.store(false, Ordering::Release);
    queues.close();
    dtls_progress.notify();
    let _ = decrypt_worker.join();
    let _ = encrypt_worker.stop();
    let _ = udp_reader.join();
    let _ = tun_reader.join();
    let _ = tun_writer.join();
    let _ = udp_writer.join();
    let encrypted_drops = encrypted_drops.load(Ordering::Relaxed);
    let plain_drops = plain_drops.load(Ordering::Relaxed);
    if encrypted_drops > 0 || plain_drops > 0 {
        eprintln!(
            "[client] queue overflow drops: encrypted_rx={encrypted_drops}, plain_tx={plain_drops}"
        );
    }
    result
}

pub(crate) fn run(path: &str) -> io::Result<()> {
    RUNNING.store(true, Ordering::Relaxed);
    install_signal_handlers()?;
    eprintln!("[client] loading config: {path}");
    let values = parse_ini_section(path, "client")?;
    eprintln!("[client] config loaded");
    let server: Ipv4Addr = value(&values, "server_address", "127.0.0.1")
        .parse()
        .map_err(|_| io::Error::other("invalid server_address"))?;
    let port: u16 = value(&values, "port", "4433")
        .parse()
        .map_err(|_| io::Error::other("invalid port"))?;
    let keepalive_interval_secs: u64 = value(&values, "keepalive_interval", "30")
        .parse()
        .map_err(|_| io::Error::other("invalid keepalive_interval"))?;
    if !(5..=90).contains(&keepalive_interval_secs) {
        return Err(io::Error::other(
            "keepalive_interval must be between 5 and 90 seconds",
        ));
    }
    let keepalive_interval = Duration::from_secs(keepalive_interval_secs);
    let verify_server_san_ip = boolean_value(&values, "verify_server_san_ip", true)?;
    let force_dns = boolean_value(&values, "force_dns", false)?;
    let dns_server: Ipv4Addr = value(&values, "dns_server", "10.8.1.1")
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dns_server"))?;
    let config = Config {
        server: false,
        certificate_file: value(&values, "certificate_file", "client-cert.pem"),
        private_key_file: value(&values, "private_key_file", "client-key.pem"),
        ca_file: Some(required_value(&values, "ca_file")?),
        crl_file: values
            .get("crl_file")
            .filter(|value| !value.trim().is_empty())
            .cloned(),
        ocsp_enabled: boolean_value(&values, "ocsp_enabled", true)?,
        ocsp_url: values
            .get("ocsp_url")
            .filter(|value| !value.trim().is_empty())
            .cloned(),
        mtu: value(&values, "mtu", "1200")
            .parse()
            .map_err(|_| io::Error::other("invalid mtu"))?,
    };
    let skip_tun = std::env::var_os("AVPN_SKIP_TUN").is_some();
    if skip_tun {
        eprintln!("[client] TUN skipped because AVPN_SKIP_TUN is set");
        let _connection = connect(server, port, &config, verify_server_san_ip)?;
        println!("DTLS handshake test succeeded");
        return Ok(());
    }
    let tun = Arc::new(Tun::open(&value(&values, "tun_name", "autobricks1"))?);
    eprintln!("[client] TUN opened: {}", tun.name());
    let vpn_address = value(&values, "vpn_address", "10.8.1.2");
    let vpn_gateway = value(&values, "vpn_gateway", "10.8.1.1");
    let vpn_network = value(&values, "vpn_network", "10.8.1.0/24");
    tun.configure_mtu(config.mtu)?;
    tun.configure_ipv4(&vpn_address, &vpn_gateway, &vpn_network)?;
    eprintln!(
        "[client] TUN configured: {vpn_address}, route {vpn_network}, MTU {}",
        config.mtu
    );
    let _dns = force_dns
        .then(|| DnsGuard::apply(tun.name(), dns_server))
        .transpose()?;
    if force_dns {
        println!("DNS forced through {dns_server}; previous settings will be restored on exit");
    }
    while RUNNING.load(Ordering::Relaxed) {
        let error = match panic_gate("client connection", || {
            run_connection(
                server,
                port,
                &config,
                &tun,
                keepalive_interval,
                verify_server_san_ip,
            )
        }) {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        let delay = reconnect_delay(&error);
        if delay.is_zero() {
            eprintln!("[client] connection lost: {error}; reconnecting immediately");
        } else {
            eprintln!(
                "[client] connection lost: {error}; retrying in {}s",
                delay.as_secs()
            );
            std::thread::sleep(delay);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{effective_keepalive_interval, reconnect_delay};
    use std::io;
    use std::time::Duration;

    #[test]
    fn health_probe_caps_long_keepalive_interval() {
        assert_eq!(
            effective_keepalive_interval(Duration::from_secs(30)),
            Duration::from_secs(20)
        );
        assert_eq!(
            effective_keepalive_interval(Duration::from_secs(5)),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn timeout_reconnects_immediately_but_other_failures_back_off() {
        let timeout = io::Error::from(io::ErrorKind::TimedOut);
        let failure = io::Error::other("handshake failed");
        assert_eq!(reconnect_delay(&timeout), Duration::ZERO);
        assert_eq!(reconnect_delay(&failure), Duration::from_secs(3));
    }
}
