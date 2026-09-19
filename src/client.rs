use autobricks_vpn::{
    base::queue::Queue,
    base::worker::{QueueWorker, WorkerSignal},
    ipv4_packet_addresses, ipv4_socket_addr_size, is_keepalive_packet, panic_gate,
    parse_ini_section, socket_addr_storage, Config, DnsGuard, Dtls, DtlsIo, SynchronizedDtls, Tun,
    KEEPALIVE_PACKET,
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
use std::thread;
use std::time::{Duration, Instant};

static RUNNING: AtomicBool = AtomicBool::new(true);
const SERVER_LIVENESS_TIMEOUT: Duration = Duration::from_secs(23);
const HEALTH_PROBE_INTERVAL: Duration = Duration::from_secs(20);
const HEALTH_PROBE_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const RETRY_DELAY: Duration = Duration::from_secs(3);
const DTLS_READ_DRAIN_LIMIT: usize = 4096;

#[derive(Default)]
struct ClientDiagnostics {
    udp_read: AtomicU64,
    tun_read: AtomicU64,
    dtls_read_ok: AtomicU64,
    dtls_read_would_block: AtomicU64,
    dtls_read_want_read: AtomicU64,
    dtls_read_want_write: AtomicU64,
    dtls_read_socket_error: AtomicU64,
    dtls_read_other: AtomicU64,
    tun_write: AtomicU64,
    icmp_echo_reply: AtomicU64,
    dtls_write_ok: AtomicU64,
    dtls_write_would_block: AtomicU64,
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

#[cfg(unix)]
fn wait_for_udp(socket: &std::net::UdpSocket, timeout: Duration) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: socket_fd(socket),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(true);
        }
        Err(error)
    } else {
        Ok(result > 0)
    }
}

#[cfg(windows)]
fn wait_for_udp(socket: &std::net::UdpSocket, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    let mut byte = [0u8; 1];
    while RUNNING.load(Ordering::Relaxed) {
        match socket.peek(&mut byte) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
    }
    Ok(false)
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
    const QUEUE_CAPACITY: usize = 1024;
    let keepalive_interval = effective_keepalive_interval(keepalive_interval);
    let encrypted_queue = Arc::new(Queue::new(QUEUE_CAPACITY).map_err(io::Error::other)?);
    let plain_queue = Arc::new(Queue::new(QUEUE_CAPACITY).map_err(io::Error::other)?);
    dtls.use_shared_receive_queue(Arc::clone(&encrypted_queue))?;
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

    let udp_socket = socket.try_clone()?;
    let udp_queue = Arc::clone(&encrypted_queue);
    let udp_active = Arc::clone(&active);
    let udp_drops = Arc::clone(&encrypted_drops);
    let udp_errors = error_sender.clone();
    let udp_progress = Arc::clone(&dtls_progress);
    let udp_diagnostics = Arc::clone(&diagnostics);
    let udp_reader = thread::Builder::new()
        .name("avpn-client-udp-read".to_string())
        .spawn(move || {
            let mut packet = [0u8; 2048];
            while RUNNING.load(Ordering::Acquire) && udp_active.load(Ordering::Acquire) {
                match wait_for_udp(&udp_socket, Duration::from_millis(100)) {
                    Ok(false) => continue,
                    Ok(true) => {}
                    Err(error) => {
                        udp_active.store(false, Ordering::Release);
                        let _ = udp_errors.send(error);
                        udp_queue.close();
                        break;
                    }
                }
                loop {
                    match udp_socket.recv(&mut packet) {
                        Ok(count) => {
                            udp_diagnostics.udp_read.fetch_add(1, Ordering::Relaxed);
                            match udp_queue.push(packet[..count].to_vec()) {
                                Ok(Some(_)) => {
                                    udp_drops.fetch_add(1, Ordering::Relaxed);
                                }
                                Ok(None) => {}
                                Err(_) => return,
                            }
                            udp_progress.notify();
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            udp_active.store(false, Ordering::Release);
                            let _ = udp_errors.send(error);
                            udp_queue.close();
                            return;
                        }
                    }
                }
            }
        })?;

    let tun_reader_device = Arc::clone(tun);
    let tun_queue = Arc::clone(&plain_queue);
    let tun_active = Arc::clone(&active);
    let tun_drops = Arc::clone(&plain_drops);
    let tun_errors = error_sender.clone();
    let tun_diagnostics = Arc::clone(&diagnostics);
    let tun_reader = thread::Builder::new()
        .name("avpn-client-tun-read".to_string())
        .spawn(move || {
            let mut packet = [0u8; 2048];
            while RUNNING.load(Ordering::Acquire) && tun_active.load(Ordering::Acquire) {
                #[cfg(unix)]
                {
                    let mut descriptor = libc::pollfd {
                        fd: tun_reader_device.fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let result = unsafe { libc::poll(&mut descriptor, 1, 100) };
                    if result == 0 {
                        continue;
                    }
                    if result < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        tun_active.store(false, Ordering::Release);
                        let _ = tun_errors.send(error);
                        tun_queue.close();
                        return;
                    }
                }
                match tun_reader_device.read_packet(&mut packet) {
                    Ok(count) if count > 0 => match tun_queue.push(packet[..count].to_vec()) {
                        Ok(Some(_)) => {
                            tun_diagnostics.tun_read.fetch_add(1, Ordering::Relaxed);
                            tun_drops.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(None) => {
                            tun_diagnostics.tun_read.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => return,
                    },
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        #[cfg(windows)]
                        thread::park_timeout(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        tun_active.store(false, Ordering::Release);
                        let _ = tun_errors.send(error);
                        tun_queue.close();
                        return;
                    }
                }
            }
        })?;

    let tun_writer_device = Arc::clone(tun);
    let decrypt_dtls = Arc::clone(&dtls);
    let decrypt_active = Arc::clone(&active);
    let decrypt_plain_queue = Arc::clone(&plain_queue);
    let decrypt_errors = error_sender.clone();
    let decrypt_activity = Arc::clone(&last_server_activity);
    let decrypt_progress = Arc::clone(&dtls_progress);
    let decrypt_diagnostics = Arc::clone(&diagnostics);
    let mut tun_writer = QueueWorker::spawn(
        "avpn-client-tun-write",
        Arc::clone(&encrypted_queue),
        move |datagram| {
            if !decrypt_active.load(Ordering::Acquire) {
                return;
            }
            let mut packet = [0u8; 2048];
            let mut incoming = Some(datagram);
            for _ in 0..DTLS_READ_DRAIN_LIMIT {
                let result = panic_gate("client DTLS read worker", || {
                    decrypt_dtls.with(|dtls| {
                        if let Some(datagram) = incoming.take() {
                            dtls.push_incoming(datagram)?;
                        }
                        dtls.read(&mut packet)
                    })
                });
                decrypt_progress.notify();
                let count = match result {
                    Ok(0) => break,
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        decrypt_diagnostics
                            .dtls_read_would_block
                            .fetch_add(1, Ordering::Relaxed);
                        (match decrypt_dtls.with(|dtls| dtls.last_read_error_code()) {
                            2 => &decrypt_diagnostics.dtls_read_want_read,
                            3 => &decrypt_diagnostics.dtls_read_want_write,
                            -308 => &decrypt_diagnostics.dtls_read_socket_error,
                            _ => &decrypt_diagnostics.dtls_read_other,
                        })
                        .fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    Err(error) => {
                        decrypt_active.store(false, Ordering::Release);
                        let _ = decrypt_errors.send(error);
                        decrypt_plain_queue.close();
                        return;
                    }
                };
                decrypt_diagnostics
                    .dtls_read_ok
                    .fetch_add(1, Ordering::Relaxed);
                if count >= 28 && packet[9] == 1 {
                    let header_len = usize::from(packet[0] & 0x0f) * 4;
                    if header_len < count && packet[header_len] == 0 {
                        decrypt_diagnostics
                            .icmp_echo_reply
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                *decrypt_activity
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
                if is_keepalive_packet(&packet[..count]) {
                    continue;
                }
                if ipv4_packet_addresses(&packet[..count]).is_none() {
                    eprintln!("[client] malformed IPv4 packet from server dropped");
                    continue;
                }
                if let Err(error) = tun_writer_device.write_packet(&packet[..count]) {
                    decrypt_active.store(false, Ordering::Release);
                    let _ = decrypt_errors.send(error);
                    decrypt_plain_queue.close();
                    return;
                }
                decrypt_diagnostics
                    .tun_write
                    .fetch_add(1, Ordering::Relaxed);
            }
        },
    )?;

    let encrypt_dtls = Arc::clone(&dtls);
    let encrypt_active = Arc::clone(&active);
    let encrypt_receive_queue = Arc::clone(&encrypted_queue);
    let encrypt_errors = error_sender.clone();
    let encrypt_diagnostics = Arc::clone(&diagnostics);
    let mut udp_writer = QueueWorker::spawn_peek(
        "avpn-client-udp-write",
        Arc::clone(&plain_queue),
        Arc::clone(&dtls_progress),
        Duration::from_secs(2),
        move |packet| {
            if !encrypt_active.load(Ordering::Acquire) {
                return true;
            }
            match panic_gate("client DTLS write worker", || {
                encrypt_dtls.with(|dtls| dtls.write(packet))
            }) {
                Ok(written) if written == packet.len() => {
                    encrypt_diagnostics
                        .dtls_write_ok
                        .fetch_add(1, Ordering::Relaxed);
                    true
                }
                Ok(written) => {
                    eprintln!(
                        "[client] partial DTLS write: {written}/{} bytes; packet dropped",
                        packet.len()
                    );
                    true
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    encrypt_diagnostics
                        .dtls_write_would_block
                        .fetch_add(1, Ordering::Relaxed);
                    false
                }
                Err(error) => {
                    encrypt_active.store(false, Ordering::Release);
                    let _ = encrypt_errors.send(error);
                    encrypt_receive_queue.close();
                    true
                }
            }
        },
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
                "[client-diag] udp_rx={} tun_rx={} encrypted_q={} encrypted_drop={} dtls_incoming={} callback_pop={} callback_empty={} callback_oversize={} dtls_read_ok={} dtls_read_wouldblock={} want_read={} want_write={} socket_error={} read_other={} tun_tx={} icmp_reply={} plain_q={} plain_drop={} dtls_write_ok={} dtls_write_wouldblock={}",
                diagnostics.udp_read.load(Ordering::Relaxed),
                diagnostics.tun_read.load(Ordering::Relaxed),
                encrypted_queue.len(),
                encrypted_drops.load(Ordering::Relaxed),
                incoming,
                callback_pop,
                callback_empty,
                callback_oversize,
                diagnostics.dtls_read_ok.load(Ordering::Relaxed),
                diagnostics.dtls_read_would_block.load(Ordering::Relaxed),
                diagnostics.dtls_read_want_read.load(Ordering::Relaxed),
                diagnostics.dtls_read_want_write.load(Ordering::Relaxed),
                diagnostics.dtls_read_socket_error.load(Ordering::Relaxed),
                diagnostics.dtls_read_other.load(Ordering::Relaxed),
                diagnostics.tun_write.load(Ordering::Relaxed),
                diagnostics.icmp_echo_reply.load(Ordering::Relaxed),
                plain_queue.len(),
                plain_drops.load(Ordering::Relaxed),
                diagnostics.dtls_write_ok.load(Ordering::Relaxed),
                diagnostics.dtls_write_would_block.load(Ordering::Relaxed),
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
            match dtls.with(|dtls| dtls.write(KEEPALIVE_PACKET)) {
                Ok(written) if written == KEEPALIVE_PACKET.len() => {
                    last_keepalive = Instant::now();
                    if probe_due {
                        probing = true;
                        last_probe = Instant::now();
                    }
                }
                Ok(written) => {
                    return Err(io::Error::other(format!(
                        "partial keepalive write: {written} bytes"
                    )));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    result = Err(error);
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
    encrypted_queue.close();
    plain_queue.close();
    let _ = tun_writer.stop();
    let _ = udp_writer.stop();
    let _ = udp_reader.join();
    let _ = tun_reader.join();
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
