use autobricks_vpn::{
    ipv4_packet_addresses, ipv4_socket_addr_size, is_keepalive_packet, panic_gate,
    parse_ini_section, socket_addr_storage, Config, DnsGuard, Dtls, DtlsIo, PacketQueue, Tun,
    KEEPALIVE_PACKET,
};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static RUNNING: AtomicBool = AtomicBool::new(true);
/// Caps how many packets are drained per wakeup so one busy fd cannot starve the other.
const DRAIN_BATCH_LIMIT: u32 = 64;
const INPUT_PROCESS_BATCH: usize = 32;
const INPUT_QUEUE_CAPACITY: usize = 512;
const OUTBOUND_QUEUE_CAPACITY: usize = 256;
const OUTBOUND_QUEUE_TTL: Duration = Duration::from_secs(2);
const OUTBOUND_FLUSH_BATCH: usize = 32;

struct QueuedPacket {
    enqueued_at: Instant,
    payload: Vec<u8>,
}

#[derive(Default)]
struct QueueStats {
    would_block: u64,
    expired_drops: u64,
    overflow_drops: u64,
    max_depth: usize,
}

fn expire_queued_packets(queue: &mut VecDeque<QueuedPacket>, stats: &mut QueueStats, now: Instant) {
    while queue
        .front()
        .is_some_and(|packet| now.duration_since(packet.enqueued_at) >= OUTBOUND_QUEUE_TTL)
    {
        queue.pop_front();
        stats.expired_drops = stats.expired_drops.saturating_add(1);
    }
}

fn enqueue_packet(
    queue: &mut VecDeque<QueuedPacket>,
    stats: &mut QueueStats,
    packet: &[u8],
    now: Instant,
) {
    expire_queued_packets(queue, stats, now);
    if queue.len() >= OUTBOUND_QUEUE_CAPACITY {
        queue.pop_front();
        stats.overflow_drops = stats.overflow_drops.saturating_add(1);
    }
    queue.push_back(QueuedPacket {
        enqueued_at: now,
        payload: packet.to_vec(),
    });
    stats.max_depth = stats.max_depth.max(queue.len());
}

fn flush_outbound_queue(
    dtls: &mut Dtls,
    queue: &mut VecDeque<QueuedPacket>,
    stats: &mut QueueStats,
) -> io::Result<()> {
    expire_queued_packets(queue, stats, Instant::now());
    for _ in 0..OUTBOUND_FLUSH_BATCH {
        let Some(packet) = queue.front() else {
            break;
        };
        let length = packet.payload.len();
        match dtls.write(&packet.payload) {
            Ok(written) if written == length => {
                queue.pop_front();
            }
            Ok(written) => {
                queue.pop_front();
                eprintln!("[client] partial queued DTLS write: {written}/{length}; packet dropped");
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                stats.would_block = stats.would_block.saturating_add(1);
                break;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
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
    #[cfg(unix)]
    autobricks_vpn::enlarge_udp_buffers(crate::platform::socket_handle(&socket));
    eprintln!("[client] UDP connected to {server}:{port}");

    let mut dtls = Dtls::new(config)?;
    dtls.set_socket(crate::platform::socket_handle(&socket))?;
    dtls.set_nonblocking(true);
    let server_peer = socket_addr_storage(SocketAddr::from((server, port)));
    dtls.set_peer(&server_peer, ipv4_socket_addr_size())?;
    let io = DtlsIo::new_client(
        crate::platform::socket_handle(&socket),
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
        if !crate::platform::wait_udp(&socket, retransmit_timeout)? {
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
    tun: &Tun,
    keepalive_interval: Duration,
    verify_server_san_ip: bool,
) -> io::Result<()> {
    let (socket, mut dtls) = connect(server, port, config, verify_server_san_ip)?;
    #[cfg(unix)]
    {
        // After the handshake, only this loop receives UDP datagrams. wolfSSL consumes
        // them from a bounded queue instead of reading the socket inside its callback.
        let server_peer = socket_addr_storage(SocketAddr::from((server, port)));
        dtls.set_io(DtlsIo::new_queued_client(
            crate::platform::socket_handle(&socket),
            server_peer,
            ipv4_socket_addr_size() as _,
        ))?;
    }
    #[cfg(windows)]
    let _socket_lifetime_guard = &socket;
    println!(
        "Rust VPN client connected to {server}:{port} through {}",
        tun.name()
    );
    let liveness_timeout = keepalive_interval.saturating_mul(3);
    let mut packet = [0u8; 2048];
    let mut last_keepalive = Instant::now();
    let mut last_server_activity = Instant::now();
    let mut outbound = VecDeque::with_capacity(OUTBOUND_QUEUE_CAPACITY);
    let mut tun_inbound = PacketQueue::new(INPUT_QUEUE_CAPACITY);
    #[cfg(unix)]
    let mut udp_inbound = PacketQueue::new(INPUT_QUEUE_CAPACITY);
    let mut queue_stats = QueueStats::default();

    while RUNNING.load(Ordering::Relaxed) {
        flush_outbound_queue(&mut dtls, &mut outbound, &mut queue_stats)?;
        let until_keepalive = keepalive_interval.saturating_sub(last_keepalive.elapsed());
        let until_dead = liveness_timeout.saturating_sub(last_server_activity.elapsed());
        let until_queue_expiration = outbound
            .front()
            .map(|packet| OUTBOUND_QUEUE_TTL.saturating_sub(packet.enqueued_at.elapsed()))
            .unwrap_or(Duration::MAX);
        let ready = crate::platform::wait_io(
            &socket,
            tun,
            until_keepalive.min(until_dead).min(until_queue_expiration),
            !outbound.is_empty(),
        )?;
        if ready.udp_writable {
            flush_outbound_queue(&mut dtls, &mut outbound, &mut queue_stats)?;
        }
        if last_server_activity.elapsed() >= liveness_timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "server did not respond to keepalive",
            ));
        }
        if last_keepalive.elapsed() >= keepalive_interval {
            match dtls.write(KEEPALIVE_PACKET) {
                Ok(written) if written == KEEPALIVE_PACKET.len() => {
                    last_keepalive = Instant::now();
                }
                Ok(written) => {
                    return Err(io::Error::other(format!(
                        "partial keepalive write: {written} bytes"
                    )));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        if ready.tun {
            // Event stage: empty the kernel TUN queue quickly without doing DTLS work here.
            for _ in 0..DRAIN_BATCH_LIMIT {
                let count = match tun.read_packet(tun_inbound.write_buffer()) {
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                };
                if count == 0 {
                    break;
                }
                tun_inbound.commit_write(count)?;
            }
        }
        // Processing stage: bounded work keeps UDP receive, keepalive and queue flush fair.
        for _ in 0..INPUT_PROCESS_BATCH {
            let Some(packet) = tun_inbound.front() else {
                break;
            };
            if !outbound.is_empty() {
                enqueue_packet(&mut outbound, &mut queue_stats, packet, Instant::now());
                tun_inbound.pop_front();
                continue;
            }
            match dtls.write(packet) {
                Ok(written) if written == packet.len() => {}
                Ok(written) => eprintln!(
                    "[client] partial DTLS write: {written}/{} bytes; packet dropped",
                    packet.len()
                ),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    queue_stats.would_block = queue_stats.would_block.saturating_add(1);
                    enqueue_packet(&mut outbound, &mut queue_stats, packet, Instant::now());
                }
                Err(error) => return Err(error),
            }
            tun_inbound.pop_front();
        }
        if ready.udp {
            #[cfg(unix)]
            for _ in 0..DRAIN_BATCH_LIMIT {
                let count = match socket.recv(udp_inbound.write_buffer()) {
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                };
                udp_inbound.commit_write(count)?;
            }
            #[cfg(windows)]
            for _ in 0..DRAIN_BATCH_LIMIT {
                let count = match dtls.read(&mut packet) {
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                };
                last_server_activity = Instant::now();
                if is_keepalive_packet(&packet[..count]) {
                    continue;
                }
                if ipv4_packet_addresses(&packet[..count]).is_some() {
                    tun.write_packet(&packet[..count])?;
                } else {
                    eprintln!("[client] malformed IPv4 packet from server dropped");
                }
            }
        }
        #[cfg(unix)]
        for _ in 0..INPUT_PROCESS_BATCH {
            let Some(datagram) = udp_inbound.front() else {
                break;
            };
            dtls.push_incoming(datagram)?;
            udp_inbound.pop_front();
            let count = match dtls.read(&mut packet) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            };
            last_server_activity = Instant::now();
            if is_keepalive_packet(&packet[..count]) {
                continue;
            }
            if ipv4_packet_addresses(&packet[..count]).is_some() {
                tun.write_packet(&packet[..count])?;
            } else {
                eprintln!("[client] malformed IPv4 packet from server dropped");
            }
        }
    }
    eprintln!(
        "[client] outbound queue stats: would_block={} expired_drops={} overflow_drops={} max_depth={}",
        queue_stats.would_block,
        queue_stats.expired_drops,
        queue_stats.overflow_drops,
        queue_stats.max_depth
    );
    Ok(())
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
    let tun = Tun::open(&value(&values, "tun_name", "autobricks1"))?;
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
    let retry_delay = Duration::from_secs(3);
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
        eprintln!(
            "[client] connection lost: {error}; retrying in {}s",
            retry_delay.as_secs()
        );
        std::thread::sleep(retry_delay);
    }
    Ok(())
}
