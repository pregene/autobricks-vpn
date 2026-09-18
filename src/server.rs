use autobricks_vpn::{
    ipv4_destination, ipv4_in_cidr, ipv4_is_broadcast, ipv4_packet_addresses, is_keepalive_packet,
    panic_gate, parse_ini_entries, parse_ini_section, parse_ipv4_cidr, validate_client_bindings,
    validate_datagram_write, Config, Dtls, DtlsIo, ForwardingGuard, IpRateLimiter, PacketQueue,
    RateLimitDecision, Tun, TunErrorAction, KEEPALIVE_PACKET, PACKET_BUFFER_SIZE,
};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::mem;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("vpn-server supports Linux and macOS only");

static RUNNING: AtomicBool = AtomicBool::new(true);
/// Caps how many packets are drained per wakeup so one busy fd cannot starve the other.
const DRAIN_BATCH_LIMIT: u32 = 64;
/// UDP work is capped lower than TUN work so inbound ACK bursts cannot starve downloads.
const UDP_DRAIN_BATCH_LIMIT: u32 = 16;
const INPUT_PROCESS_BATCH: usize = 32;
const INPUT_QUEUE_CAPACITY: usize = 1024;
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_PER_IP: usize = 2;
const OUTBOUND_QUEUE_CAPACITY: usize = 256;
const OUTBOUND_QUEUE_TTL: Duration = Duration::from_secs(2);
const OUTBOUND_FLUSH_BATCH: usize = 32;

type PeerKey = (Ipv4Addr, u16);

struct QueuedPacketSlot {
    enqueued_at: Instant,
    payload: [u8; PACKET_BUFFER_SIZE],
    length: usize,
}

struct OutboundQueue {
    slots: Box<[QueuedPacketSlot]>,
    head: usize,
    length: usize,
}

impl OutboundQueue {
    fn new(capacity: usize) -> Self {
        let now = Instant::now();
        let slots = (0..capacity.max(1))
            .map(|_| QueuedPacketSlot {
                enqueued_at: now,
                payload: [0; PACKET_BUFFER_SIZE],
                length: 0,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            slots,
            head: 0,
            length: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.length == 0
    }
    fn front(&self) -> Option<&QueuedPacketSlot> {
        (self.length != 0).then(|| &self.slots[self.head])
    }
    fn pop_front(&mut self) {
        if self.length == 0 {
            return;
        }
        self.slots[self.head].length = 0;
        self.head = (self.head + 1) % self.slots.len();
        self.length -= 1;
    }
    fn push_copy(&mut self, packet: &[u8], now: Instant) -> io::Result<bool> {
        if packet.len() > PACKET_BUFFER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet exceeds fixed slot",
            ));
        }
        let overflow = self.length == self.slots.len();
        if overflow {
            self.pop_front();
        }
        let index = (self.head + self.length) % self.slots.len();
        let slot = &mut self.slots[index];
        slot.payload[..packet.len()].copy_from_slice(packet);
        slot.length = packet.len();
        slot.enqueued_at = now;
        self.length += 1;
        Ok(overflow)
    }
}

struct IncomingDatagram {
    peer: libc::sockaddr_storage,
    peer_size: libc::socklen_t,
    payload: [u8; PACKET_BUFFER_SIZE],
    length: usize,
}

impl IncomingDatagram {
    fn new() -> Self {
        Self {
            peer: unsafe { mem::zeroed() },
            peer_size: 0,
            payload: [0; PACKET_BUFFER_SIZE],
            length: 0,
        }
    }
}

struct DatagramLease<'a> {
    datagram: Option<Box<IncomingDatagram>>,
    free: &'a mut VecDeque<Box<IncomingDatagram>>,
}

impl<'a> DatagramLease<'a> {
    fn new(datagram: Box<IncomingDatagram>, free: &'a mut VecDeque<Box<IncomingDatagram>>) -> Self {
        Self {
            datagram: Some(datagram),
            free,
        }
    }
}

impl Deref for DatagramLease<'_> {
    type Target = IncomingDatagram;

    fn deref(&self) -> &Self::Target {
        self.datagram.as_deref().expect("datagram lease is valid")
    }
}

impl Drop for DatagramLease<'_> {
    fn drop(&mut self) {
        if let Some(datagram) = self.datagram.take() {
            self.free.push_back(datagram);
        }
    }
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

struct Session {
    dtls: Dtls,
    peer: libc::sockaddr_storage,
    address: Ipv4Addr,
    fingerprint: Option<String>,
    established: bool,
    established_at: Option<Instant>,
    last_activity: Instant,
    dtls_deadline: Option<Instant>,
    bytes_tx: u64,
    bytes_rx: u64,
    packets_tx: u64,
    packets_rx: u64,
    outbound: OutboundQueue,
    queue_expired_drops: u64,
    queue_overflow_drops: u64,
    disconnect_reason: &'static str,
}

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
        let snapshot = session_snapshot(sessions);
        let message = format!("{snapshot}\n");
        self.watchers
            .retain_mut(|stream| match stream.write_all(message.as_bytes()) {
                Ok(()) => true,
                Err(error) => error.kind() == io::ErrorKind::WouldBlock,
            });
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

impl Drop for ControlSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
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

impl Drop for Session {
    fn drop(&mut self) {
        if self.established {
            let duration_seconds = self
                .established_at
                .map(|started| started.elapsed().as_secs())
                .unwrap_or(0);
            autobricks_vpn::syslog_connection_event(&format!(
                "client disconnected vpn_ip={} fingerprint={} duration_seconds={} bytes_tx={} bytes_rx={} packets_tx={} packets_rx={} reason={}",
                self.address,
                self.fingerprint.as_deref().unwrap_or("unknown"),
                duration_seconds,
                self.bytes_tx,
                self.bytes_rx,
                self.packets_tx,
                self.packets_rx,
                self.disconnect_reason
            ));
        }
    }
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

fn receive_peer(fd: RawFd, datagram: &mut IncomingDatagram) -> io::Result<()> {
    datagram.peer = unsafe { mem::zeroed() };
    let mut length = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let result = unsafe {
        libc::recvfrom(
            fd,
            datagram.payload.as_mut_ptr() as *mut _,
            datagram.payload.len(),
            0,
            &mut datagram.peer as *mut _ as *mut _,
            &mut length,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        datagram.peer_size = length;
        datagram.length = result as usize;
        Ok(())
    }
}

fn peer_ipv4(peer: &libc::sockaddr_storage) -> Option<Ipv4Addr> {
    if peer.ss_family as libc::c_int != libc::AF_INET {
        return None;
    }
    let peer = unsafe { &*(peer as *const _ as *const libc::sockaddr_in) };
    Some(Ipv4Addr::from(peer.sin_addr.s_addr.to_ne_bytes()))
}

fn peer_key(peer: &libc::sockaddr_storage) -> Option<PeerKey> {
    if peer.ss_family as libc::c_int != libc::AF_INET {
        return None;
    }
    let peer = unsafe { &*(peer as *const _ as *const libc::sockaddr_in) };
    Some((
        Ipv4Addr::from(peer.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(peer.sin_port),
    ))
}

fn rebuild_session_indexes(
    sessions: &[Session],
    peer_sessions: &mut HashMap<PeerKey, usize>,
    vpn_sessions: &mut HashMap<Ipv4Addr, usize>,
) {
    peer_sessions.clear();
    vpn_sessions.clear();
    for (index, session) in sessions.iter().enumerate() {
        if let Some(key) = peer_key(&session.peer) {
            peer_sessions.insert(key, index);
        }
        if session.established {
            vpn_sessions.insert(session.address, index);
        }
    }
}

fn remove_session(
    sessions: &mut Vec<Session>,
    index: usize,
    peer_sessions: &mut HashMap<PeerKey, usize>,
    vpn_sessions: &mut HashMap<Ipv4Addr, usize>,
) {
    sessions.swap_remove(index);
    rebuild_session_indexes(sessions, peer_sessions, vpn_sessions);
}

fn expire_queued_packets(session: &mut Session, now: Instant) {
    while session
        .outbound
        .front()
        .is_some_and(|packet| now.duration_since(packet.enqueued_at) >= OUTBOUND_QUEUE_TTL)
    {
        session.outbound.pop_front();
        session.queue_expired_drops = session.queue_expired_drops.saturating_add(1);
    }
}

fn enqueue_tunnel_packet(session: &mut Session, packet: &[u8], now: Instant) {
    expire_queued_packets(session, now);
    match session.outbound.push_copy(packet, now) {
        Ok(true) => {
            session.queue_overflow_drops = session.queue_overflow_drops.saturating_add(1);
        }
        Ok(false) => {}
        Err(error) => {
            eprintln!("[server] unable to queue tunnel packet: {error}");
            session.queue_overflow_drops = session.queue_overflow_drops.saturating_add(1);
        }
    }
}

fn send_tunnel_packet(session: &mut Session, packet: &[u8]) -> bool {
    let now = Instant::now();
    expire_queued_packets(session, now);
    if !session.outbound.is_empty() {
        enqueue_tunnel_packet(session, packet, now);
        return true;
    }
    match panic_gate("server DTLS write", || session.dtls.write(packet)) {
        Ok(written) if written == packet.len() => {
            session.last_activity = Instant::now();
            session.bytes_tx = session.bytes_tx.saturating_add(written as u64);
            session.packets_tx = session.packets_tx.saturating_add(1);
            true
        }
        Ok(written) => {
            eprintln!(
                "[server] partial DTLS write: {written}/{} bytes; packet dropped",
                packet.len()
            );
            true
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            enqueue_tunnel_packet(session, packet, now);
            true
        }
        Err(error) => {
            eprintln!("[server] DTLS session failed: {error}; removing client");
            session.disconnect_reason = "dtls_write_error";
            false
        }
    }
}

fn flush_outbound_queue(session: &mut Session) -> bool {
    expire_queued_packets(session, Instant::now());
    for _ in 0..OUTBOUND_FLUSH_BATCH {
        let Some(packet) = session.outbound.front() else {
            break;
        };
        let length = packet.length;
        match panic_gate("queued server DTLS write", || {
            session.dtls.write(&packet.payload[..length])
        }) {
            Ok(written) if written == length => {
                session.outbound.pop_front();
                session.last_activity = Instant::now();
                session.bytes_tx = session.bytes_tx.saturating_add(written as u64);
                session.packets_tx = session.packets_tx.saturating_add(1);
            }
            Ok(written) => {
                eprintln!("[server] partial queued DTLS write: {written}/{length}; packet dropped");
                session.outbound.pop_front();
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => {
                eprintln!("[server] queued DTLS write failed: {error}; removing client");
                session.disconnect_reason = "dtls_write_error";
                return false;
            }
        }
    }
    true
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
    let fd = crate::platform::socket_handle(&socket);
    autobricks_vpn::enlarge_udp_buffers(fd);
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
    let mut fingerprint_bindings: HashMap<String, Ipv4Addr> = bindings
        .iter()
        .map(|(address, fingerprint)| (fingerprint.clone(), *address))
        .collect();
    let tun = Tun::open(&value(&server, "tun_name", "autobricks0"))?;
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
    let mut sessions: Vec<Session> = Vec::with_capacity(max_clients);
    let mut peer_sessions: HashMap<PeerKey, usize> = HashMap::with_capacity(max_clients);
    let mut vpn_sessions: HashMap<Ipv4Addr, usize> = HashMap::with_capacity(max_clients);
    let mut handshake_limiter =
        IpRateLimiter::new(30, Duration::from_secs(60), Duration::from_secs(600));
    let mut next_config_reload = Instant::now() + config_reload_interval;
    let mut packet = [0u8; 2048];
    let mut udp_inbound: VecDeque<Box<IncomingDatagram>> =
        VecDeque::with_capacity(INPUT_QUEUE_CAPACITY);
    let mut udp_free: VecDeque<Box<IncomingDatagram>> = (0..INPUT_QUEUE_CAPACITY)
        .map(|_| Box::new(IncomingDatagram::new()))
        .collect();
    let mut tun_inbound = PacketQueue::new(INPUT_QUEUE_CAPACITY);
    println!(
        "Rust multi-client VPN hub listening on {listen}:{port} through {}",
        tun.name()
    );
    while RUNNING.load(Ordering::Relaxed) {
        control.process(&mut sessions)?;
        rebuild_session_indexes(&sessions, &mut peer_sessions, &mut vpn_sessions);
        let mut queue_index = 0;
        while queue_index < sessions.len() {
            if sessions[queue_index].established
                && !flush_outbound_queue(&mut sessions[queue_index])
            {
                remove_session(
                    &mut sessions,
                    queue_index,
                    &mut peer_sessions,
                    &mut vpn_sessions,
                );
            } else {
                queue_index += 1;
            }
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
                    fingerprint_bindings = bindings
                        .iter()
                        .map(|(address, fingerprint)| (fingerprint.clone(), *address))
                        .collect();
                    stateless_acceptor = new_acceptor;
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
                    rebuild_session_indexes(&sessions, &mut peer_sessions, &mut vpn_sessions);
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
        let poll_timeout = sessions
            .iter()
            .filter_map(|session| session.dtls_deadline)
            .map(|deadline| deadline.saturating_duration_since(now))
            .min()
            .unwrap_or(Duration::from_secs(1))
            .min(Duration::from_secs(1));
        let ready = crate::platform::wait_io(&socket, &tun, poll_timeout, false)?;
        let now = Instant::now();
        let mut session_index = 0;
        while session_index < sessions.len() {
            let deadline_expired = sessions[session_index]
                .dtls_deadline
                .is_some_and(|deadline| deadline <= now);
            if !sessions[session_index].established && deadline_expired {
                if let Err(error) = panic_gate("DTLS retransmission", || {
                    sessions[session_index].dtls.handle_timeout()
                }) {
                    eprintln!("[server] DTLS retransmission failed: {error}");
                    sessions[session_index].disconnect_reason = "handshake_timeout_error";
                    remove_session(
                        &mut sessions,
                        session_index,
                        &mut peer_sessions,
                        &mut vpn_sessions,
                    );
                    continue;
                }
                let timeout = sessions[session_index].dtls.current_timeout();
                sessions[session_index].dtls_deadline = Some(Instant::now() + timeout);
            }
            session_index += 1;
        }
        sessions.retain_mut(|session| {
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
        rebuild_session_indexes(&sessions, &mut peer_sessions, &mut vpn_sessions);
        if ready.tun {
            for _ in 0..DRAIN_BATCH_LIMIT {
                let count = match tun.read_packet(tun_inbound.write_buffer()) {
                    Ok(count) => count,
                    Err(error) => match autobricks_vpn::classify_tun_error(&error) {
                        TunErrorAction::Retry | TunErrorAction::DropPacket => break,
                        TunErrorAction::Fatal => return Err(error),
                    },
                };
                if count == 0 {
                    break;
                }
                tun_inbound.commit_write(count)?;
            }
        }
        // TUN consumer stage: route a bounded number of queued packets per loop.
        for _ in 0..INPUT_PROCESS_BATCH {
            let Some(packet) = tun_inbound.front() else {
                break;
            };
            if let Some(destination) = ipv4_destination(packet) {
                let broadcast = ipv4_is_broadcast(destination, network_address, network_prefix);
                let multicast = destination.is_multicast();
                if (broadcast && allow_broadcast) || (multicast && allow_multicast) {
                    let mut index = 0;
                    while index < sessions.len() {
                        if sessions[index].established
                            && !send_tunnel_packet(&mut sessions[index], packet)
                        {
                            remove_session(
                                &mut sessions,
                                index,
                                &mut peer_sessions,
                                &mut vpn_sessions,
                            );
                        } else {
                            index += 1;
                        }
                    }
                } else if !broadcast && !multicast {
                    if let Some(index) = vpn_sessions.get(&destination).copied() {
                        if !send_tunnel_packet(&mut sessions[index], packet) {
                            remove_session(
                                &mut sessions,
                                index,
                                &mut peer_sessions,
                                &mut vpn_sessions,
                            );
                        }
                    }
                }
            }
            tun_inbound.pop_front();
        }
        if ready.udp {
            for _ in 0..UDP_DRAIN_BATCH_LIMIT {
                let mut datagram = udp_free
                    .pop_front()
                    .or_else(|| udp_inbound.pop_front())
                    .expect("UDP packet pool is non-empty");
                match receive_peer(fd, &mut datagram) {
                    Ok(()) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        udp_free.push_back(datagram);
                        break;
                    }
                    Err(error) => return Err(error),
                }
                udp_inbound.push_back(datagram);
            }
        }
        // UDP consumer stage: wolfSSL remains owned by this single processing context.
        for _ in 0..INPUT_PROCESS_BATCH {
            let Some(datagram) = udp_inbound.pop_front() else {
                break;
            };
            let datagram = DatagramLease::new(datagram, &mut udp_free);
            let peer = datagram.peer;
            let peer_size = datagram.peer_size;
            let incoming = &datagram.payload[..datagram.length];
            let Some(incoming_peer_key) = peer_key(&peer) else {
                continue;
            };
            let index = peer_sessions.get(&incoming_peer_key).copied();
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
                        stateless_acceptor.set_incoming_peer(peer, peer_size, incoming)
                    {
                        eprintln!("[server] unable to prepare stateless DTLS accept: {error}");
                        stateless_acceptor =
                            create_stateless_acceptor(fd, &config, &cookie_secret)?;
                        continue;
                    }
                    let cookie_valid = match panic_gate("stateless DTLS accept", || {
                        stateless_acceptor.accept_stateless()
                    }) {
                        Ok(valid) => valid,
                        Err(error) => {
                            eprintln!("[server] stateless DTLS accept failed: {error}");
                            stateless_acceptor =
                                create_stateless_acceptor(fd, &config, &cookie_secret)?;
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
                            rebuild_session_indexes(
                                &sessions,
                                &mut peer_sessions,
                                &mut vpn_sessions,
                            );
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
                            remove_session(
                                &mut sessions,
                                oldest,
                                &mut peer_sessions,
                                &mut vpn_sessions,
                            );
                        }
                    }
                    eprintln!("[server] DTLS cookie verified; creating session");
                    let replacement = create_stateless_acceptor(fd, &config, &cookie_secret)?;
                    let dtls = mem::replace(&mut stateless_acceptor, replacement);
                    let session = Session {
                        dtls,
                        peer,
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
                        outbound: OutboundQueue::new(OUTBOUND_QUEUE_CAPACITY),
                        queue_expired_drops: 0,
                        queue_overflow_drops: 0,
                        disconnect_reason: "server_shutdown",
                    };
                    sessions.push(session);
                    rebuild_session_indexes(&sessions, &mut peer_sessions, &mut vpn_sessions);
                    sessions.len() - 1
                }
            };
            let established_before_processing = sessions
                .iter()
                .filter(|session| session.established)
                .count();
            let session = &mut sessions[index];
            if !new_session {
                if let Err(error) = session.dtls.push_incoming(incoming) {
                    eprintln!("[server] unable to queue client datagram: {error}");
                    remove_session(&mut sessions, index, &mut peer_sessions, &mut vpn_sessions);
                    continue;
                }
            }
            if !session.established {
                eprintln!("[server] processing DTLS handshake for peer session");
                let handshake_complete = match panic_gate("client DTLS handshake", || {
                    session.dtls.handshake()
                }) {
                    Ok(complete) => complete,
                    Err(error) => {
                        eprintln!("[server] DTLS handshake rejected: {error}");
                        remove_session(&mut sessions, index, &mut peer_sessions, &mut vpn_sessions);
                        continue;
                    }
                };
                if handshake_complete {
                    eprintln!("[server] DTLS handshake complete; reading certificate");
                    let fingerprint =
                        match panic_gate("client certificate", || session.dtls.fingerprint()) {
                            Ok(fingerprint) => fingerprint,
                            Err(error) => {
                                eprintln!("[server] unable to authenticate peer: {error}");
                                remove_session(
                                    &mut sessions,
                                    index,
                                    &mut peer_sessions,
                                    &mut vpn_sessions,
                                );
                                continue;
                            }
                        };
                    let Some(address) = fingerprint_bindings.get(&fingerprint).copied() else {
                        eprintln!("unassigned client certificate {fingerprint}");
                        remove_session(&mut sessions, index, &mut peer_sessions, &mut vpn_sessions);
                        continue;
                    };
                    if verify_client_san_ip {
                        let san_matches = match panic_gate("client SAN IP verification", || {
                            session.dtls.peer_certificate_has_san_ip(address)
                        }) {
                            Ok(matches) => matches,
                            Err(error) => {
                                eprintln!("[server] unable to verify client SAN IP: {error}");
                                remove_session(
                                    &mut sessions,
                                    index,
                                    &mut peer_sessions,
                                    &mut vpn_sessions,
                                );
                                continue;
                            }
                        };
                        if !san_matches {
                            eprintln!(
                                "[server] client certificate SAN IP does not match assigned VPN IP {address}"
                            );
                            remove_session(
                                &mut sessions,
                                index,
                                &mut peer_sessions,
                                &mut vpn_sessions,
                            );
                            continue;
                        }
                    }
                    session.address = address;
                    session.fingerprint = Some(fingerprint.clone());
                    session.established = true;
                    session.established_at = Some(Instant::now());
                    session.dtls_deadline = None;
                    let connected_address = session.address;
                    let existing_index = vpn_sessions
                        .get(&connected_address)
                        .copied()
                        .filter(|existing| *existing != index);
                    let replaces_existing = existing_index.is_some();
                    if established_before_processing >= max_clients && !replaces_existing {
                        eprintln!("maximum client count ({max_clients}) reached after handshake");
                        sessions[index].disconnect_reason = "max_clients";
                        remove_session(&mut sessions, index, &mut peer_sessions, &mut vpn_sessions);
                        continue;
                    }
                    println!("[server] client {fingerprint} connected as {connected_address}");
                    autobricks_vpn::syslog_connection_event(&format!(
                        "client connected vpn_ip={connected_address} fingerprint={fingerprint}"
                    ));
                    if let Some(existing_index) = existing_index {
                        eprintln!("[server] replacing previous session for {connected_address}");
                        sessions[existing_index].disconnect_reason = "replaced";
                        remove_session(
                            &mut sessions,
                            existing_index,
                            &mut peer_sessions,
                            &mut vpn_sessions,
                        );
                    } else {
                        rebuild_session_indexes(&sessions, &mut peer_sessions, &mut vpn_sessions);
                    }
                } else {
                    session.dtls_deadline = Some(Instant::now() + session.dtls.current_timeout());
                }
            } else {
                let count = match panic_gate("client DTLS read", || session.dtls.read(&mut packet))
                {
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) => {
                        eprintln!("[server] client DTLS session failed: {error}");
                        session.disconnect_reason = "dtls_read_error";
                        remove_session(&mut sessions, index, &mut peer_sessions, &mut vpn_sessions);
                        continue;
                    }
                };
                if is_keepalive_packet(&packet[..count]) {
                    session.last_activity = Instant::now();
                    if let Err(error) = panic_gate("keepalive response", || {
                        let written = session.dtls.write(KEEPALIVE_PACKET)?;
                        validate_datagram_write(written, KEEPALIVE_PACKET.len())
                    }) {
                        if error.kind() != io::ErrorKind::WouldBlock {
                            eprintln!("[server] keepalive response failed: {error}");
                            session.disconnect_reason = "keepalive_write_error";
                            remove_session(
                                &mut sessions,
                                index,
                                &mut peer_sessions,
                                &mut vpn_sessions,
                            );
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
                                TunErrorAction::Fatal => return Err(error),
                            },
                        }
                    }
                }
            }
        }
        control.publish_if_changed(&sessions);
    }
    eprintln!("[server] shutting down; client forwarding rule removed");
    Ok(())
}

#[cfg(test)]
mod allocation_tests {
    use super::*;

    #[test]
    fn outbound_queue_reuses_fixed_slots_and_drops_oldest() {
        let mut queue = OutboundQueue::new(2);
        let now = Instant::now();
        assert!(!queue.push_copy(b"first", now).unwrap());
        assert!(!queue.push_copy(b"second", now).unwrap());
        assert!(queue.push_copy(b"third", now).unwrap());
        let front = queue.front().unwrap();
        assert_eq!(&front.payload[..front.length], b"second");
        queue.pop_front();
        let front = queue.front().unwrap();
        assert_eq!(&front.payload[..front.length], b"third");
    }

    #[test]
    fn datagram_lease_returns_preallocated_slot() {
        let mut free = VecDeque::with_capacity(1);
        let slot = Box::new(IncomingDatagram::new());
        let address = (&*slot) as *const IncomingDatagram;
        {
            let lease = DatagramLease::new(slot, &mut free);
            assert_eq!((&*lease) as *const IncomingDatagram, address);
        }
        assert_eq!(
            (&**free.front().unwrap()) as *const IncomingDatagram,
            address
        );
    }
}
