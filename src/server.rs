use autobricks_vpn::{
    ipv4_destination, ipv4_in_cidr, ipv4_is_broadcast, ipv4_packet_addresses, is_keepalive_packet,
    panic_gate, parse_ini_entries, parse_ini_section, parse_ipv4_cidr, validate_client_bindings,
    validate_datagram_write, Config, Dtls, DtlsIo, ForwardingGuard, IpRateLimiter,
    RateLimitDecision, Tun, TunErrorAction, KEEPALIVE_PACKET,
};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Read;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("vpn-server supports Linux and macOS only");

static RUNNING: AtomicBool = AtomicBool::new(true);
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_PER_IP: usize = 2;

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
    disconnect_reason: &'static str,
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

fn receive_peer(fd: RawFd) -> io::Result<(libc::sockaddr_storage, libc::socklen_t, Vec<u8>)> {
    let mut peer: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut length = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let mut packet = [0u8; 2048];
    let result = unsafe {
        libc::recvfrom(
            fd,
            packet.as_mut_ptr() as *mut _,
            packet.len(),
            0,
            &mut peer as *mut _ as *mut _,
            &mut length,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((peer, length, packet[..result as usize].to_vec()))
    }
}

fn same_peer(a: &libc::sockaddr_storage, b: &libc::sockaddr_storage) -> bool {
    unsafe {
        libc::memcmp(
            a as *const _ as *const _,
            b as *const _ as *const _,
            mem::size_of::<libc::sockaddr_storage>(),
        ) == 0
    }
}

fn peer_ipv4(peer: &libc::sockaddr_storage) -> Option<Ipv4Addr> {
    if peer.ss_family as libc::c_int != libc::AF_INET {
        return None;
    }
    let peer = unsafe { &*(peer as *const _ as *const libc::sockaddr_in) };
    Some(Ipv4Addr::from(peer.sin_addr.s_addr.to_ne_bytes()))
}

fn poll(fds: &mut [libc::pollfd], timeout: Duration) -> io::Result<()> {
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            Ok(())
        } else {
            Err(error)
        }
    } else {
        Ok(())
    }
}

fn send_tunnel_packet(session: &mut Session, packet: &[u8]) -> bool {
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
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => true,
        Err(error) => {
            eprintln!("[server] DTLS session failed: {error}; removing client");
            session.disconnect_reason = "dtls_write_error";
            false
        }
    }
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
    let mut handshake_limiter =
        IpRateLimiter::new(30, Duration::from_secs(60), Duration::from_secs(600));
    let mut next_config_reload = Instant::now() + config_reload_interval;
    let mut packet = [0u8; 2048];
    println!(
        "Rust multi-client VPN hub listening on {listen}:{port} through {}",
        tun.name()
    );
    while RUNNING.load(Ordering::Relaxed) {
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
        let poll_timeout = sessions
            .iter()
            .filter_map(|session| session.dtls_deadline)
            .map(|deadline| deadline.saturating_duration_since(now))
            .min()
            .unwrap_or(Duration::from_secs(1))
            .min(Duration::from_secs(1));
        let mut fds = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: tun.fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        poll(&mut fds, poll_timeout)?;
        if fds[1].revents & libc::POLLNVAL != 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN descriptor is invalid",
            ));
        }
        if fds[1].revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN device reported a permanent poll error",
            ));
        }
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
                    sessions.swap_remove(session_index);
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
        if fds[1].revents & libc::POLLIN != 0 {
            let count = match tun.read_packet(&mut packet) {
                Ok(count) => count,
                Err(error) => match autobricks_vpn::classify_tun_error(&error) {
                    TunErrorAction::Retry | TunErrorAction::DropPacket => 0,
                    TunErrorAction::Fatal => return Err(error),
                },
            };
            if let Some(destination) = ipv4_destination(&packet[..count]) {
                let broadcast = ipv4_is_broadcast(destination, network_address, network_prefix);
                let multicast = destination.is_multicast();
                if (broadcast && allow_broadcast) || (multicast && allow_multicast) {
                    let mut index = 0;
                    while index < sessions.len() {
                        if sessions[index].established
                            && !send_tunnel_packet(&mut sessions[index], &packet[..count])
                        {
                            sessions.swap_remove(index);
                        } else {
                            index += 1;
                        }
                    }
                } else if !broadcast && !multicast {
                    if let Some((index, _)) = sessions
                        .iter()
                        .enumerate()
                        .filter(|(_, session)| {
                            session.established && session.address == destination
                        })
                        .max_by_key(|(_, session)| session.last_activity)
                    {
                        if !send_tunnel_packet(&mut sessions[index], &packet[..count]) {
                            sessions.swap_remove(index);
                        }
                    }
                }
            }
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let (peer, peer_size, incoming) = match receive_peer(fd) {
                Ok(packet) => packet,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
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
                        disconnect_reason: "server_shutdown",
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
                if let Err(error) = session.dtls.push_incoming(incoming) {
                    eprintln!("[server] unable to queue client datagram: {error}");
                    sessions.swap_remove(index);
                    continue;
                }
            }
            if !session.established {
                eprintln!("[server] processing DTLS handshake for peer session");
                let handshake_complete =
                    match panic_gate("client DTLS handshake", || session.dtls.handshake()) {
                        Ok(complete) => complete,
                        Err(error) => {
                            eprintln!("[server] DTLS handshake rejected: {error}");
                            sessions.swap_remove(index);
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
                            session.dtls.peer_certificate_has_san_ip(*address)
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
                        sessions.swap_remove(index);
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
                                TunErrorAction::Fatal => return Err(error),
                            },
                        }
                    }
                }
            }
        }
    }
    eprintln!("[server] shutting down; client forwarding rule removed");
    Ok(())
}

#[cfg(unix)]
fn socket_fd(socket: &std::net::UdpSocket) -> RawFd {
    socket.as_raw_fd()
}

#[cfg(windows)]
fn socket_fd(socket: &std::net::UdpSocket) -> RawFd {
    socket.as_raw_socket() as RawFd
}
