use autobricks_vpn::{
    ipv4_destination, ipv4_source, parse_ini_section, Config, Dtls, DtlsIo, ForwardingGuard, Tun,
};
use std::collections::HashMap;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static RUNNING: AtomicBool = AtomicBool::new(true);

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
    io: Box<DtlsIo>,
    peer: libc::sockaddr_storage,
    address: Ipv4Addr,
    established: bool,
    last_activity: Instant,
}

fn value(values: &HashMap<String, String>, key: &str, default: &str) -> String {
    values
        .get(key)
        .cloned()
        .unwrap_or_else(|| default.to_string())
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

fn poll(fds: &mut [libc::pollfd]) -> io::Result<()> {
    let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 1000) };
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

fn main() -> io::Result<()> {
    install_signal_handlers();
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "server.ini".to_string());
    eprintln!("[server] loading config: {path}");
    let server = parse_ini_section(&path, "server")?;
    let clients = parse_ini_section(&path, "client")?;
    eprintln!("[server] config loaded: {} client bindings", clients.len());
    let max_clients: usize = value(&server, "max_clients", "64")
        .parse()
        .map_err(|_| io::Error::other("invalid max_clients"))?;
    if !(1..=1024).contains(&max_clients) {
        return Err(io::Error::other("max_clients must be between 1 and 1024"));
    }
    let port: u16 = value(&server, "port", "4433")
        .parse()
        .map_err(|_| io::Error::other("invalid port"))?;
    let listen: Ipv4Addr = value(&server, "listen_address", "0.0.0.0")
        .parse()
        .map_err(|_| io::Error::other("invalid listen_address"))?;
    let certificate_file = value(&server, "certificate_file", "server-cert.pem");
    let private_key_file = value(&server, "private_key_file", "server-key.pem");
    let ca_file = server.get("ca_file").filter(|v| !v.is_empty()).cloned();
    let mtu: u16 = value(&server, "mtu", "1200")
        .parse()
        .map_err(|_| io::Error::other("invalid mtu"))?;
    let socket = std::net::UdpSocket::bind(SocketAddr::from((listen, port)))?;
    eprintln!("[server] UDP bound to {listen}:{port}");
    socket.set_nonblocking(true)?;
    let fd = socket_fd(&socket);
    let tun = Tun::open(&value(&server, "tun_name", "autobricks0"))?;
    eprintln!("[server] TUN opened: {}", tun.name());
    let vpn_address = value(&server, "vpn_address", "10.8.1.1");
    let vpn_network = value(&server, "vpn_network", "10.8.1.0/24");
    tun.configure_mtu(mtu)?;
    tun.configure_ipv4(&vpn_address, &vpn_address, &vpn_network)?;
    eprintln!("[server] TUN configured: {vpn_address}, route {vpn_network}, MTU {mtu}");
    let _forwarding = ForwardingGuard::enable(tun.name(), &vpn_network)?;
    eprintln!("[server] client forwarding enabled for {vpn_network}");
    let config = Config {
        server: true,
        certificate_file,
        private_key_file,
        ca_file,
        mtu,
    };
    let bindings: HashMap<Ipv4Addr, String> = clients
        .into_iter()
        .filter_map(|(ip, fingerprint)| {
            Some((
                ip.parse().ok()?,
                fingerprint.replace(':', "").to_lowercase(),
            ))
        })
        .collect();
    let mut sessions: Vec<Session> = Vec::with_capacity(max_clients);
    let mut packet = [0u8; 2048];
    println!(
        "Rust multi-client VPN hub listening on {listen}:{port} through {}",
        tun.name()
    );
    while RUNNING.load(Ordering::Relaxed) {
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
        poll(&mut fds)?;
        if fds[1].revents & libc::POLLIN != 0 {
            let count = tun.read_packet(&mut packet)?;
            if let Some(destination) = ipv4_destination(&packet[..count]) {
                if let Some(session) = sessions
                    .iter_mut()
                    .filter(|session| session.established && session.address == destination)
                    .max_by_key(|session| session.last_activity)
                {
                    match session.dtls.write(&packet[..count]) {
                        Ok(written) if written == count => {
                            session.last_activity = Instant::now();
                        }
                        Ok(written) => eprintln!(
                            "[server] partial DTLS write: {written}/{count} bytes; packet dropped"
                        ),
                        Err(error) => {
                            eprintln!("[server] DTLS write failed: {error}; packet dropped")
                        }
                    }
                }
            }
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let (peer, peer_size, incoming) = receive_peer(fd)?;
            let index = sessions
                .iter()
                .position(|session| same_peer(&session.peer, &peer));
            let new_session = index.is_none();
            let index = match index {
                Some(index) => index,
                None if sessions.len() < max_clients => {
                    eprintln!("[server] creating DTLS session");
                    let mut io = Box::new(DtlsIo::new(fd, peer, peer_size));
                    io.push(incoming.clone());
                    let mut dtls = Dtls::new(&config)?;
                    dtls.set_socket(fd)?;
                    dtls.set_nonblocking(true);
                    dtls.set_peer(&peer, peer_size as usize)?;
                    dtls.set_io(&mut io);
                    eprintln!("[server] DTLS session ready");
                    sessions.push(Session {
                        dtls,
                        io,
                        peer,
                        address: Ipv4Addr::UNSPECIFIED,
                        established: false,
                        last_activity: Instant::now(),
                    });
                    sessions.len() - 1
                }
                None => {
                    eprintln!("maximum client count ({max_clients}) reached");
                    continue;
                }
            };
            let session = &mut sessions[index];
            if !new_session {
                session.io.push(incoming);
            }
            if !session.established {
                eprintln!("[server] processing DTLS handshake for peer session");
                if session.dtls.handshake()? {
                    eprintln!("[server] DTLS handshake complete; reading certificate");
                    let fingerprint = session.dtls.fingerprint()?;
                    let Some((address, _)) = bindings
                        .iter()
                        .find(|(_, expected)| **expected == fingerprint)
                    else {
                        eprintln!("unassigned client certificate {fingerprint}");
                        continue;
                    };
                    session.address = *address;
                    session.established = true;
                    println!(
                        "[server] client {fingerprint} connected as {}",
                        session.address
                    );
                }
            } else {
                let count = session.dtls.read(&mut packet)?;
                if let Some(source) = ipv4_source(&packet[..count]) {
                    if source == session.address {
                        tun.write_packet(&packet[..count])?;
                        session.last_activity = Instant::now();
                    }
                }
            }
        }
        sessions.retain(|session| session.last_activity.elapsed() < Duration::from_secs(300));
    }
    eprintln!("[server] shutting down; client forwarding removed");
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
