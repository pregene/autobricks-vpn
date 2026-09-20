use crate::client::materialize_embedded_credentials;
use autobricks_vpn::{
    base::queue::Queue, base::worker::WorkerSignal, ipv4_destination, ipv4_in_cidr,
    ipv4_is_broadcast, ipv4_packet_addresses, is_keepalive_packet, panic_gate, parse_ini_entries,
    parse_ini_section, parse_ipv4_cidr, validate_client_bindings, Config, Dtls, DtlsIo,
    DtlsIoResult, EncryptedDatagram, ForwardingGuard, IpRateLimiter, RateLimitDecision,
    SynchronizedDtls, Tun, KEEPALIVE_PACKET,
};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Read;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::RawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

mod control;
mod decrypt;
mod encrypt;
mod queues;
mod udp_write;
#[cfg(test)]
use udp_write::drain_encrypted_queue;
mod session;
mod socket;
mod tun_read;
mod udp_read;
use control::ControlSocket;
use session::Session;
use socket::{peer_ipv4, poll, receive_peer, same_peer, send_encrypted_datagram, socket_fd};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("vpn-server supports Linux and macOS only");

static RUNNING: AtomicBool = AtomicBool::new(true);

struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_PER_IP: usize = 2;
const SERVER_QUEUE_CAPACITY: usize = 4096;
const SESSION_TX_QUEUE_CAPACITY: usize = 512;
const SESSION_PACKET_TTL: Duration = Duration::from_secs(2);

struct UdpDatagram {
    peer: libc::sockaddr_storage,
    peer_size: libc::socklen_t,
    packet: Vec<u8>,
}

type ReloadUpdate = (
    HashMap<Ipv4Addr, String>,
    HashMap<Ipv4Addr, (String, String)>,
    Dtls,
    Option<mpsc::Sender<()>>,
);

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

fn client_logins(entries: &[(String, String)]) -> io::Result<HashMap<Ipv4Addr, (String, String)>> {
    let mut logins = HashMap::new();
    for (address, value) in entries {
        let parts: Vec<_> = value.split_whitespace().collect();
        match parts.as_slice() {
            [_] => {}
            [_, id, password] if !id.is_empty() && !password.is_empty() => {
                let address = address
                    .parse()
                    .map_err(|_| io::Error::other("invalid client address"))?;
                logins.insert(address, ((*id).to_string(), (*password).to_string()));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid login fields for {address}"),
                ))
            }
        }
    }
    Ok(logins)
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

pub(crate) fn run(path: &str) -> io::Result<()> {
    RUNNING.store(true, Ordering::Relaxed);
    install_signal_handlers();
    eprintln!("[server] loading config: {path}");
    let mut server = parse_ini_section(path, "server")?;
    let _embedded_credentials = materialize_embedded_credentials(path, &mut server)?;
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
    let control_socket_group = server.get("control_socket_group").map(String::as_str);
    let control = ControlSocket::bind(control_socket_path.clone(), control_socket_group)?;
    let control_wake = control.wake_handle();
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
    let logins = client_logins(&clients)?;
    let bindings = validate_client_bindings(clients, vpn_address, &vpn_network)?;
    let tun = Arc::new(Tun::open(&value(&server, "tun_name", "autobricks0"))?);
    eprintln!("[server] TUN opened: {}", tun.name());
    tun.configure_mtu(mtu)?;
    tun.configure_ipv4(&vpn_address_text, &vpn_address_text, &vpn_network)?;
    eprintln!("[server] TUN configured: {vpn_address}, route {vpn_network}, MTU {mtu}");
    let _forwarding = ForwardingGuard::enable(tun.name(), &vpn_network)?;
    eprintln!("[server] client forwarding enabled for {vpn_network}");
    let config = Arc::new(Config {
        server: true,
        certificate_file,
        private_key_file,
        ca_file,
        crl_file,
        ocsp_enabled,
        ocsp_url,
        mtu,
    });
    // Validate credentials and the wolfSSL setup before accepting untrusted packets.
    drop(Dtls::new(&config)?);
    let cookie_secret = generate_cookie_secret()?;
    let stateless_acceptor = decrypt::create_stateless_acceptor(fd, &config, &cookie_secret)?;
    let sessions = Arc::new(Mutex::new(Vec::<Session>::with_capacity(max_clients)));
    let handshake_limiter =
        IpRateLimiter::new(30, Duration::from_secs(60), Duration::from_secs(600));
    let next_config_reload = Instant::now() + config_reload_interval;
    let queues = queues::ServerQueues::new()?;
    let udp_rx_queue = Arc::clone(&queues.udp_rx_queue);
    let tun_read_queue = Arc::clone(&queues.tun_read_queue);
    let dtls_progress = Arc::new(WorkerSignal::new());
    let retry_requested = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicBool::new(true));
    let plain_drops = Arc::new(AtomicU64::new(0));
    let encrypted_drops = Arc::new(AtomicU64::new(0));
    let (error_sender, error_receiver) = mpsc::channel::<io::Error>();
    let (reload_sender, reload_receiver) = mpsc::channel();

    let tun_reader = tun_read::spawn_tun_reader(
        Arc::clone(&tun),
        Arc::clone(&tun_read_queue),
        Arc::clone(&active),
        Arc::clone(&plain_drops),
        error_sender.clone(),
        #[cfg(target_os = "macos")]
        vpn_address,
    )?;

    let encrypt_worker = encrypt::spawn(
        Arc::clone(&tun_read_queue),
        Arc::clone(&sessions),
        Arc::clone(&active),
        Arc::clone(&dtls_progress),
        Arc::clone(&retry_requested),
        encrypt::EncryptRouting {
            network_address,
            network_prefix,
            allow_broadcast,
            allow_multicast,
        },
    )?;

    let udp_writer = udp_write::spawn(
        socket.try_clone()?,
        Arc::clone(&sessions),
        Arc::clone(&active),
        Arc::clone(&dtls_progress),
        Arc::clone(&tun_read_queue),
        Arc::clone(&retry_requested),
    )?;
    println!(
        "Rust multi-client VPN hub listening on {listen}:{port} through {}",
        tun.name()
    );
    let cleanup_active = Arc::clone(&active);
    let cleanup_progress = Arc::clone(&dtls_progress);
    let cleanup_control_wake = Arc::clone(&control_wake);
    let udp_read_queue = Arc::clone(&udp_rx_queue);
    let udp_read_active = Arc::clone(&active);
    let udp_read_progress = Arc::clone(&dtls_progress);
    let path = path.to_owned();
    let control_worker = control::spawn(control::ControlContext {
        udp_rx_queue: Arc::clone(&udp_rx_queue),
        control,
        sessions: Arc::clone(&sessions),
        path: path.clone(),
        fd,
        config: Arc::clone(&config),
        cookie_secret,
        bindings: bindings.clone(),
        logins: logins.clone(),
        vpn_address,
        vpn_network: vpn_network.clone(),
        next_config_reload,
        config_reload_interval,
        max_session_lifetime,
        active: Arc::clone(&active),
        reload_sender,
    })?;
    let decrypt_worker = decrypt::spawn(decrypt::DecryptContext {
        fd,
        config,
        cookie_secret,
        stateless_acceptor,
        sessions,
        bindings,
        logins,
        handshake_limiter,
        max_clients,
        max_pending_handshakes,
        verify_client_san_ip,
        allow_broadcast,
        allow_multicast,
        network_address,
        network_prefix,
        tun: Arc::clone(&tun),
        udp_rx_queue,
        tun_read_queue: Arc::clone(&tun_read_queue),
        active,
        dtls_progress,
        retry_requested,
        control_wake,
        error_receiver,
        reload_receiver,
    })?;
    let read_result = udp_read::run(
        fd,
        udp_read_queue,
        udp_read_active,
        Arc::clone(&encrypted_drops),
        udp_read_progress,
    );
    cleanup_active.store(false, Ordering::Release);
    cleanup_progress.notify();
    cleanup_control_wake.notify();
    queues.close();
    let encrypt_result = encrypt_worker
        .join()
        .map_err(|_| io::Error::other("encrypt worker panicked"));
    let udp_write_result = udp_writer
        .join()
        .map_err(|_| io::Error::other("UDP write worker panicked"));
    let decrypt_result = decrypt_worker
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("decrypt worker panicked")));
    let control_result = control_worker
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("session control worker panicked")));
    let tun_read_result = tun_reader
        .join()
        .map_err(|_| io::Error::other("TUN read worker panicked"));
    let plain_drops = plain_drops.load(Ordering::Relaxed);
    let encrypted_drops = encrypted_drops.load(Ordering::Relaxed);
    if plain_drops > 0 || encrypted_drops > 0 {
        eprintln!("[server] queue overflow drops: udp_rx={encrypted_drops}, tun_rx={plain_drops}");
    }
    eprintln!("[server] shutting down; client forwarding rule removed");
    read_result
        .and(decrypt_result)
        .and(control_result)
        .and(encrypt_result)
        .and(udp_write_result)
        .and(tun_read_result)
}

#[cfg(test)]
mod tests {
    use super::{
        client_logins, drain_encrypted_queue, materialize_embedded_credentials, parse_ini_section,
        validate_client_bindings, Config, Dtls, EncryptedDatagram, Queue,
    };
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

    #[test]
    fn login_fields_are_optional_but_must_be_complete() {
        let address = "10.9.1.2".to_string();
        assert!(client_logins(&[(address.clone(), "fingerprint".into())])
            .unwrap()
            .is_empty());
        let logins =
            client_logins(&[(address.clone(), "fingerprint alice secret".into())]).unwrap();
        assert_eq!(
            logins[&address.parse().unwrap()],
            ("alice".into(), "secret".into())
        );
        assert!(client_logins(&[(address.clone(), "fingerprint alice".into())]).is_err());
        assert!(client_logins(&[(address, "fingerprint alice secret extra".into())]).is_err());
        let binding = validate_client_bindings(
            vec![(
                "10.9.1.2".into(),
                format!("{} alice secret", "a".repeat(64)),
            )],
            "10.9.1.1".parse().unwrap(),
            "10.9.1.0/24",
        )
        .unwrap();
        assert_eq!(binding[&"10.9.1.2".parse().unwrap()], "a".repeat(64));
    }

    #[test]
    fn configured_embedded_server_credentials_initialize_dtls() {
        let Ok(path) = std::env::var("AVPN_TEST_SERVER_CONFIG") else {
            return;
        };
        let mut values = parse_ini_section(&path, "server").unwrap();
        let _credentials = materialize_embedded_credentials(&path, &mut values)
            .unwrap()
            .unwrap();
        let config = Config {
            server: true,
            certificate_file: values["certificate_file"].clone(),
            private_key_file: values["private_key_file"].clone(),
            ca_file: Some(values["ca_file"].clone()),
            crl_file: None,
            ocsp_enabled: false,
            ocsp_url: None,
            mtu: 1350,
        };
        Dtls::new(&config).unwrap();
    }
}
