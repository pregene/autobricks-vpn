use autobricks_vpn::{
    ipv4_packet_addresses, ipv4_socket_addr_size, is_keepalive_packet, panic_gate,
    parse_ini_section, socket_addr_storage, Config, DnsGuard, Dtls, DtlsIo, Tun, KEEPALIVE_PACKET,
};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
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
    if verify_server_san_ip {
        dtls.verify_peer_ip(server)?;
    }
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

    while RUNNING.load(Ordering::Relaxed) {
        #[cfg(unix)]
        let mut fds = [
            libc::pollfd {
                fd: socket_fd(&socket),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: tun.fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let until_keepalive = keepalive_interval.saturating_sub(last_keepalive.elapsed());
        let until_dead = liveness_timeout.saturating_sub(last_server_activity.elapsed());
        let poll_timeout = until_keepalive
            .min(until_dead)
            .as_millis()
            .min(i32::MAX as u128) as i32;
        #[cfg(unix)]
        let result = unsafe { libc::poll(fds.as_mut_ptr(), 2, poll_timeout) };
        #[cfg(unix)]
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        #[cfg(unix)]
        let (tun_ready, socket_ready) = (
            fds[1].revents & libc::POLLIN != 0,
            fds[0].revents & libc::POLLIN != 0,
        );
        #[cfg(windows)]
        let (tun_ready, socket_ready) = {
            std::thread::sleep(Duration::from_millis(poll_timeout.clamp(1, 10) as u64));
            (true, true)
        };
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
        if tun_ready {
            let count = match tun.read_packet(&mut packet) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => 0,
                Err(error) => return Err(error),
            };
            if count > 0 {
                match dtls.write(&packet[..count]) {
                    Ok(written) if written == count => {}
                    Ok(written) => eprintln!(
                        "[client] partial DTLS write: {written}/{count} bytes; packet dropped"
                    ),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        eprintln!("[client] DTLS output busy; packet dropped")
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        if socket_ready {
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
