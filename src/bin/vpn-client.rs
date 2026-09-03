use autobricks_vpn::{parse_ini_section, socket_addr_storage, Config, Dtls, DtlsIo, Tun};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

#[cfg(unix)]
fn socket_fd(socket: &std::net::UdpSocket) -> i32 {
    socket.as_raw_fd()
}

#[cfg(windows)]
fn socket_fd(socket: &std::net::UdpSocket) -> i32 {
    socket.as_raw_socket() as i32
}

fn value(values: &HashMap<String, String>, key: &str, default: &str) -> String {
    values
        .get(key)
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn main() -> io::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "client.ini".to_string());
    eprintln!("[client] loading config: {path}");
    let values = parse_ini_section(&path, "client")?;
    eprintln!("[client] config loaded");
    let server: Ipv4Addr = value(&values, "server_address", "127.0.0.1")
        .parse()
        .map_err(|_| io::Error::other("invalid server_address"))?;
    let port: u16 = value(&values, "port", "4433")
        .parse()
        .map_err(|_| io::Error::other("invalid port"))?;
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(SocketAddr::from((server, port)))?;
    eprintln!("[client] UDP connected to {server}:{port}");
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let config = Config {
        server: false,
        certificate_file: value(&values, "certificate_file", "client-cert.pem"),
        private_key_file: value(&values, "private_key_file", "client-key.pem"),
        ca_file: Some(value(&values, "ca_file", "ca.pem")),
        mtu: value(&values, "mtu", "1200")
            .parse()
            .map_err(|_| io::Error::other("invalid mtu"))?,
    };
    let mut dtls = Dtls::new(&config)?;
    eprintln!("[client] DTLS context created");
    dtls.set_socket(socket_fd(&socket))?;
    eprintln!("[client] DTLS socket attached");
    let skip_tun = std::env::var_os("AVPN_SKIP_TUN").is_some();
    let tun = if skip_tun {
        eprintln!("[client] TUN skipped because AVPN_SKIP_TUN is set");
        None
    } else {
        let tun = Tun::open(&value(&values, "tun_name", "autobricks1"))?;
        eprintln!("[client] TUN opened before handshake: {}", tun.name());
        Some(tun)
    };
    let server_peer = socket_addr_storage(SocketAddr::from((server, port)));
    dtls.set_peer(&server_peer, std::mem::size_of::<libc::sockaddr_in>())?;
    let mut io = Box::new(DtlsIo::new_client(
        socket_fd(&socket),
        server_peer,
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    ));
    dtls.set_io(&mut io);
    eprintln!("[client] DTLS peer set; starting handshake with {server}:{port}");
    eprintln!("[client] sending ClientHello");
    if !dtls.handshake()? {
        return Err(io::Error::other("DTLS handshake did not complete"));
    }
    socket.set_nonblocking(true)?;
    socket.set_read_timeout(None)?;
    dtls.set_nonblocking(true);
    eprintln!("[client] DTLS handshake complete");
    if skip_tun {
        println!("DTLS handshake test succeeded");
        return Ok(());
    }
    let vpn_address = value(&values, "vpn_address", "10.8.1.2");
    let vpn_gateway = value(&values, "vpn_gateway", "10.8.1.1");
    let vpn_network = value(&values, "vpn_network", "10.8.1.0/24");
    let tun = tun.expect("TUN is required when AVPN_SKIP_TUN is not set");
    tun.configure_mtu(config.mtu)?;
    tun.configure_ipv4(&vpn_address, &vpn_gateway, &vpn_network)?;
    eprintln!(
        "[client] TUN configured: {vpn_address}, route {vpn_network}, MTU {}",
        config.mtu
    );
    println!(
        "Rust VPN client connected to {server}:{port} through {}",
        tun.name()
    );
    if values
        .get("force_dns")
        .is_some_and(|value| value == "true" || value == "1")
    {
        println!(
            "DNS policy requested: {} (OS resolver configuration is required)",
            value(&values, "dns_server", "10.8.1.1")
        );
    }
    let mut packet = [0u8; 2048];
    loop {
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
        let result = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if fds[1].revents & libc::POLLIN != 0 {
            let count = tun.read_packet(&mut packet)?;
            match dtls.write(&packet[..count]) {
                Ok(written) if written == count => {}
                Ok(written) => eprintln!(
                    "[client] partial DTLS write: {written}/{count} bytes; packet dropped"
                ),
                Err(error) => eprintln!("[client] DTLS write failed: {error}; packet dropped"),
            }
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let count = dtls.read(&mut packet)?;
            tun.write_packet(&packet[..count])?;
        }
    }
}
