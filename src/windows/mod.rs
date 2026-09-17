//! Windows platform backend.
//!
//! Wintun packet I/O and the current bounded polling fallback live here. The
//! boundary permits a future Overlapped I/O/IOCP implementation.

use crate::{run_command, validate_mtu};
use std::io;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) struct IoReady {
    pub udp: bool,
    pub tun: bool,
}

pub(crate) fn socket_handle(socket: &UdpSocket) -> usize {
    socket.as_raw_socket() as usize
}

pub(crate) fn wait_udp(socket: &UdpSocket, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    let mut byte = [0u8; 1];
    loop {
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
}

pub(crate) fn wait_io(_socket: &UdpSocket, _tun: &Tun, timeout: Duration) -> io::Result<IoReady> {
    std::thread::sleep(timeout.clamp(Duration::from_millis(1), Duration::from_millis(10)));
    Ok(IoReady {
        udp: true,
        tun: true,
    })
}

pub struct Tun {
    name: String,
    session: Arc<wintun::Session>,
}

impl Tun {
    pub fn open(requested_name: &str) -> io::Result<Self> {
        let dll = std::env::var("WINTUN_DLL").unwrap_or_else(|_| "wintun.dll".to_string());
        let wintun = unsafe { wintun::load_from_path(dll) }
            .map_err(|error| io::Error::other(format!("loading Wintun: {error}")))?;
        let adapter = wintun::Adapter::open(&wintun, requested_name)
            .or_else(|_| wintun::Adapter::create(&wintun, requested_name, "autobricks-vpn", None))
            .map_err(|error| io::Error::other(format!("opening Wintun adapter: {error}")))?;
        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|error| io::Error::other(format!("starting Wintun session: {error}")))?,
        );
        Ok(Self {
            name: requested_name.to_string(),
            session,
        })
    }

    pub fn fd(&self) -> usize {
        0
    }
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn configure_mtu(&self, mtu: u16) -> io::Result<()> {
        validate_mtu(mtu)?;
        run_command(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &self.name,
                &format!("mtu={mtu}"),
                "store=active",
            ],
        )
    }

    pub fn configure_ipv4(&self, address: &str, peer: &str, network: &str) -> io::Result<()> {
        let (network_address, prefix) = crate::validate_tun_ipv4(address, peer, network)?;
        let mask = Ipv4Addr::from(if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        });
        run_command(
            "netsh",
            &[
                "interface",
                "ip",
                "set",
                "address",
                &format!("name={}", self.name),
                "static",
                address,
                &mask.to_string(),
                peer,
            ],
        )?;
        run_command(
            "route",
            &["ADD", network_address, "MASK", &mask.to_string(), peer],
        )
    }

    pub fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        match self
            .session
            .try_receive()
            .map_err(|error| io::Error::other(error.to_string()))?
        {
            Some(packet) if packet.bytes().len() <= buffer.len() => {
                buffer[..packet.bytes().len()].copy_from_slice(packet.bytes());
                Ok(packet.bytes().len())
            }
            Some(_) => Err(io::Error::other("TUN packet too large")),
            None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    pub fn write_packet(&self, buffer: &[u8]) -> io::Result<usize> {
        let mut packet = self
            .session
            .allocate_send_packet(buffer.len() as u16)
            .map_err(|error| io::Error::other(error.to_string()))?;
        packet.bytes_mut().copy_from_slice(buffer);
        self.session.send_packet(packet);
        Ok(buffer.len())
    }
}
