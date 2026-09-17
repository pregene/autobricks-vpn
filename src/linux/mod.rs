//! Linux platform backend.
//!
//! TUN access is isolated here so the current `poll(2)` readiness backend can be
//! replaced by an `io_uring` completion backend without changing DTLS/session logic.

use crate::{run_command, validate_mtu};
use libc::{c_char, c_void};
use std::io;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

pub(crate) struct IoReady {
    pub udp: bool,
    pub tun: bool,
}

pub(crate) fn socket_handle(socket: &UdpSocket) -> RawFd {
    socket.as_raw_fd()
}

pub(crate) fn wait_udp(socket: &UdpSocket, timeout: Duration) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: socket_handle(socket),
        events: libc::POLLIN,
        revents: 0,
    };
    if poll(&mut descriptor, 1, timeout)? {
        return Ok(true);
    }
    Ok(descriptor.revents & libc::POLLIN != 0)
}

pub(crate) fn wait_io(socket: &UdpSocket, tun: &Tun, timeout: Duration) -> io::Result<IoReady> {
    let mut descriptors = [
        libc::pollfd {
            fd: socket_handle(socket),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: tun.fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let _interrupted = poll(descriptors.as_mut_ptr(), descriptors.len(), timeout)?;
    if descriptors[1].revents & libc::POLLNVAL != 0 {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "TUN descriptor is invalid",
        ));
    }
    if descriptors[1].revents & (libc::POLLERR | libc::POLLHUP) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "TUN device reported a permanent poll error",
        ));
    }
    Ok(IoReady {
        udp: descriptors[0].revents & libc::POLLIN != 0,
        tun: descriptors[1].revents & libc::POLLIN != 0,
    })
}

fn poll(descriptors: *mut libc::pollfd, count: usize, timeout: Duration) -> io::Result<bool> {
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let result = unsafe { libc::poll(descriptors, count as libc::nfds_t, timeout_ms) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
        return Ok(true);
    }
    Ok(false)
}

pub struct Tun {
    fd: RawFd,
    name: String,
}

impl Tun {
    pub fn open(requested_name: &str) -> io::Result<Self> {
        #[repr(C)]
        struct IfReq {
            name: [u8; libc::IFNAMSIZ],
            flags: libc::c_short,
            padding: [u8; 22],
        }
        const TUNSETIFF: libc::c_ulong = 0x400454ca;
        const IFF_TUN: libc::c_short = 0x0001;
        const IFF_NO_PI: libc::c_short = 0x1000;
        let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const c_char, libc::O_RDWR) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut request = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            padding: [0; 22],
        };
        for (slot, byte) in request.name.iter_mut().zip(requested_name.bytes()) {
            *slot = byte;
        }
        if unsafe { libc::ioctl(fd, TUNSETIFF, &mut request) } < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(error);
        }
        if let Err(error) = set_nonblocking(fd) {
            unsafe { libc::close(fd) };
            return Err(error);
        }
        let name = String::from_utf8_lossy(&request.name)
            .trim_end_matches('\0')
            .to_string();
        Ok(Self { fd, name })
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn configure_mtu(&self, mtu: u16) -> io::Result<()> {
        validate_mtu(mtu)?;
        run_command(
            "ip",
            &["link", "set", "dev", &self.name, "mtu", &mtu.to_string()],
        )
    }

    pub fn configure_ipv4(&self, address: &str, _peer: &str, network: &str) -> io::Result<()> {
        let (_, prefix) = crate::validate_tun_ipv4(address, _peer, network)?;
        run_command(
            "ip",
            &[
                "addr",
                "replace",
                &format!("{address}/{prefix}"),
                "dev",
                &self.name,
            ],
        )?;
        run_command("ip", &["link", "set", "dev", &self.name, "up"])?;
        run_command("ip", &["route", "replace", network, "dev", &self.name])
    }

    pub fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let count =
            unsafe { libc::read(self.fd, buffer.as_mut_ptr() as *mut c_void, buffer.len()) };
        if count < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(count as usize)
        }
    }

    pub fn write_packet(&self, buffer: &[u8]) -> io::Result<usize> {
        let count = unsafe { libc::write(self.fd, buffer.as_ptr() as *const c_void, buffer.len()) };
        if count < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(count as usize)
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
