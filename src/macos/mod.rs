//! macOS platform backend.
//!
//! macOS uses `utun` and a `poll(2)` readiness loop today. This module is the
//! replacement boundary for a future `kqueue` backend.

use crate::{run_command, validate_mtu};
use libc::c_void;
use std::ffi::CStr;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

#[allow(dead_code)]
pub(crate) struct IoReady {
    pub udp: bool,
    pub udp_writable: bool,
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

#[allow(dead_code)]
pub(crate) fn wait_io(
    socket: &UdpSocket,
    tun: &Tun,
    timeout: Duration,
    want_udp_write: bool,
) -> io::Result<IoReady> {
    let mut descriptors = [
        libc::pollfd {
            fd: socket_handle(socket),
            events: libc::POLLIN | if want_udp_write { libc::POLLOUT } else { 0 },
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
        udp_writable: descriptors[0].revents & libc::POLLOUT != 0,
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
    #[allow(clippy::manual_c_str_literals)]
    pub fn open(_requested_name: &str) -> io::Result<Self> {
        const CTL_NAME: &[u8] = b"com.apple.net.utun_control\0";
        #[repr(C)]
        struct CtlInfo {
            ctl_id: u32,
            ctl_name: [u8; 96],
        }
        #[repr(C)]
        struct SockAddrCtl {
            sc_len: u8,
            sc_family: u8,
            ss_sysaddr: u16,
            sc_id: u32,
            sc_unit: u32,
            sc_reserved: [u32; 5],
        }
        let mut info = CtlInfo {
            ctl_name: [0; 96],
            ctl_id: 0,
        };
        info.ctl_name[..CTL_NAME.len()].copy_from_slice(CTL_NAME);
        unsafe {
            let fd = libc::socket(32, libc::SOCK_DGRAM, 2);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(fd, 0xc0644e03u64, &mut info) < 0 {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }
            let address = SockAddrCtl {
                sc_len: mem::size_of::<SockAddrCtl>() as u8,
                sc_family: 32,
                ss_sysaddr: 2,
                sc_id: info.ctl_id,
                sc_unit: 0,
                sc_reserved: [0; 5],
            };
            if libc::connect(
                fd,
                &address as *const _ as *const libc::sockaddr,
                mem::size_of::<SockAddrCtl>() as u32,
            ) < 0
            {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }
            if let Err(error) = set_nonblocking(fd) {
                libc::close(fd);
                return Err(error);
            }
            let mut name = [0u8; 16];
            let mut name_len = name.len() as libc::socklen_t;
            if libc::getsockopt(fd, 2, 2, name.as_mut_ptr() as *mut c_void, &mut name_len) < 0 {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }
            let name = CStr::from_bytes_until_nul(&name)
                .unwrap_or(CStr::from_bytes_with_nul(b"utun\0").unwrap())
                .to_string_lossy()
                .into_owned();
            Ok(Self { fd, name })
        }
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn configure_mtu(&self, mtu: u16) -> io::Result<()> {
        validate_mtu(mtu)?;
        run_command("ifconfig", &[&self.name, "mtu", &mtu.to_string()])
    }

    pub fn configure_ipv4(&self, address: &str, peer: &str, network: &str) -> io::Result<()> {
        let (network_address, prefix) = crate::validate_tun_ipv4(address, peer, network)?;
        let mask = Ipv4Addr::from(if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        });
        run_command(
            "ifconfig",
            &[
                &self.name,
                address,
                peer,
                "netmask",
                &mask.to_string(),
                "up",
            ],
        )?;
        run_command(
            "route",
            &[
                "-n",
                "add",
                "-net",
                network_address,
                "-netmask",
                &mask.to_string(),
                "-interface",
                &self.name,
            ],
        )
    }

    pub fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut packet = [0u8; 2048];
        let count =
            unsafe { libc::read(self.fd, packet.as_mut_ptr() as *mut c_void, packet.len()) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let count = count as usize;
        if count <= 4 || count - 4 > buffer.len() {
            return Err(io::Error::other("TUN packet too large"));
        }
        buffer[..count - 4].copy_from_slice(&packet[4..count]);
        Ok(count - 4)
    }

    pub fn write_packet(&self, buffer: &[u8]) -> io::Result<usize> {
        let mut packet = [0u8; 2048];
        if buffer.len() > packet.len() - 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TUN packet exceeds internal buffer",
            ));
        }
        let family: u32 = if buffer.first().is_some_and(|byte| byte >> 4 == 6) {
            30
        } else {
            2
        };
        packet[..4].copy_from_slice(&family.to_be_bytes());
        packet[4..4 + buffer.len()].copy_from_slice(buffer);
        let count =
            unsafe { libc::write(self.fd, packet.as_ptr() as *const c_void, buffer.len() + 4) };
        if count < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok((count as usize).saturating_sub(4))
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
