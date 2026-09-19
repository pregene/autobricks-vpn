use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::time::Duration;

pub(super) fn receive_peer(
    fd: RawFd,
) -> io::Result<(libc::sockaddr_storage, libc::socklen_t, Vec<u8>)> {
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

pub(super) fn same_peer(a: &libc::sockaddr_storage, b: &libc::sockaddr_storage) -> bool {
    unsafe {
        libc::memcmp(
            a as *const _ as *const _,
            b as *const _ as *const _,
            mem::size_of::<libc::sockaddr_storage>(),
        ) == 0
    }
}

pub(super) fn peer_ipv4(peer: &libc::sockaddr_storage) -> Option<Ipv4Addr> {
    if peer.ss_family as libc::c_int != libc::AF_INET {
        return None;
    }
    let peer = unsafe { &*(peer as *const _ as *const libc::sockaddr_in) };
    Some(Ipv4Addr::from(peer.sin_addr.s_addr.to_ne_bytes()))
}

pub(super) fn poll(fds: &mut [libc::pollfd], timeout: Duration) -> io::Result<()> {
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

pub(super) fn send_encrypted_datagram(
    fd: RawFd,
    peer: &libc::sockaddr_storage,
    peer_size: libc::socklen_t,
    packet: &[u8],
) -> io::Result<usize> {
    let written = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            peer as *const _ as *const libc::sockaddr,
            peer_size,
        )
    };
    if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(written as usize)
    }
}

#[cfg(unix)]
pub(super) fn socket_fd(socket: &std::net::UdpSocket) -> RawFd {
    socket.as_raw_fd()
}

#[cfg(windows)]
pub(super) fn socket_fd(socket: &std::net::UdpSocket) -> RawFd {
    socket.as_raw_socket() as RawFd
}
