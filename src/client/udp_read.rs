use super::{socket_fd, ClientDiagnostics, RUNNING};
use autobricks_vpn::{base::queue::Queue, base::worker::WorkerSignal};
use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc::Sender, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;

#[cfg(unix)]
pub(super) fn wait_for_udp(socket: &UdpSocket, timeout: Duration) -> io::Result<bool> {
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
        Ok(descriptor.revents & libc::POLLIN != 0)
    }
}

#[cfg(windows)]
pub(super) fn wait_for_udp(socket: &UdpSocket, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    use crate::windows_socket::{poll, PollFd, POLLIN};
    let mut descriptor = PollFd {
        fd: socket_fd(socket),
        events: POLLIN,
        revents: 0,
    };
    while RUNNING.load(Ordering::Relaxed) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        poll(
            std::slice::from_mut(&mut descriptor),
            remaining.min(Duration::from_millis(100)),
        )?;
        if descriptor.revents & POLLIN != 0 {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
    }
    Ok(false)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn readiness_preserves_full_sized_datagram() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        assert!(!wait_for_udp(&receiver, Duration::ZERO).unwrap());
        let packet = [42u8; 1350];
        sender
            .send_to(&packet, receiver.local_addr().unwrap())
            .unwrap();
        assert!(wait_for_udp(&receiver, Duration::from_secs(1)).unwrap());
        let mut received = [0u8; 2048];
        assert_eq!(receiver.recv(&mut received).unwrap(), packet.len());
        assert_eq!(&received[..packet.len()], &packet);
    }
}

pub(super) fn spawn(
    socket: UdpSocket,
    queue: Arc<Queue<Vec<u8>>>,
    active: Arc<AtomicBool>,
    drops: Arc<AtomicU64>,
    progress: Arc<WorkerSignal>,
    diagnostics: Arc<ClientDiagnostics>,
    errors: Sender<io::Error>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("avpn-client-udp-read".to_string())
        .spawn(move || {
            let mut packet = [0u8; 2048];
            while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
                match wait_for_udp(&socket, Duration::from_millis(100)) {
                    Ok(false) => continue,
                    Ok(true) => {}
                    Err(error) => {
                        active.store(false, Ordering::Release);
                        let _ = errors.send(error);
                        queue.close();
                        break;
                    }
                }
                loop {
                    match socket.recv(&mut packet) {
                        Ok(count) => {
                            diagnostics.udp_read.fetch_add(1, Ordering::Relaxed);
                            match queue.push(packet[..count].to_vec()) {
                                Ok(Some(_)) => {
                                    drops.fetch_add(1, Ordering::Relaxed);
                                }
                                Ok(None) => {}
                                Err(_) => return,
                            }
                            progress.notify();
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            active.store(false, Ordering::Release);
                            let _ = errors.send(error);
                            queue.close();
                            return;
                        }
                    }
                }
            }
        })
}
