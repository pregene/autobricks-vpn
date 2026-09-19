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
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
    Ok(false)
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
