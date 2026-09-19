use super::RUNNING;
use autobricks_vpn::{base::queue::Queue, base::worker::WorkerSignal, EncryptedDatagram};
use std::io;
use std::net::UdpSocket;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Sender, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub(super) fn spawn(
    socket: UdpSocket,
    queue: Arc<Queue<EncryptedDatagram>>,
    active: Arc<AtomicBool>,
    progress: Arc<WorkerSignal>,
    errors: Sender<io::Error>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("avpn-client-udp-write".to_string())
        .spawn(move || {
            while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
                let Some(front) = queue.peek() else { break };
                if !RUNNING.load(Ordering::Acquire) || !active.load(Ordering::Acquire) {
                    break;
                }
                if front.value().enqueued_at.elapsed() >= Duration::from_secs(2) {
                    front.pop();
                    progress.notify();
                    continue;
                }
                match socket.send(&front.value().bytes) {
                    Ok(written) if written == front.value().bytes.len() => {
                        front.pop();
                        progress.notify();
                    }
                    Ok(written) => {
                        active.store(false, Ordering::Release);
                        let _ = errors.send(io::Error::new(
                            io::ErrorKind::WriteZero,
                            format!(
                                "partial UDP datagram write: {written}/{} bytes",
                                front.value().bytes.len()
                            ),
                        ));
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        drop(front);
                        #[cfg(unix)]
                        {
                            let mut descriptor = libc::pollfd {
                                fd: socket.as_raw_fd(),
                                events: libc::POLLOUT,
                                revents: 0,
                            };
                            let _ = unsafe { libc::poll(&mut descriptor, 1, 100) };
                        }
                        #[cfg(windows)]
                        thread::park_timeout(Duration::from_millis(1));
                    }
                    Err(error) => {
                        active.store(false, Ordering::Release);
                        let _ = errors.send(error);
                        break;
                    }
                }
            }
        })
}
