use super::{ClientDiagnostics, RUNNING};
use autobricks_vpn::{base::queue::Queue, Tun};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Sender, Arc};
use std::thread::{self, JoinHandle};
#[cfg(windows)]
use std::time::Duration;

pub(super) fn spawn(
    tun: Arc<Tun>,
    queue: Arc<Queue<Vec<u8>>>,
    active: Arc<AtomicBool>,
    diagnostics: Arc<ClientDiagnostics>,
    errors: Sender<io::Error>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("avpn-client-tun-write".to_string())
        .spawn(move || {
            while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
                let Some(front) = queue.peek() else { break };
                if !RUNNING.load(Ordering::Acquire) || !active.load(Ordering::Acquire) {
                    break;
                }
                match tun.write_packet(front.value()) {
                    Ok(written) if written == front.value().len() => {
                        front.pop();
                        diagnostics.tun_write.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(written) => {
                        active.store(false, Ordering::Release);
                        let _ = errors.send(io::Error::new(
                            io::ErrorKind::WriteZero,
                            format!("partial TUN write: {written}/{} bytes", front.value().len()),
                        ));
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        // The TUN writer must retain the packet until the descriptor is writable.
                        drop(front);
                        #[cfg(unix)]
                        {
                            let mut descriptor = libc::pollfd {
                                fd: tun.fd(),
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
