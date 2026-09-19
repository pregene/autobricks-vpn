use super::{ClientDiagnostics, RUNNING};
use autobricks_vpn::{base::queue::Queue, Tun};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc::Sender, Arc};
use std::thread::{self, JoinHandle};
#[cfg(windows)]
use std::time::Duration;

pub(super) fn spawn(
    tun: Arc<Tun>,
    queue: Arc<Queue<Vec<u8>>>,
    active: Arc<AtomicBool>,
    drops: Arc<AtomicU64>,
    diagnostics: Arc<ClientDiagnostics>,
    errors: Sender<io::Error>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("avpn-client-tun-read".to_string())
        .spawn(move || {
            let mut packet = [0u8; 2048];
            while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
                #[cfg(unix)]
                {
                    let mut descriptor = libc::pollfd {
                        fd: tun.fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let result = unsafe { libc::poll(&mut descriptor, 1, 100) };
                    if result == 0 {
                        continue;
                    }
                    if result < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        active.store(false, Ordering::Release);
                        let _ = errors.send(error);
                        queue.close();
                        return;
                    }
                }
                match tun.read_packet(&mut packet) {
                    Ok(count) if count > 0 => match queue.push(packet[..count].to_vec()) {
                        Ok(Some(_)) => {
                            diagnostics.tun_read.fetch_add(1, Ordering::Relaxed);
                            drops.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(None) => {
                            diagnostics.tun_read.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => return,
                    },
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        #[cfg(windows)]
                        thread::park_timeout(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        active.store(false, Ordering::Release);
                        let _ = errors.send(error);
                        queue.close();
                        return;
                    }
                }
            }
        })
}
