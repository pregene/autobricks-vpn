use super::{poll, receive_peer, UdpDatagram, RUNNING};
use autobricks_vpn::{base::queue::Queue, base::worker::WorkerSignal};
use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Runs on the Main Thread; only receives datagrams and enqueues them.
pub(super) fn run(
    fd: RawFd,
    queue: Arc<Queue<UdpDatagram>>,
    active: Arc<AtomicBool>,
    drops: Arc<AtomicU64>,
    progress: Arc<WorkerSignal>,
) -> io::Result<()> {
    while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        poll(
            std::slice::from_mut(&mut descriptor),
            Duration::from_millis(100),
        )?;
        if descriptor.revents & libc::POLLIN == 0 {
            continue;
        }
        loop {
            match receive_peer(fd) {
                Ok((peer, peer_size, packet)) => {
                    match queue.push(UdpDatagram {
                        peer,
                        peer_size,
                        packet,
                    }) {
                        Ok(Some(_)) => {
                            drops.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(None) => {}
                        Err(_) => return Ok(()),
                    }
                    progress.notify();
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    break
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}
