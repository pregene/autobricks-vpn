use super::{poll, RUNNING};
use autobricks_vpn::{base::queue::Queue, Tun, TunErrorAction};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub(super) fn spawn_tun_writer(
    tun: Arc<Tun>,
    queue: Arc<Queue<Vec<u8>>>,
    active: Arc<AtomicBool>,
    errors: mpsc::Sender<io::Error>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("avpn-server-tun-write".to_string())
        .spawn(move || {
            let _stop = super::StopOnDrop(Arc::clone(&active));
            while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
                let Some(front) = queue.peek() else { break };
                if !RUNNING.load(Ordering::Acquire) || !active.load(Ordering::Acquire) {
                    break;
                }
                match tun.write_packet(front.value()) {
                    Ok(written) if written == front.value().len() => {
                        front.pop();
                    }
                    Ok(written) => eprintln!(
                        "[server] partial TUN write: {written}/{} bytes; packet dropped",
                        front.pop().len()
                    ),
                    Err(error) => match autobricks_vpn::classify_tun_error(&error) {
                        TunErrorAction::Retry => {
                            drop(front);
                            let mut descriptor = libc::pollfd {
                                fd: tun.fd(),
                                events: libc::POLLOUT,
                                revents: 0,
                            };
                            let _ = poll(
                                std::slice::from_mut(&mut descriptor),
                                Duration::from_millis(100),
                            );
                        }
                        TunErrorAction::DropPacket => {
                            front.pop();
                        }
                        TunErrorAction::Fatal => {
                            drop(front);
                            active.store(false, Ordering::Release);
                            let _ = errors.send(error);
                            break;
                        }
                    },
                }
            }
        })
}
