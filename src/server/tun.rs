use super::{poll, RUNNING};
use autobricks_vpn::{base::queue::Queue, Tun, TunErrorAction};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub(super) fn spawn_tun_reader(
    tun_reader_device: Arc<Tun>,
    tun_reader_queue: Arc<Queue<Vec<u8>>>,
    tun_reader_active: Arc<AtomicBool>,
    tun_reader_drops: Arc<AtomicU64>,
    tun_reader_errors: mpsc::Sender<io::Error>,
) -> io::Result<JoinHandle<()>> {
    let tun_reader = thread::Builder::new()
        .name("avpn-server-tun-read".to_string())
        .spawn(move || {
            let mut packet = [0u8; 2048];
            while RUNNING.load(Ordering::Acquire) && tun_reader_active.load(Ordering::Acquire) {
                let mut descriptor = libc::pollfd {
                    fd: tun_reader_device.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if let Err(error) = poll(
                    std::slice::from_mut(&mut descriptor),
                    Duration::from_millis(100),
                ) {
                    tun_reader_active.store(false, Ordering::Release);
                    let _ = tun_reader_errors.send(error);
                    tun_reader_queue.close();
                    return;
                }
                if descriptor.revents & libc::POLLNVAL != 0
                    || descriptor.revents & (libc::POLLERR | libc::POLLHUP) != 0
                {
                    tun_reader_active.store(false, Ordering::Release);
                    let _ = tun_reader_errors.send(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "TUN device reported a permanent poll error",
                    ));
                    tun_reader_queue.close();
                    return;
                }
                if descriptor.revents & libc::POLLIN == 0 {
                    continue;
                }
                match tun_reader_device.read_packet(&mut packet) {
                    Ok(count) if count > 0 => match tun_reader_queue.push(packet[..count].to_vec())
                    {
                        Ok(Some(_)) => {
                            tun_reader_drops.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(None) => {}
                        Err(_) => return,
                    },
                    Ok(_) => {}
                    Err(error) => match autobricks_vpn::classify_tun_error(&error) {
                        TunErrorAction::Retry | TunErrorAction::DropPacket => {}
                        TunErrorAction::Fatal => {
                            tun_reader_active.store(false, Ordering::Release);
                            let _ = tun_reader_errors.send(error);
                            tun_reader_queue.close();
                            return;
                        }
                    },
                }
            }
        })?;
    Ok(tun_reader)
}
