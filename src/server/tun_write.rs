use super::RUNNING;
use autobricks_vpn::{base::queue::Queue, Tun, TunErrorAction};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};

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
                let Some(packet) = queue.pop() else { break };
                if !RUNNING.load(Ordering::Acquire) || !active.load(Ordering::Acquire) {
                    break;
                }
                match tun.write_packet(&packet) {
                    Ok(written) if written == packet.len() => {}
                    Ok(written) => eprintln!(
                        "[server] partial TUN write: {written}/{} bytes; packet dropped",
                        packet.len()
                    ),
                    Err(error) => match autobricks_vpn::classify_tun_error(&error) {
                        TunErrorAction::Retry | TunErrorAction::DropPacket => {}
                        TunErrorAction::Fatal => {
                            active.store(false, Ordering::Release);
                            let _ = errors.send(error);
                            break;
                        }
                    },
                }
            }
        })
}
