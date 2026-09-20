use super::{
    ipv4_destination, ipv4_is_broadcast, panic_gate, DtlsIoResult, Session, SESSION_PACKET_TTL,
};
use autobricks_vpn::{base::queue::Queue, base::worker::WorkerSignal};
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

pub(super) enum SendPacketResult {
    Sent,
    Retry,
    DropPacket,
}

fn send_tunnel_packet(session: &mut Session, packet: &[u8]) -> SendPacketResult {
    match panic_gate("server DTLS write", || {
        session.dtls.with(|dtls| dtls.write_status(packet))
    }) {
        Ok(DtlsIoResult::Complete(written)) if written == packet.len() => {
            session.last_activity = Instant::now();
            session.bytes_tx = session.bytes_tx.saturating_add(written as u64);
            session.packets_tx = session.packets_tx.saturating_add(1);
            SendPacketResult::Sent
        }
        Ok(DtlsIoResult::Complete(written)) => {
            eprintln!(
                "[server] partial DTLS write: {written}/{} bytes",
                packet.len()
            );
            SendPacketResult::DropPacket
        }
        // Retain the same packet for either condition; retry only after DTLS/UDP progress.
        Ok(DtlsIoResult::WantRead) => SendPacketResult::Retry,
        Ok(DtlsIoResult::WantWrite) => SendPacketResult::Retry,
        Err(error) => {
            eprintln!("[server] DTLS write failed: {error}; retaining session until timeout");
            SendPacketResult::Retry
        }
    }
}

pub(super) fn drain_session_plain(session: &mut Session) -> SendPacketResult {
    let queue = Arc::clone(&session.raw_tx_queue);
    drain_raw_queue(&queue, |packet| send_tunnel_packet(session, packet))
}

fn drain_raw_queue(
    queue: &Queue<(Vec<u8>, Instant)>,
    mut write: impl FnMut(&[u8]) -> SendPacketResult,
) -> SendPacketResult {
    while let Ok(front) = queue.try_peek() {
        if front.value().1.elapsed() >= SESSION_PACKET_TTL {
            front.pop();
            continue;
        }
        match write(&front.value().0) {
            SendPacketResult::Sent => {
                front.pop();
            }
            SendPacketResult::Retry => {
                drop(front);
                return SendPacketResult::Retry;
            }
            SendPacketResult::DropPacket => {
                front.pop();
            }
        }
    }
    SendPacketResult::Sent
}

pub(super) fn queue_session_plain(session: &mut Session, packet: Vec<u8>) {
    let _ = session.raw_tx_queue.push((packet, Instant::now()));
}

fn flush_pending(list: &mut [Session]) {
    for session in list {
        let _ = drain_session_plain(session);
    }
}

pub(super) struct EncryptRouting {
    pub(super) network_address: Ipv4Addr,
    pub(super) network_prefix: u8,
    pub(super) allow_broadcast: bool,
    pub(super) allow_multicast: bool,
}

pub(super) fn spawn(
    queue: Arc<Queue<Vec<u8>>>,
    sessions: Arc<Mutex<Vec<Session>>>,
    active: Arc<AtomicBool>,
    signal: Arc<WorkerSignal>,
    retry_requested: Arc<AtomicBool>,
    routing: EncryptRouting,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("avpn-server-encrypt".to_string())
        .spawn(move || {
            let _stop = super::StopOnDrop(Arc::clone(&active));
            while active.load(Ordering::Acquire) && super::RUNNING.load(Ordering::Acquire) {
                let observed = queue.generation();
                while let Ok(packet) = queue.try_pop() {
                    let Some(destination) = ipv4_destination(&packet) else {
                        continue;
                    };
                    let broadcast = ipv4_is_broadcast(
                        destination,
                        routing.network_address,
                        routing.network_prefix,
                    );
                    let multicast = destination.is_multicast();
                    let mut list = sessions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if (broadcast && routing.allow_broadcast)
                        || (multicast && routing.allow_multicast)
                    {
                        for session in list.iter_mut() {
                            if session.authenticated {
                                queue_session_plain(session, packet.clone());
                            }
                        }
                        flush_pending(&mut list);
                    } else if !broadcast && !multicast {
                        if let Some(index) = list
                            .iter()
                            .enumerate()
                            .filter(|(_, session)| {
                                session.authenticated && session.address == destination
                            })
                            .max_by_key(|(_, session)| session.last_activity)
                            .map(|(index, _)| index)
                        {
                            queue_session_plain(&mut list[index], packet);
                            let _ = drain_session_plain(&mut list[index]);
                        }
                    }
                    drop(list);
                    signal.notify();
                    if retry_requested.swap(false, Ordering::AcqRel) {
                        let mut list = sessions
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        flush_pending(&mut list);
                    }
                }
                let mut list = sessions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                flush_pending(&mut list);
                let pending = list.iter().any(|session| !session.raw_tx_queue.is_empty());
                drop(list);
                signal.notify();
                if queue.is_closed() {
                    break;
                }
                if pending {
                    // A WANT status keeps the front packet. Visit every session again;
                    // a busy session must not put the whole encrypt worker to sleep.
                    thread::yield_now();
                } else {
                    queue.wait_for_change(observed);
                }
            }
        })
}

#[cfg(test)]
mod tests {
    use super::{drain_raw_queue, Queue, SendPacketResult, SESSION_PACKET_TTL};
    use std::time::Instant;

    #[test]
    fn would_block_preserves_front_packet_and_fifo_order() {
        let queue = Queue::new(3).unwrap();
        queue.push((vec![1], Instant::now())).unwrap();
        queue.push((vec![2], Instant::now())).unwrap();

        let result = drain_raw_queue(&queue, |_| SendPacketResult::Retry);
        assert!(matches!(result, SendPacketResult::Retry));
        assert_eq!(queue.len(), 2);

        let mut sent = Vec::new();
        let result = drain_raw_queue(&queue, |packet| {
            sent.push(packet[0]);
            SendPacketResult::Sent
        });
        assert!(matches!(result, SendPacketResult::Sent));
        assert_eq!(sent, vec![1, 2]);
        assert!(queue.is_empty());
    }

    #[test]
    fn expired_packet_is_not_retried() {
        let queue = Queue::new(2).unwrap();
        queue
            .push((vec![1], Instant::now() - SESSION_PACKET_TTL))
            .unwrap();
        queue.push((vec![2], Instant::now())).unwrap();
        let mut sent = Vec::new();
        drain_raw_queue(&queue, |packet| {
            sent.push(packet[0]);
            SendPacketResult::Sent
        });
        assert_eq!(sent, vec![2]);
        assert!(queue.is_empty());
    }
}
