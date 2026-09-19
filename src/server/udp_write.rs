use super::{
    poll, send_encrypted_datagram, socket_fd, EncryptedDatagram, Queue, Session, RUNNING,
    SESSION_PACKET_TTL,
};
use autobricks_vpn::base::worker::WorkerSignal;
use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

pub(super) fn drain_encrypted_queue(
    queue: &Queue<EncryptedDatagram>,
    mut send: impl FnMut(&[u8]) -> io::Result<usize>,
) -> io::Result<bool> {
    loop {
        let front = match queue.try_peek() {
            Ok(front) => front,
            Err(_) => return Ok(false),
        };
        if front.value().enqueued_at.elapsed() >= SESSION_PACKET_TTL {
            front.pop();
            continue;
        }
        match send(&front.value().bytes) {
            Ok(written) if written == front.value().bytes.len() => {
                front.pop();
            }
            Ok(written) => {
                let expected = front.value().bytes.len();
                front.pop();
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("partial UDP datagram write: {written}/{expected}"),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                drop(front);
                return Ok(true);
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn spawn(
    socket: UdpSocket,
    sessions: Arc<Mutex<Vec<Session>>>,
    active: Arc<AtomicBool>,
    signal: Arc<WorkerSignal>,
    encrypt_queue: Arc<Queue<Vec<u8>>>,
    retry_requested: Arc<AtomicBool>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("avpn-server-udp-write".to_string())
        .spawn(move || {
            let _stop = super::StopOnDrop(Arc::clone(&active));
            let fd = socket_fd(&socket);
            while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
                let observed = signal.generation();
                let mut sent_any = false;
                let mut socket_blocked = false;
                let mut remove = Vec::new();
                {
                    let mut sessions = sessions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    for (index, session) in sessions.iter_mut().enumerate() {
                        let queue_was_nonempty = !session.enc_tx_queue.is_empty();
                        match drain_encrypted_queue(&session.enc_tx_queue, |packet| {
                            send_encrypted_datagram(fd, &session.peer, session.peer_size, packet)
                        }) {
                            Ok(blocked) => {
                                socket_blocked |= blocked;
                                sent_any |= queue_was_nonempty && !blocked;
                            }
                            Err(error) => {
                                eprintln!(
                                    "[server] UDP send failed for {}: {error}; removing client",
                                    session.address
                                );
                                session.disconnect_reason = "udp_write_error";
                                remove.push(index);
                            }
                        }
                    }
                    for index in remove.into_iter().rev() {
                        sessions.swap_remove(index);
                    }
                }
                if socket_blocked {
                    let mut descriptor = libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    let _ = poll(std::slice::from_mut(&mut descriptor), SESSION_PACKET_TTL);
                    retry_requested.store(true, Ordering::Release);
                    encrypt_queue.notify_change();
                } else if !sent_any {
                    let encrypted_pending = sessions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .iter()
                        .any(|session| !session.enc_tx_queue.is_empty());
                    if !encrypted_pending
                        && RUNNING.load(Ordering::Acquire)
                        && active.load(Ordering::Acquire)
                    {
                        signal.wait(observed);
                    }
                } else {
                    retry_requested.store(true, Ordering::Release);
                    encrypt_queue.notify_change();
                }
            }
        })
}
