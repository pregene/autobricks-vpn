use super::{ClientDiagnostics, DTLS_READ_DRAIN_LIMIT};
use autobricks_vpn::{
    base::queue::Queue,
    base::worker::{QueueWorker, WorkerSignal},
    ipv4_packet_addresses, is_keepalive_packet, panic_gate, DtlsIoResult, SynchronizedDtls,
};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Sender, Arc, Mutex};
use std::time::Instant;

pub(super) struct DecryptContext {
    pub queue: Arc<Queue<Vec<u8>>>,
    pub tun_write_queue: Arc<Queue<Vec<u8>>>,
    pub dtls: Arc<SynchronizedDtls>,
    pub active: Arc<AtomicBool>,
    pub activity: Arc<Mutex<Instant>>,
    pub progress: Arc<WorkerSignal>,
    pub diagnostics: Arc<ClientDiagnostics>,
    pub errors: Sender<io::Error>,
}

pub(super) fn spawn(context: DecryptContext) -> io::Result<QueueWorker<Vec<u8>>> {
    let DecryptContext {
        queue,
        tun_write_queue,
        dtls,
        active,
        activity,
        progress,
        diagnostics,
        errors,
    } = context;
    QueueWorker::spawn("avpn-client-decrypt", queue, move |datagram| {
        if !active.load(Ordering::Acquire) {
            return;
        }
        let mut packet = [0u8; 2048];
        let mut incoming = Some(datagram);
        for _ in 0..DTLS_READ_DRAIN_LIMIT {
            let observed = progress.generation();
            let result = panic_gate("client DTLS read worker", || {
                dtls.with(|dtls| {
                    if let Some(datagram) = incoming.take() {
                        dtls.push_incoming(datagram)?;
                    }
                    dtls.read_status(&mut packet)
                })
            });
            let count = match result {
                Ok(DtlsIoResult::Complete(0)) => break,
                Ok(DtlsIoResult::Complete(count)) => count,
                Ok(DtlsIoResult::WantRead) => {
                    diagnostics
                        .dtls_read_want_read
                        .fetch_add(1, Ordering::Relaxed);
                    progress.notify();
                    break;
                }
                Ok(DtlsIoResult::WantWrite) => {
                    diagnostics
                        .dtls_read_want_write
                        .fetch_add(1, Ordering::Relaxed);
                    // Retry the same DTLS state only after UDP output/input progresses.
                    progress.wait(observed);
                    if !active.load(Ordering::Acquire) {
                        break;
                    }
                    continue;
                }
                Err(error) => {
                    diagnostics.dtls_read_other.fetch_add(1, Ordering::Relaxed);
                    active.store(false, Ordering::Release);
                    let _ = errors.send(error);
                    tun_write_queue.close();
                    return;
                }
            };
            progress.notify();
            diagnostics.dtls_read_ok.fetch_add(1, Ordering::Relaxed);
            if count >= 28 && packet[9] == 1 {
                let header_len = usize::from(packet[0] & 0x0f) * 4;
                if header_len < count && packet[header_len] == 0 {
                    diagnostics.icmp_echo_reply.fetch_add(1, Ordering::Relaxed);
                }
            }
            *activity
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
            if is_keepalive_packet(&packet[..count]) {
                continue;
            }
            if ipv4_packet_addresses(&packet[..count]).is_none() {
                eprintln!("[client] malformed IPv4 packet from server dropped");
                continue;
            }
            if tun_write_queue.push(packet[..count].to_vec()).is_err() {
                return;
            }
        }
    })
}
