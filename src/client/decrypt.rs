use super::{ClientDiagnostics, DTLS_READ_DRAIN_LIMIT, RUNNING};
use autobricks_vpn::{
    base::queue::Queue, base::worker::WorkerSignal, ipv4_packet_addresses, is_keepalive_packet,
    panic_gate, DtlsIoResult, SynchronizedDtls,
};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Sender, Arc, Mutex};
use std::thread::{self, JoinHandle};
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

pub(super) fn spawn(context: DecryptContext) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("avpn-client-decrypt".to_string())
        .spawn(move || {
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
            let mut packet = [0u8; 2048];
            let mut drain_pending = false;
            while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
                let observed = progress.generation();
                if queue.is_empty() && !drain_pending {
                    if queue.is_closed() {
                        break;
                    }
                    progress.wait(observed);
                    continue;
                }
                let mut made_progress = false;
                for _ in 0..DTLS_READ_DRAIN_LIMIT {
                    if queue.is_empty() && !drain_pending {
                        break;
                    }
                    let result = panic_gate("client DTLS read worker", || {
                        dtls.with(|dtls| {
                            let before = dtls.receive_callback_stats().0;
                            let result = dtls.read_status(&mut packet);
                            let after = dtls.receive_callback_stats().0;
                            result.map(|status| (status, after > before))
                        })
                    });
                    let (result, consumed) = match result {
                        Ok(result) => result,
                        Err(error) => {
                            diagnostics.dtls_read_other.fetch_add(1, Ordering::Relaxed);
                            active.store(false, Ordering::Release);
                            let _ = errors.send(error);
                            tun_write_queue.close();
                            return;
                        }
                    };
                    made_progress |= consumed;
                    match result {
                        DtlsIoResult::Complete(count) if count > 0 => {
                            drain_pending = true;
                            made_progress = true;
                            progress.notify();
                            diagnostics.dtls_read_ok.fetch_add(1, Ordering::Relaxed);
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
                        DtlsIoResult::Complete(_) | DtlsIoResult::WantRead => {
                            diagnostics
                                .dtls_read_want_read
                                .fetch_add(1, Ordering::Relaxed);
                            drain_pending = false;
                            progress.notify();
                            if !consumed {
                                break;
                            }
                        }
                        DtlsIoResult::WantWrite => {
                            diagnostics
                                .dtls_read_want_write
                                .fetch_add(1, Ordering::Relaxed);
                            drain_pending = true;
                            if !consumed {
                                break;
                            }
                        }
                    }
                }
                if !made_progress {
                    thread::yield_now();
                }
            }
        })
}
