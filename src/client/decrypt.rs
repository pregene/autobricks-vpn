use super::{ClientDiagnostics, RUNNING};
use autobricks_vpn::{
    base::queue::{Queue, TryPopError},
    base::worker::WorkerSignal,
    ipv4_packet_addresses, is_keepalive_packet, panic_gate, DtlsIoResult, SynchronizedDtls,
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
            let mut plain = [0u8; 2048];
            let mut pending: Option<Vec<u8>> = None;
            let mut drain = false;
            while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
                let observed = progress.generation();
                if drain {
                    match panic_gate("client DTLS read worker", || {
                        dtls.with(|dtls| dtls.read_status(&mut plain))
                    }) {
                        Ok(DtlsIoResult::Complete(n)) if n > 0 => {
                            diagnostics.dtls_read_ok.fetch_add(1, Ordering::Relaxed);
                            *activity
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
                            if !is_keepalive_packet(&plain[..n]) {
                                if ipv4_packet_addresses(&plain[..n]).is_some() {
                                    if tun_write_queue.push(plain[..n].to_vec()).is_err() {
                                        return;
                                    }
                                } else {
                                    eprintln!("[client] malformed IPv4 packet from server dropped");
                                }
                            }
                            continue;
                        }
                        Ok(DtlsIoResult::WantRead | DtlsIoResult::Complete(_)) => {
                            diagnostics
                                .dtls_read_want_read
                                .fetch_add(1, Ordering::Relaxed);
                            drain = false;
                            progress.notify();
                        }
                        Ok(DtlsIoResult::WantWrite) => {
                            diagnostics
                                .dtls_read_want_write
                                .fetch_add(1, Ordering::Relaxed);
                            progress.wait(observed);
                            continue;
                        }
                        Err(error) => {
                            diagnostics.dtls_read_other.fetch_add(1, Ordering::Relaxed);
                            active.store(false, Ordering::Release);
                            let _ = errors.send(error);
                            return;
                        }
                    }
                }
                if pending.is_none() {
                    match queue.try_pop() {
                        Ok(packet) => pending = Some(packet),
                        Err(TryPopError::Closed) => break,
                        Err(TryPopError::Empty) => {
                            progress.wait(observed);
                            continue;
                        }
                    }
                }
                let packet = pending.as_ref().expect("pending DTLS datagram");
                match panic_gate("client DTLS inject worker", || {
                    dtls.with(|dtls| dtls.inject(packet))
                }) {
                    Ok(true) => {
                        pending = None;
                        drain = true;
                    }
                    Ok(false) => {
                        drain = true;
                    }
                    Err(error) => {
                        diagnostics.dtls_read_other.fetch_add(1, Ordering::Relaxed);
                        active.store(false, Ordering::Release);
                        let _ = errors.send(error);
                        return;
                    }
                }
            }
        })
}
