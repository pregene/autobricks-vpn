use super::ClientDiagnostics;
use autobricks_vpn::{
    base::queue::Queue,
    base::worker::{QueueWorker, WorkerSignal},
    panic_gate, DtlsIoResult, SynchronizedDtls,
};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Sender, Arc};

pub(super) fn spawn(
    queue: Arc<Queue<Vec<u8>>>,
    receive_queue: Arc<Queue<Vec<u8>>>,
    dtls: Arc<SynchronizedDtls>,
    active: Arc<AtomicBool>,
    _progress: Arc<WorkerSignal>,
    diagnostics: Arc<ClientDiagnostics>,
    errors: Sender<io::Error>,
) -> io::Result<QueueWorker<Vec<u8>>> {
    QueueWorker::spawn_scan_peek("avpn-client-encrypt", queue, move |packet| {
        if !active.load(Ordering::Acquire) {
            return true;
        }
        match panic_gate("client DTLS write worker", || {
            dtls.with(|dtls| dtls.write_status(packet))
        }) {
            Ok(DtlsIoResult::Complete(written)) if written == packet.len() => {
                diagnostics.dtls_write_ok.fetch_add(1, Ordering::Relaxed);
                true
            }
            Ok(DtlsIoResult::Complete(written)) => {
                eprintln!(
                    "[client] partial DTLS write: {written}/{} bytes; packet dropped",
                    packet.len()
                );
                true
            }
            Ok(DtlsIoResult::WantRead) => {
                diagnostics
                    .dtls_write_want_read
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
            Ok(DtlsIoResult::WantWrite) => {
                diagnostics
                    .dtls_write_want_write
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(error) => {
                active.store(false, Ordering::Release);
                let _ = errors.send(error);
                receive_queue.close();
                true
            }
        }
    })
}
