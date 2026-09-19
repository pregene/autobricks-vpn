use super::control::ControlWake;
use autobricks_vpn::{base::queue::Queue, EncryptedDatagram, SynchronizedDtls};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

pub(super) struct Session {
    pub(super) dtls: SynchronizedDtls,
    pub(super) peer: libc::sockaddr_storage,
    pub(super) peer_size: libc::socklen_t,
    pub(super) address: Ipv4Addr,
    pub(super) fingerprint: Option<String>,
    pub(super) established: bool,
    pub(super) established_at: Option<Instant>,
    pub(super) last_activity: Instant,
    pub(super) dtls_deadline: Option<Instant>,
    pub(super) drain_pending: bool,
    pub(super) bytes_tx: u64,
    pub(super) bytes_rx: u64,
    pub(super) packets_tx: u64,
    pub(super) packets_rx: u64,
    pub(super) disconnect_reason: &'static str,
    pub(super) enc_tx_queue: Arc<Queue<EncryptedDatagram>>,
    pub(super) raw_tx_queue: Arc<Queue<(Vec<u8>, Instant)>>,
    pub(super) control_wake: Arc<ControlWake>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.enc_tx_queue.close();
        self.raw_tx_queue.close();
        self.control_wake.notify();
        if self.established {
            let duration_seconds = self
                .established_at
                .map(|started| started.elapsed().as_secs())
                .unwrap_or(0);
            autobricks_vpn::syslog_connection_event(&format!(
                "client disconnected vpn_ip={} fingerprint={} duration_seconds={} bytes_tx={} bytes_rx={} packets_tx={} packets_rx={} reason={}",
                self.address,
                self.fingerprint.as_deref().unwrap_or("unknown"),
                duration_seconds,
                self.bytes_tx,
                self.bytes_rx,
                self.packets_tx,
                self.packets_rx,
                self.disconnect_reason
            ));
        }
    }
}
