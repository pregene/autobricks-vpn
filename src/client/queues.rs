use autobricks_vpn::{base::queue::Queue, EncryptedDatagram};
use std::io;
use std::sync::Arc;

const QUEUE_CAPACITY: usize = 512;

pub(super) struct ClientQueues {
    /// Ciphertext received from UDP, consumed only by the decrypt worker.
    pub encrypted_rx: Arc<Queue<Vec<u8>>>,
    /// Plaintext received from TUN, consumed only by the encrypt worker.
    pub raw_tx: Arc<Queue<Vec<u8>>>,
    /// Plaintext decoded by wolfSSL and awaiting TUN write.
    pub tun_write: Arc<Queue<Vec<u8>>>,
    /// Ciphertext produced by wolfSSL and awaiting UDP send.
    pub enc_tx: Arc<Queue<EncryptedDatagram>>,
}

impl ClientQueues {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            encrypted_rx: Arc::new(Queue::new(QUEUE_CAPACITY).map_err(io::Error::other)?),
            raw_tx: Arc::new(Queue::new(QUEUE_CAPACITY).map_err(io::Error::other)?),
            tun_write: Arc::new(Queue::new(QUEUE_CAPACITY).map_err(io::Error::other)?),
            enc_tx: Arc::new(Queue::new(QUEUE_CAPACITY).map_err(io::Error::other)?),
        })
    }

    pub fn close(&self) {
        self.encrypted_rx.close();
        self.raw_tx.close();
        self.tun_write.close();
        self.enc_tx.close();
    }
}

#[cfg(test)]
mod tests {
    use super::ClientQueues;

    #[test]
    fn owns_four_independent_bounded_queues() {
        let queues = ClientQueues::new().unwrap();
        assert_eq!(queues.encrypted_rx.capacity(), 512);
        assert_eq!(queues.tun_write.capacity(), 512);
        assert_eq!(queues.raw_tx.capacity(), 512);
        assert_eq!(queues.enc_tx.capacity(), 512);
        queues.encrypted_rx.push(vec![1]).unwrap();
        assert_eq!(queues.encrypted_rx.len(), 1);
        assert!(queues.tun_write.is_empty());
        assert!(queues.raw_tx.is_empty());
        assert!(queues.enc_tx.is_empty());
        queues.close();
        assert!(queues.encrypted_rx.is_closed());
        assert!(queues.tun_write.is_closed());
        assert!(queues.raw_tx.is_closed());
        assert!(queues.enc_tx.is_closed());
    }
}
