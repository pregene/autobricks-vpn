use super::{UdpDatagram, SERVER_QUEUE_CAPACITY};
use autobricks_vpn::base::queue::Queue;
use std::{io, sync::Arc};

pub(super) struct ServerQueues {
    pub(super) udp_rx_queue: Arc<Queue<UdpDatagram>>,
    pub(super) tun_read_queue: Arc<Queue<Vec<u8>>>,
}

impl ServerQueues {
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self {
            udp_rx_queue: new_queue()?,
            tun_read_queue: new_queue()?,
        })
    }

    pub(super) fn close(&self) {
        self.udp_rx_queue.close();
        self.tun_read_queue.close();
    }
}

fn new_queue<T>() -> io::Result<Arc<Queue<T>>> {
    Queue::new(SERVER_QUEUE_CAPACITY)
        .map(Arc::new)
        .map_err(|error| io::Error::other(error.to_string()))
}
