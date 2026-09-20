use super::{poll, RUNNING};
use autobricks_vpn::{base::queue::Queue, Tun, TunErrorAction};
use std::io;
#[cfg(target_os = "macos")]
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub(super) fn spawn_tun_reader(
    tun_reader_device: Arc<Tun>,
    tun_reader_queue: Arc<Queue<Vec<u8>>>,
    tun_reader_active: Arc<AtomicBool>,
    tun_reader_drops: Arc<AtomicU64>,
    tun_reader_errors: mpsc::Sender<io::Error>,
    #[cfg(target_os = "macos")] server_address: Ipv4Addr,
) -> io::Result<JoinHandle<()>> {
    let tun_reader = thread::Builder::new()
        .name("avpn-server-tun-read".to_string())
        .spawn(move || {
            let _stop = super::StopOnDrop(Arc::clone(&tun_reader_active));
            let mut packet = [0u8; 2048];
            while RUNNING.load(Ordering::Acquire) && tun_reader_active.load(Ordering::Acquire) {
                let mut descriptor = libc::pollfd {
                    fd: tun_reader_device.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if let Err(error) = poll(
                    std::slice::from_mut(&mut descriptor),
                    Duration::from_millis(100),
                ) {
                    tun_reader_active.store(false, Ordering::Release);
                    let _ = tun_reader_errors.send(error);
                    tun_reader_queue.close();
                    return;
                }
                if descriptor.revents & libc::POLLNVAL != 0
                    || descriptor.revents & (libc::POLLERR | libc::POLLHUP) != 0
                {
                    tun_reader_active.store(false, Ordering::Release);
                    let _ = tun_reader_errors.send(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "TUN device reported a permanent poll error",
                    ));
                    tun_reader_queue.close();
                    return;
                }
                if descriptor.revents & libc::POLLIN == 0 {
                    continue;
                }
                match tun_reader_device.read_packet(&mut packet) {
                    Ok(count) if count > 0 => {
                        #[cfg(target_os = "macos")]
                        if let Some(reply) = local_echo_reply(&packet[..count], server_address) {
                            if let Err(error) = tun_reader_device.write_packet(&reply) {
                                eprintln!("[server] local ICMP echo reply failed: {error}");
                            }
                            continue;
                        }
                        match tun_reader_queue.push(packet[..count].to_vec()) {
                            Ok(Some(_)) => {
                                tun_reader_drops.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(None) => {}
                            Err(_) => return,
                        }
                    }
                    Ok(_) => {}
                    Err(error) => match autobricks_vpn::classify_tun_error(&error) {
                        TunErrorAction::Retry | TunErrorAction::DropPacket => {}
                        TunErrorAction::Fatal => {
                            tun_reader_active.store(false, Ordering::Release);
                            let _ = tun_reader_errors.send(error);
                            tun_reader_queue.close();
                            return;
                        }
                    },
                }
            }
        })?;
    Ok(tun_reader)
}

#[cfg(target_os = "macos")]
fn local_echo_reply(packet: &[u8], address: Ipv4Addr) -> Option<Vec<u8>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 1 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < 20 || total_len < header_len + 8 || total_len > packet.len() {
        return None;
    }
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
        return None;
    }
    let self_address = address.octets();
    if packet[12..16] != self_address
        || packet[16..20] != self_address
        || packet[header_len] != 8
        || packet[header_len + 1] != 0
    {
        return None;
    }
    let mut reply = packet[..total_len].to_vec();
    reply[header_len] = 0;
    reply[header_len + 2..header_len + 4].fill(0);
    let checksum = internet_checksum(&reply[header_len..]);
    reply[header_len + 2..header_len + 4].copy_from_slice(&checksum.to_be_bytes());
    Some(reply)
}

#[cfg(target_os = "macos")]
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        sum += u32::from(chunk[0]) << 8 | u32::from(*chunk.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{internet_checksum, local_echo_reply};
    use std::net::Ipv4Addr;

    #[test]
    fn replies_only_to_local_ipv4_echo() {
        let address = Ipv4Addr::new(10, 9, 1, 1);
        let mut packet = vec![0u8; 32];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&32u16.to_be_bytes());
        packet[9] = 1;
        packet[12..16].copy_from_slice(&address.octets());
        packet[16..20].copy_from_slice(&address.octets());
        packet[20] = 8;
        packet[24..28].copy_from_slice(&123u32.to_be_bytes());
        let checksum = internet_checksum(&packet[20..]);
        packet[22..24].copy_from_slice(&checksum.to_be_bytes());
        let reply = local_echo_reply(&packet, address).unwrap();
        assert_eq!(reply[20], 0);
        assert_eq!(internet_checksum(&reply[20..]), 0);
        packet[16] = 2;
        assert!(local_echo_reply(&packet, address).is_none());
    }
}
