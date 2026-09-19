use super::*;
use autobricks_vpn::base::queue::TryPopError;
pub(super) fn create_stateless_acceptor(
    fd: RawFd,
    config: &Config,
    cookie_secret: &[u8],
) -> io::Result<Dtls> {
    let peer = unsafe { mem::zeroed() };
    let peer_size = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let io = DtlsIo::new(fd, peer, peer_size);
    let mut dtls = Dtls::new(config)?;
    dtls.set_socket(fd)?;
    dtls.set_nonblocking(true);
    dtls.set_io(io)?;
    dtls.set_cookie_secret(cookie_secret)?;
    Ok(dtls)
}

pub(super) struct DecryptContext {
    pub(super) fd: RawFd,
    pub(super) config: Arc<Config>,
    pub(super) cookie_secret: [u8; 32],
    pub(super) stateless_acceptor: Dtls,
    pub(super) sessions: Arc<Mutex<Vec<Session>>>,
    pub(super) bindings: HashMap<Ipv4Addr, String>,
    pub(super) handshake_limiter: IpRateLimiter,
    pub(super) max_clients: usize,
    pub(super) max_pending_handshakes: usize,
    pub(super) verify_client_san_ip: bool,
    pub(super) allow_broadcast: bool,
    pub(super) allow_multicast: bool,
    pub(super) network_address: Ipv4Addr,
    pub(super) network_prefix: u8,
    pub(super) udp_rx_queue: Arc<Queue<UdpDatagram>>,
    pub(super) tun_write_queue: Arc<Queue<Vec<u8>>>,
    pub(super) tun_read_queue: Arc<Queue<Vec<u8>>>,
    pub(super) active: Arc<AtomicBool>,
    pub(super) dtls_progress: Arc<WorkerSignal>,
    pub(super) retry_requested: Arc<AtomicBool>,
    pub(super) control_wake: Arc<control::ControlWake>,
    pub(super) error_receiver: mpsc::Receiver<io::Error>,
    pub(super) reload_receiver: mpsc::Receiver<(HashMap<Ipv4Addr, String>, Dtls)>,
}

pub(super) fn spawn(context: DecryptContext) -> io::Result<thread::JoinHandle<io::Result<()>>> {
    thread::Builder::new()
        .name("avpn-server-decrypt".to_string())
        .spawn(move || {
            let _stop = StopOnDrop(Arc::clone(&context.active));
            run(context)
        })
}

fn run(context: DecryptContext) -> io::Result<()> {
    let DecryptContext {
        fd,
        config,
        cookie_secret,
        mut stateless_acceptor,
        sessions,
        mut bindings,
        mut handshake_limiter,
        max_clients,
        max_pending_handshakes,
        verify_client_san_ip,
        allow_broadcast,
        allow_multicast,
        network_address,
        network_prefix,
        udp_rx_queue,
        tun_write_queue,
        tun_read_queue,
        active,
        dtls_progress,
        retry_requested,
        control_wake,
        error_receiver,
        reload_receiver,
    } = context;
    let mut result = Ok(());
    'server: while RUNNING.load(Ordering::Acquire) && active.load(Ordering::Acquire) {
        let observed = udp_rx_queue.generation();
        handshake_limiter.purge(Instant::now());
        while let Ok((new_bindings, new_acceptor)) = reload_receiver.try_recv() {
            bindings = new_bindings;
            stateless_acceptor = new_acceptor;
        }
        if let Ok(error) = error_receiver.try_recv() {
            result = Err(error);
            break;
        }
        let next = match udp_rx_queue.try_pop() {
            Ok(datagram) => Some(datagram),
            Err(TryPopError::Empty) => {
                udp_rx_queue.wait_for_change(observed);
                None
            }
            Err(TryPopError::Closed) => break,
        };
        if let Some(UdpDatagram {
            peer,
            peer_size,
            packet: incoming,
        }) = next
        {
            let mut packet = [0u8; 2048];
            let mut sessions = sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let index = sessions
                .iter()
                .position(|session| same_peer(&session.peer, &peer));
            let new_session = index.is_none();
            let index = match index {
                Some(index) => index,
                None => {
                    let Some(peer_ip) = peer_ipv4(&peer) else {
                        continue;
                    };
                    if handshake_limiter.check_ban(peer_ip, Instant::now()) {
                        continue;
                    }
                    if let Err(error) =
                        stateless_acceptor.set_incoming_peer(peer, peer_size, incoming.clone())
                    {
                        eprintln!("[server] unable to prepare stateless DTLS accept: {error}");
                        stateless_acceptor =
                            match create_stateless_acceptor(fd, &config, &cookie_secret) {
                                Ok(acceptor) => acceptor,
                                Err(error) => {
                                    result = Err(error);
                                    break 'server;
                                }
                            };
                        continue;
                    }
                    let cookie_valid = match panic_gate("stateless DTLS accept", || {
                        stateless_acceptor.accept_stateless()
                    }) {
                        Ok(valid) => valid,
                        Err(error) => {
                            eprintln!("[server] stateless DTLS accept failed: {error}");
                            stateless_acceptor =
                                match create_stateless_acceptor(fd, &config, &cookie_secret) {
                                    Ok(acceptor) => acceptor,
                                    Err(error) => {
                                        result = Err(error);
                                        break 'server;
                                    }
                                };
                            continue;
                        }
                    };
                    if !cookie_valid {
                        continue;
                    }
                    match handshake_limiter.record_attempt(peer_ip, Instant::now()) {
                        RateLimitDecision::Allowed => {}
                        RateLimitDecision::BannedNow => {
                            eprintln!(
                                "[server] {peer_ip} banned for 10 minutes after 30 handshake attempts"
                            );
                            sessions.retain(|session| {
                                session.established || peer_ipv4(&session.peer) != Some(peer_ip)
                            });
                            continue;
                        }
                        RateLimitDecision::Banned => continue,
                    }
                    let established_count = sessions
                        .iter()
                        .filter(|session| session.established)
                        .count();
                    if established_count >= max_clients {
                        eprintln!("maximum client count ({max_clients}) reached");
                        continue;
                    }
                    let pending_from_ip = sessions
                        .iter()
                        .filter(|session| {
                            !session.established && peer_ipv4(&session.peer) == Some(peer_ip)
                        })
                        .count();
                    if pending_from_ip >= MAX_PENDING_PER_IP {
                        eprintln!("too many pending handshakes from {peer_ip}");
                        continue;
                    }
                    let pending_count = sessions
                        .iter()
                        .filter(|session| !session.established)
                        .count();
                    if pending_count >= max_pending_handshakes {
                        if let Some((oldest, _)) = sessions
                            .iter()
                            .enumerate()
                            .filter(|(_, session)| !session.established)
                            .min_by_key(|(_, session)| session.last_activity)
                        {
                            sessions.swap_remove(oldest);
                        }
                    }
                    eprintln!("[server] DTLS cookie verified; creating session");
                    let replacement = match create_stateless_acceptor(fd, &config, &cookie_secret) {
                        Ok(acceptor) => acceptor,
                        Err(error) => {
                            result = Err(error);
                            break 'server;
                        }
                    };
                    let mut dtls = mem::replace(&mut stateless_acceptor, replacement);
                    let enc_tx_queue = Arc::new(
                        Queue::new(SESSION_TX_QUEUE_CAPACITY)
                            .map_err(|error| io::Error::other(error.to_string()))?,
                    );
                    let raw_tx_queue = Arc::new(
                        Queue::new(SESSION_TX_QUEUE_CAPACITY)
                            .map_err(|error| io::Error::other(error.to_string()))?,
                    );
                    dtls.use_queued_send(Arc::clone(&enc_tx_queue), Arc::clone(&dtls_progress))?;
                    let session = Session {
                        dtls: SynchronizedDtls::new(dtls),
                        peer,
                        peer_size,
                        address: Ipv4Addr::UNSPECIFIED,
                        fingerprint: None,
                        established: false,
                        established_at: None,
                        last_activity: Instant::now(),
                        dtls_deadline: None,
                        bytes_tx: 0,
                        bytes_rx: 0,
                        packets_tx: 0,
                        packets_rx: 0,
                        disconnect_reason: "server_shutdown",
                        enc_tx_queue,
                        raw_tx_queue,
                        control_wake: Arc::clone(&control_wake),
                    };
                    sessions.push(session);
                    control_wake.notify();
                    sessions.len() - 1
                }
            };
            let established_before_processing = sessions
                .iter()
                .filter(|session| session.established)
                .count();
            let session = &mut sessions[index];
            if !new_session {
                if let Err(error) = session.dtls.with(|dtls| dtls.push_incoming(incoming)) {
                    eprintln!("[server] unable to queue client datagram: {error}");
                    sessions.swap_remove(index);
                    continue;
                }
            }
            if !session.established {
                eprintln!("[server] processing DTLS handshake for peer session");
                let handshake_complete = match panic_gate("client DTLS handshake", || {
                    session.dtls.with(|dtls| dtls.handshake())
                }) {
                    Ok(complete) => complete,
                    Err(error) => {
                        eprintln!("[server] DTLS handshake rejected: {error}");
                        sessions.swap_remove(index);
                        continue;
                    }
                };
                if handshake_complete {
                    eprintln!("[server] DTLS handshake complete; reading certificate");
                    let fingerprint = match panic_gate("client certificate", || {
                        session.dtls.with(|dtls| dtls.fingerprint())
                    }) {
                        Ok(fingerprint) => fingerprint,
                        Err(error) => {
                            eprintln!("[server] unable to authenticate peer: {error}");
                            sessions.swap_remove(index);
                            continue;
                        }
                    };
                    let Some((address, _)) = bindings
                        .iter()
                        .find(|(_, expected)| **expected == fingerprint)
                    else {
                        eprintln!("unassigned client certificate {fingerprint}");
                        sessions.swap_remove(index);
                        continue;
                    };
                    if verify_client_san_ip {
                        let san_matches = match panic_gate("client SAN IP verification", || {
                            session
                                .dtls
                                .with(|dtls| dtls.peer_certificate_has_san_ip(*address))
                        }) {
                            Ok(matches) => matches,
                            Err(error) => {
                                eprintln!("[server] unable to verify client SAN IP: {error}");
                                sessions.swap_remove(index);
                                continue;
                            }
                        };
                        if !san_matches {
                            eprintln!(
                                "[server] client certificate SAN IP does not match assigned VPN IP {address}"
                            );
                            sessions.swap_remove(index);
                            continue;
                        }
                    }
                    session.address = *address;
                    session.fingerprint = Some(fingerprint.clone());
                    session.established = true;
                    session.established_at = Some(Instant::now());
                    session.dtls_deadline = None;
                    control_wake.notify();
                    let connected_peer = session.peer;
                    let connected_address = session.address;
                    let replaces_existing = sessions.iter().any(|candidate| {
                        candidate.established
                            && candidate.address == connected_address
                            && !same_peer(&candidate.peer, &connected_peer)
                    });
                    if established_before_processing >= max_clients && !replaces_existing {
                        eprintln!("maximum client count ({max_clients}) reached after handshake");
                        sessions[index].disconnect_reason = "max_clients";
                        sessions.swap_remove(index);
                        continue;
                    }
                    println!("[server] client {fingerprint} connected as {connected_address}");
                    autobricks_vpn::syslog_connection_event(&format!(
                        "client connected vpn_ip={connected_address} fingerprint={fingerprint}"
                    ));
                    let mut duplicate_index = 0;
                    while duplicate_index < sessions.len() {
                        let duplicate = sessions[duplicate_index].established
                            && sessions[duplicate_index].address == connected_address
                            && !same_peer(&sessions[duplicate_index].peer, &connected_peer);
                        if duplicate {
                            eprintln!(
                                "[server] replacing previous session for {connected_address}"
                            );
                            sessions[duplicate_index].disconnect_reason = "replaced";
                            sessions.swap_remove(duplicate_index);
                        } else {
                            duplicate_index += 1;
                        }
                    }
                } else {
                    let timeout = session.dtls.with(|dtls| dtls.current_timeout());
                    session.dtls_deadline = Some(Instant::now() + timeout);
                    control_wake.notify();
                }
            } else {
                let read_result = panic_gate("client DTLS read", || {
                    session.dtls.with(|dtls| dtls.read_status(&mut packet))
                });
                // A pending write may be waiting for this DTLS input to advance.
                dtls_progress.notify();
                retry_requested.store(true, Ordering::Release);
                tun_read_queue.notify_change();
                let count = match read_result {
                    Ok(DtlsIoResult::Complete(count)) => count,
                    Ok(DtlsIoResult::WantRead) => continue,
                    Ok(DtlsIoResult::WantWrite) => continue,
                    Err(error) => {
                        eprintln!("[server] client DTLS read failed: {error}; retaining session until timeout");
                        continue;
                    }
                };
                if is_keepalive_packet(&packet[..count]) {
                    session.last_activity = Instant::now();
                    super::encrypt::queue_session_plain(session, KEEPALIVE_PACKET.to_vec());
                    tun_read_queue.notify_change();
                    continue;
                }
                if let Some((source, destination)) = ipv4_packet_addresses(&packet[..count]) {
                    let broadcast = ipv4_is_broadcast(destination, network_address, network_prefix);
                    let multicast = destination.is_multicast();
                    let destination_allowed = (!broadcast && !multicast)
                        || (broadcast && allow_broadcast)
                        || (multicast && allow_multicast);
                    if source == session.address && destination_allowed {
                        session.bytes_rx = session.bytes_rx.saturating_add(count as u64);
                        session.packets_rx = session.packets_rx.saturating_add(1);
                        match tun_write_queue.push(packet[..count].to_vec()) {
                            Ok(Some(_)) => eprintln!(
                                "[server] TUN write queue overflow; oldest packet dropped"
                            ),
                            Ok(None) => session.last_activity = Instant::now(),
                            Err(_) => break 'server,
                        }
                    }
                }
            }
        }
    }
    if result.is_ok() {
        if let Ok(error) = error_receiver.try_recv() {
            return Err(error);
        }
    }
    result
}
