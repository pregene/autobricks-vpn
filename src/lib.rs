extern crate self as autobricks_vpn;

use libc::{c_char, c_int, c_uchar, c_uint, c_void};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(windows)]
type RawFd = usize;
use std::process::Command;
use std::ptr;
use std::time::Duration;
use std::time::Instant;

mod client;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod server;

fn run_from_ffi(config_path: *const c_char, runner: impl FnOnce(&str) -> io::Result<()>) -> c_int {
    if config_path.is_null() {
        eprintln!("autobricks-vpn: config path is required");
        return 2;
    }
    let path = unsafe { CStr::from_ptr(config_path) };
    let path = match path.to_str() {
        Ok(path) if !path.is_empty() => path,
        _ => {
            eprintln!("autobricks-vpn: config path must be valid non-empty UTF-8");
            return 2;
        }
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runner(path))) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            eprintln!("autobricks-vpn: {error}");
            1
        }
        Err(_) => {
            eprintln!("autobricks-vpn: runtime panic was contained");
            3
        }
    }
}

/// Run the VPN client with the required configuration path.
#[no_mangle]
pub extern "C" fn autobricks_vpn_client_run(config_path: *const c_char) -> c_int {
    run_from_ffi(config_path, client::run)
}

/// Run the VPN server with the required configuration path.
#[no_mangle]
pub extern "C" fn autobricks_vpn_server_run(config_path: *const c_char) -> c_int {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        run_from_ffi(config_path, server::run)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = config_path;
        eprintln!("autobricks-vpn: server is supported only on Linux and macOS");
        4
    }
}

#[repr(C)]
struct WolfMethod {
    _private: [u8; 0],
}
#[repr(C)]
struct WolfCtx {
    _private: [u8; 0],
}
#[repr(C)]
struct WolfSsl {
    _private: [u8; 0],
}
#[repr(C)]
struct WolfX509 {
    _private: [u8; 0],
}
#[repr(C)]
struct WolfMd {
    _private: [u8; 0],
}

#[cfg(unix)]
pub type SocketAddrStorage = libc::sockaddr_storage;
#[cfg(unix)]
pub type SocketLength = libc::socklen_t;

#[cfg(windows)]
#[repr(C)]
pub struct SocketAddrStorage {
    family: u16,
    data: [u8; 126],
}
#[cfg(windows)]
pub type SocketLength = c_int;

#[cfg(windows)]
#[link(name = "ws2_32")]
extern "system" {
    fn recv(socket: usize, buffer: *mut c_char, length: c_int, flags: c_int) -> c_int;
    fn send(socket: usize, buffer: *const c_char, length: c_int, flags: c_int) -> c_int;
}
type IoCallback =
    Option<unsafe extern "C" fn(*mut WolfSsl, *mut c_char, c_int, *mut c_void) -> c_int>;

const SUCCESS: c_int = 1;
const VERIFY_NONE: c_int = 0;
const VERIFY_PEER: c_int = 1;
const VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 2;
const ERROR_WANT_READ: c_int = 2;
const ERROR_WANT_WRITE: c_int = 3;
const SOCKET_ERROR: c_int = -308;

/// Encrypted application-data marker used to keep a DTLS session and its UDP/NAT mapping alive.
/// Valid tunneled packets start with an IPv4 or IPv6 version nibble, so this cannot be a TUN packet.
pub const KEEPALIVE_PACKET: &[u8] = &[0];
pub const MIN_TUN_MTU: u16 = 576;
pub const MAX_TUN_MTU: u16 = 1500;

pub fn is_keepalive_packet(packet: &[u8]) -> bool {
    packet == KEEPALIVE_PACKET
}

pub fn validate_datagram_write(written: usize, expected: usize) -> io::Result<()> {
    if written == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("partial datagram write: {written}/{expected} bytes"),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitDecision {
    Allowed,
    BannedNow,
    Banned,
}

struct IpAttemptState {
    attempts: VecDeque<Instant>,
    banned_until: Option<Instant>,
}

pub struct IpRateLimiter {
    states: HashMap<Ipv4Addr, IpAttemptState>,
    limit: usize,
    window: Duration,
    ban_duration: Duration,
}

impl IpRateLimiter {
    pub fn new(limit: usize, window: Duration, ban_duration: Duration) -> Self {
        Self {
            states: HashMap::new(),
            limit: limit.max(1),
            window,
            ban_duration,
        }
    }

    pub fn check_ban(&mut self, address: Ipv4Addr, now: Instant) -> bool {
        let Some(state) = self.states.get_mut(&address) else {
            return false;
        };
        if state.banned_until.is_some_and(|deadline| deadline > now) {
            return true;
        }
        state.banned_until = None;
        while state
            .attempts
            .front()
            .is_some_and(|attempt| now.saturating_duration_since(*attempt) >= self.window)
        {
            state.attempts.pop_front();
        }
        false
    }

    pub fn record_attempt(&mut self, address: Ipv4Addr, now: Instant) -> RateLimitDecision {
        if self.check_ban(address, now) {
            return RateLimitDecision::Banned;
        }
        let state = self
            .states
            .entry(address)
            .or_insert_with(|| IpAttemptState {
                attempts: VecDeque::new(),
                banned_until: None,
            });
        state.attempts.push_back(now);
        if state.attempts.len() >= self.limit {
            state.attempts.clear();
            state.banned_until = Some(now + self.ban_duration);
            RateLimitDecision::BannedNow
        } else {
            RateLimitDecision::Allowed
        }
    }

    pub fn purge(&mut self, now: Instant) {
        let window = self.window;
        self.states.retain(|_, state| {
            while state
                .attempts
                .front()
                .is_some_and(|attempt| now.saturating_duration_since(*attempt) >= window)
            {
                state.attempts.pop_front();
            }
            state.banned_until.is_some_and(|deadline| deadline > now) || !state.attempts.is_empty()
        });
    }
}

#[cfg(unix)]
pub fn syslog_connection_event(message: &str) {
    if let Ok(message) = CString::new(message) {
        unsafe {
            libc::openlog(c"autobricks-vpn".as_ptr(), libc::LOG_PID, libc::LOG_LOCAL0);
            libc::syslog(libc::LOG_INFO, c"%s".as_ptr(), message.as_ptr());
        }
    }
}

#[cfg(not(unix))]
pub fn syslog_connection_event(_message: &str) {}

pub fn validate_mtu(mtu: u16) -> io::Result<()> {
    if (MIN_TUN_MTU..=MAX_TUN_MTU).contains(&mtu) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("MTU must be between {MIN_TUN_MTU} and {MAX_TUN_MTU}"),
        ))
    }
}

pub fn validate_private_key_file(path: &str) -> io::Result<()> {
    let metadata = fs::metadata(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("unable to inspect private key {path}: {error}"),
        )
    })?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("private key is not a regular file: {path}"),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "private key permissions are too open ({:03o}); use chmod 600 {path}",
                    mode & 0o777
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunErrorAction {
    Retry,
    DropPacket,
    Fatal,
}

#[cfg(unix)]
pub fn classify_tun_error(error: &io::Error) -> TunErrorAction {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) {
        TunErrorAction::Retry
    } else if error.raw_os_error() == Some(libc::ENOBUFS) {
        TunErrorAction::DropPacket
    } else {
        // EBADF and ENODEV are permanent. Unknown TUN errors are also fatal so a
        // broken device cannot turn into a tight retry/log loop.
        TunErrorAction::Fatal
    }
}

/// Converts an unwinding Rust panic into an I/O error at a process-boundary operation.
/// This does not catch aborts, segmentation faults, or undefined behavior in foreign code.
pub fn panic_gate<T>(label: &str, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown panic");
            Err(io::Error::other(format!("{label} panicked: {message}")))
        }
    }
}

#[cfg_attr(not(test), link(name = "wolfssl"))]
extern "C" {
    fn wolfSSL_Init() -> c_int;
    fn wolfSSL_CTX_new(method: *mut WolfMethod) -> *mut WolfCtx;
    fn wolfSSL_CTX_free(ctx: *mut WolfCtx);
    fn wolfSSL_new(ctx: *mut WolfCtx) -> *mut WolfSsl;
    fn wolfSSL_free(ssl: *mut WolfSsl);
    fn wolfSSL_CTX_use_certificate_file(
        ctx: *mut WolfCtx,
        file: *const c_char,
        kind: c_int,
    ) -> c_int;
    fn wolfSSL_CTX_use_PrivateKey_file(
        ctx: *mut WolfCtx,
        file: *const c_char,
        kind: c_int,
    ) -> c_int;
    fn wolfSSL_CTX_load_verify_locations(
        ctx: *mut WolfCtx,
        file: *const c_char,
        path: *const c_char,
    ) -> c_int;
    fn wolfSSL_CTX_set_verify(ctx: *mut WolfCtx, mode: c_int, callback: *mut c_void);
    fn wolfSSL_CTX_EnableOCSP(ctx: *mut WolfCtx, options: c_int) -> c_int;
    fn wolfSSL_CTX_SetOCSP_OverrideURL(ctx: *mut WolfCtx, url: *const c_char) -> c_int;
    fn wolfSSL_CTX_EnableCRL(ctx: *mut WolfCtx, options: c_int) -> c_int;
    fn wolfSSL_CTX_LoadCRL(
        ctx: *mut WolfCtx,
        path: *const c_char,
        kind: c_int,
        monitor: c_int,
    ) -> c_int;
    #[cfg(target_os = "macos")]
    fn wolfSSL_CTX_dtls_set_mtu(ctx: *mut WolfCtx, mtu: u16) -> c_int;
    #[cfg(feature = "dtls13")]
    fn wolfDTLSv1_3_server_method() -> *mut WolfMethod;
    #[cfg(feature = "dtls13")]
    fn wolfDTLSv1_3_client_method() -> *mut WolfMethod;
    fn wolfDTLSv1_2_server_method() -> *mut WolfMethod;
    fn wolfDTLSv1_2_client_method() -> *mut WolfMethod;
    fn wolfSSL_set_fd(ssl: *mut WolfSsl, fd: c_int) -> c_int;
    fn wolfSSL_dtls_set_using_nonblock(ssl: *mut WolfSsl, nonblock: c_int);
    fn wolfSSL_SSLSetIORecv(ssl: *mut WolfSsl, callback: IoCallback);
    fn wolfSSL_SSLSetIOSend(ssl: *mut WolfSsl, callback: IoCallback);
    fn wolfSSL_SetIOReadCtx(ssl: *mut WolfSsl, context: *mut c_void);
    fn wolfSSL_SetIOWriteCtx(ssl: *mut WolfSsl, context: *mut c_void);
    fn wolfSSL_get_fd(ssl: *const WolfSsl) -> c_int;
    fn wolfSSL_dtls_set_peer(ssl: *mut WolfSsl, peer: *mut c_void, size: c_uint) -> c_int;
    fn wolfSSL_dtls_get_current_timeout(ssl: *mut WolfSsl) -> c_int;
    fn wolfSSL_dtls_got_timeout(ssl: *mut WolfSsl) -> c_int;
    fn wolfDTLS_accept_stateless(ssl: *mut WolfSsl) -> c_int;
    #[cfg(not(feature = "dtls13"))]
    fn wolfSSL_DTLS_SetCookieSecret(
        ssl: *mut WolfSsl,
        secret: *const c_uchar,
        secret_size: c_uint,
    ) -> c_int;
    #[cfg(feature = "dtls13")]
    fn wolfSSL_send_hrr_cookie(
        ssl: *mut WolfSsl,
        secret: *const c_uchar,
        secret_size: c_uint,
    ) -> c_int;
    fn wolfSSL_check_ip_address(ssl: *mut WolfSsl, ipaddr: *const c_char) -> c_int;
    fn wolfSSL_accept(ssl: *mut WolfSsl) -> c_int;
    fn wolfSSL_connect(ssl: *mut WolfSsl) -> c_int;
    fn wolfSSL_read(ssl: *mut WolfSsl, buffer: *mut c_void, size: c_int) -> c_int;
    fn wolfSSL_write(ssl: *mut WolfSsl, buffer: *const c_void, size: c_int) -> c_int;
    fn wolfSSL_get_error(ssl: *mut WolfSsl, ret: c_int) -> c_int;
    fn wolfSSL_get_peer_certificate(ssl: *mut WolfSsl) -> *mut WolfX509;
    fn wolfSSL_X509_digest(
        cert: *const WolfX509,
        md: *const WolfMd,
        out: *mut c_uchar,
        len: *mut c_uint,
    ) -> c_int;
    fn wolfSSL_X509_free(cert: *mut WolfX509);
    fn wolfSSL_X509_get_next_altname(cert: *mut WolfX509) -> *mut c_char;
    fn wolfSSL_EVP_sha256() -> *const WolfMd;
}

pub struct Config {
    pub server: bool,
    pub certificate_file: String,
    pub private_key_file: String,
    pub ca_file: Option<String>,
    pub crl_file: Option<String>,
    pub ocsp_enabled: bool,
    pub ocsp_url: Option<String>,
    pub mtu: u16,
}

pub struct Dtls {
    ctx: *mut WolfCtx,
    ssl: *mut WolfSsl,
    io: Option<Box<DtlsIo>>,
    server: bool,
    nonblocking: bool,
}

impl Dtls {
    pub fn new(config: &Config) -> io::Result<Self> {
        validate_mtu(config.mtu)?;
        validate_private_key_file(&config.private_key_file)?;
        let cert = CString::new(config.certificate_file.as_str()).map_err(invalid_input)?;
        let key = CString::new(config.private_key_file.as_str()).map_err(invalid_input)?;
        let ca = config
            .ca_file
            .as_ref()
            .map(|v| CString::new(v.as_str()).map_err(invalid_input))
            .transpose()?;
        let crl = config
            .crl_file
            .as_ref()
            .map(|value| CString::new(value.as_str()).map_err(invalid_input))
            .transpose()?;
        let ocsp_url = config
            .ocsp_url
            .as_ref()
            .map(|value| CString::new(value.as_str()).map_err(invalid_input))
            .transpose()?;
        unsafe {
            if wolfSSL_Init() != SUCCESS {
                return Err(io::Error::other("wolfSSL_Init failed"));
            }
            let method = if config.server {
                #[cfg(feature = "dtls13")]
                {
                    wolfDTLSv1_3_server_method()
                }
                #[cfg(not(feature = "dtls13"))]
                {
                    wolfDTLSv1_2_server_method()
                }
            } else {
                #[cfg(feature = "dtls13")]
                {
                    wolfDTLSv1_3_client_method()
                }
                #[cfg(not(feature = "dtls13"))]
                {
                    wolfDTLSv1_2_client_method()
                }
            };
            let ctx = wolfSSL_CTX_new(method);
            if ctx.is_null() {
                return Err(io::Error::other("wolfSSL_CTX_new failed"));
            }
            if wolfSSL_CTX_use_certificate_file(ctx, cert.as_ptr(), 1) != SUCCESS
                || wolfSSL_CTX_use_PrivateKey_file(ctx, key.as_ptr(), 1) != SUCCESS
            {
                wolfSSL_CTX_free(ctx);
                return Err(io::Error::other(
                    "unable to load certificate or private key",
                ));
            }
            if let Some(ca) = ca {
                if wolfSSL_CTX_load_verify_locations(ctx, ca.as_ptr(), ptr::null()) != SUCCESS {
                    wolfSSL_CTX_free(ctx);
                    return Err(io::Error::other("unable to load CA file"));
                }
                wolfSSL_CTX_set_verify(
                    ctx,
                    VERIFY_PEER
                        | if config.server {
                            VERIFY_FAIL_IF_NO_PEER_CERT
                        } else {
                            0
                        },
                    ptr::null_mut(),
                );
            } else {
                wolfSSL_CTX_set_verify(ctx, VERIFY_NONE, ptr::null_mut());
            }
            if let Some(crl) = crl {
                if wolfSSL_CTX_EnableCRL(ctx, 0) != SUCCESS
                    || wolfSSL_CTX_LoadCRL(ctx, crl.as_ptr(), 1, 0) != SUCCESS
                {
                    wolfSSL_CTX_free(ctx);
                    return Err(io::Error::other(
                        "unable to enable CRL verification; wolfSSL must include CRL support",
                    ));
                }
            }
            if config.ocsp_enabled || ocsp_url.is_some() {
                const OCSP_URL_OVERRIDE: c_int = 1;
                let options = if let Some(ocsp_url) = ocsp_url {
                    if wolfSSL_CTX_SetOCSP_OverrideURL(ctx, ocsp_url.as_ptr()) != SUCCESS {
                        wolfSSL_CTX_free(ctx);
                        return Err(io::Error::other("unable to set OCSP override URL"));
                    }
                    OCSP_URL_OVERRIDE
                } else {
                    0
                };
                if wolfSSL_CTX_EnableOCSP(ctx, options) != SUCCESS {
                    wolfSSL_CTX_free(ctx);
                    return Err(io::Error::other(
                        "unable to enable OCSP verification; wolfSSL must include OCSP support",
                    ));
                }
            }
            #[cfg(target_os = "macos")]
            if config.mtu > 0 {
                wolfSSL_CTX_dtls_set_mtu(ctx, config.mtu);
            }
            Ok(Self {
                ctx,
                ssl: ptr::null_mut(),
                io: None,
                server: config.server,
                nonblocking: false,
            })
        }
    }

    pub fn set_socket(&mut self, fd: RawFd) -> io::Result<()> {
        unsafe {
            let ssl = wolfSSL_new(self.ctx);
            if ssl.is_null() {
                return Err(io::Error::other("wolfSSL_new failed"));
            }
            if wolfSSL_set_fd(ssl, fd as c_int) != SUCCESS {
                wolfSSL_free(ssl);
                return Err(io::Error::other("wolfSSL_set_fd failed"));
            }
            if !self.ssl.is_null() {
                wolfSSL_free(self.ssl);
            }
            self.io = None;
            self.ssl = ssl;
        }
        Ok(())
    }

    pub fn set_nonblocking(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
        unsafe {
            wolfSSL_dtls_set_using_nonblock(self.ssl, if nonblocking { 1 } else { 0 });
        }
    }

    pub fn set_peer(&mut self, peer: &SocketAddrStorage, peer_size: usize) -> io::Result<()> {
        unsafe {
            check(wolfSSL_dtls_set_peer(
                self.ssl,
                peer as *const _ as *mut c_void,
                peer_size as c_uint,
            ))
        }
    }

    pub fn verify_peer_ip(&mut self, expected: Ipv4Addr) -> io::Result<()> {
        if self.ssl.is_null() {
            return Err(io::Error::other("DTLS socket is not initialized"));
        }
        let expected = CString::new(expected.to_string()).map_err(invalid_input)?;
        let result = unsafe { wolfSSL_check_ip_address(self.ssl, expected.as_ptr()) };
        if result == SUCCESS {
            Ok(())
        } else {
            Err(io::Error::other(
                "unable to enable peer certificate SAN IP verification",
            ))
        }
    }

    pub fn set_io(&mut self, io: DtlsIo) -> io::Result<()> {
        if self.ssl.is_null() {
            return Err(io::Error::other("DTLS socket is not initialized"));
        }
        let mut io = Box::new(io);
        let context = io.as_mut() as *mut DtlsIo as *mut c_void;
        unsafe {
            wolfSSL_SSLSetIORecv(self.ssl, Some(dtls_recv));
            wolfSSL_SSLSetIOSend(self.ssl, Some(dtls_send));
            wolfSSL_SetIOReadCtx(self.ssl, context);
            wolfSSL_SetIOWriteCtx(self.ssl, context);
        }
        self.io = Some(io);
        Ok(())
    }

    pub fn push_incoming(&mut self, packet: Vec<u8>) -> io::Result<()> {
        let io = self
            .io
            .as_mut()
            .ok_or_else(|| io::Error::other("DTLS I/O is not initialized"))?;
        if io.direct_receive {
            return Err(io::Error::other(
                "cannot queue packets for a connected DTLS socket",
            ));
        }
        io.incoming.push_back(packet);
        Ok(())
    }

    pub fn set_incoming_peer(
        &mut self,
        peer: SocketAddrStorage,
        peer_size: SocketLength,
        packet: Vec<u8>,
    ) -> io::Result<()> {
        self.set_peer(&peer, peer_size as usize)?;
        let io = self
            .io
            .as_mut()
            .ok_or_else(|| io::Error::other("DTLS I/O is not initialized"))?;
        if io.direct_receive {
            return Err(io::Error::other(
                "cannot queue packets for a connected DTLS socket",
            ));
        }
        io.peer = peer;
        io.peer_size = peer_size;
        io.incoming.clear();
        io.incoming.push_back(packet);
        Ok(())
    }

    pub fn accept_stateless(&mut self) -> io::Result<bool> {
        if self.ssl.is_null() {
            return Err(io::Error::other("DTLS socket is not initialized"));
        }
        if !self.server {
            return Err(io::Error::other(
                "stateless DTLS accept is only available to servers",
            ));
        }
        let result = unsafe { wolfDTLS_accept_stateless(self.ssl) };
        match result {
            SUCCESS => Ok(true),
            0 => Ok(false),
            _ => {
                let error = unsafe { wolfSSL_get_error(self.ssl, result) };
                Err(io::Error::other(format!(
                    "stateless DTLS cookie validation failed: {error}"
                )))
            }
        }
    }

    pub fn set_cookie_secret(&mut self, secret: &[u8]) -> io::Result<()> {
        if self.ssl.is_null() {
            return Err(io::Error::other("DTLS socket is not initialized"));
        }
        if !self.server {
            return Err(io::Error::other(
                "a DTLS cookie secret can only be set on a server",
            ));
        }
        let secret_size = c_uint::try_from(secret.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "cookie secret is too long")
        })?;
        if secret_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cookie secret must not be empty",
            ));
        }
        #[cfg(feature = "dtls13")]
        let result = unsafe { wolfSSL_send_hrr_cookie(self.ssl, secret.as_ptr(), secret_size) };
        #[cfg(not(feature = "dtls13"))]
        let result =
            unsafe { wolfSSL_DTLS_SetCookieSecret(self.ssl, secret.as_ptr(), secret_size) };
        #[cfg(feature = "dtls13")]
        let success = result == SUCCESS;
        #[cfg(not(feature = "dtls13"))]
        let success = result == 0;
        if success {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "unable to set DTLS cookie secret: {result}"
            )))
        }
    }

    pub fn handshake(&mut self) -> io::Result<bool> {
        unsafe {
            let ret = if self.server {
                wolfSSL_accept(self.ssl)
            } else {
                wolfSSL_connect(self.ssl)
            };
            if ret == SUCCESS {
                return Ok(true);
            }
            let error = wolfSSL_get_error(self.ssl, ret);
            if error == ERROR_WANT_READ
                || error == ERROR_WANT_WRITE
                || (self.nonblocking && error == SOCKET_ERROR)
            {
                return Ok(false);
            }
            Err(io::Error::other(format!("DTLS handshake failed: {error}")))
        }
    }

    pub fn current_timeout(&self) -> Duration {
        let seconds = unsafe { wolfSSL_dtls_get_current_timeout(self.ssl) };
        Duration::from_secs(seconds.max(1) as u64)
    }

    pub fn handle_timeout(&mut self) -> io::Result<()> {
        let result = unsafe { wolfSSL_dtls_got_timeout(self.ssl) };
        if result == SUCCESS {
            Ok(())
        } else {
            let error = unsafe { wolfSSL_get_error(self.ssl, result) };
            Err(io::Error::other(format!(
                "DTLS retransmission failed: {error}"
            )))
        }
    }

    pub fn accept(&mut self) -> io::Result<bool> {
        unsafe { self.handshake_server() }
    }

    unsafe fn handshake_server(&mut self) -> io::Result<bool> {
        let ret = wolfSSL_accept(self.ssl);
        if ret == SUCCESS {
            return Ok(true);
        }
        let error = wolfSSL_get_error(self.ssl, ret);
        if error == ERROR_WANT_READ || error == ERROR_WANT_WRITE || error == SOCKET_ERROR {
            return Ok(false);
        }
        Err(io::Error::other(format!("DTLS handshake failed: {error}")))
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            io_result(
                wolfSSL_read(
                    self.ssl,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len() as c_int,
                ),
                self.ssl,
            )
        }
    }
    pub fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        unsafe {
            io_result(
                wolfSSL_write(
                    self.ssl,
                    buffer.as_ptr() as *const c_void,
                    buffer.len() as c_int,
                ),
                self.ssl,
            )
        }
    }
    pub fn fingerprint(&self) -> io::Result<String> {
        unsafe {
            let cert = wolfSSL_get_peer_certificate(self.ssl);
            if cert.is_null() {
                return Err(io::Error::other("peer certificate unavailable"));
            }
            let mut digest = [0u8; 32];
            let mut length = digest.len() as c_uint;
            let result =
                wolfSSL_X509_digest(cert, wolfSSL_EVP_sha256(), digest.as_mut_ptr(), &mut length);
            wolfSSL_X509_free(cert);
            if result != SUCCESS || length != 32 {
                return Err(io::Error::other(
                    "unable to calculate certificate fingerprint",
                ));
            }
            Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
        }
    }
    pub fn peer_certificate_has_san_ip(&self, expected: Ipv4Addr) -> io::Result<bool> {
        unsafe {
            let cert = wolfSSL_get_peer_certificate(self.ssl);
            if cert.is_null() {
                return Err(io::Error::other("peer certificate unavailable"));
            }
            let mut matched = false;
            loop {
                let name = wolfSSL_X509_get_next_altname(cert);
                if name.is_null() {
                    break;
                }
                if CStr::from_ptr(name)
                    .to_str()
                    .ok()
                    .and_then(|value| value.parse::<Ipv4Addr>().ok())
                    == Some(expected)
                {
                    matched = true;
                    break;
                }
            }
            wolfSSL_X509_free(cert);
            Ok(matched)
        }
    }
    pub fn fd(&self) -> RawFd {
        unsafe { wolfSSL_get_fd(self.ssl) as RawFd }
    }
}

impl Drop for Dtls {
    fn drop(&mut self) {
        unsafe {
            if !self.ssl.is_null() {
                wolfSSL_free(self.ssl);
            }
            if !self.ctx.is_null() {
                wolfSSL_CTX_free(self.ctx);
            }
        }
    }
}

fn invalid_input(error: std::ffi::NulError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}
unsafe fn check(value: c_int) -> io::Result<()> {
    if value == SUCCESS {
        Ok(())
    } else {
        Err(io::Error::other("wolfSSL peer setup failed"))
    }
}
unsafe fn io_result(value: c_int, ssl: *mut WolfSsl) -> io::Result<usize> {
    if value >= 0 {
        Ok(value as usize)
    } else {
        let error = wolfSSL_get_error(ssl, value);
        if error == ERROR_WANT_READ || error == ERROR_WANT_WRITE || error == SOCKET_ERROR {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        } else {
            Err(io::Error::other(format!("wolfSSL I/O failed: {error}")))
        }
    }
}

pub struct DtlsIo {
    fd: RawFd,
    peer: SocketAddrStorage,
    peer_size: SocketLength,
    direct_receive: bool,
    incoming: VecDeque<Vec<u8>>,
}

impl DtlsIo {
    pub fn new(fd: RawFd, peer: SocketAddrStorage, peer_size: SocketLength) -> Self {
        Self {
            fd,
            peer,
            peer_size,
            direct_receive: false,
            incoming: VecDeque::new(),
        }
    }

    pub fn new_client(fd: RawFd, peer: SocketAddrStorage, peer_size: SocketLength) -> Self {
        Self {
            fd,
            peer,
            peer_size,
            direct_receive: true,
            incoming: VecDeque::new(),
        }
    }

    pub fn push(&mut self, packet: Vec<u8>) {
        self.incoming.push_back(packet);
    }
}

unsafe extern "C" fn dtls_recv(
    _ssl: *mut WolfSsl,
    buffer: *mut c_char,
    size: c_int,
    context: *mut c_void,
) -> c_int {
    let io = &mut *(context as *mut DtlsIo);
    if io.direct_receive {
        #[cfg(unix)]
        let result = libc::recvfrom(
            io.fd,
            buffer as *mut c_void,
            size as usize,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        #[cfg(windows)]
        let result = recv(io.fd, buffer, size, 0) as isize;
        return if result < 0 { -2 } else { result as c_int };
    }
    let Some(packet) = io.incoming.pop_front() else {
        return -2;
    };
    if packet.len() > size as usize {
        return -1;
    }
    ptr::copy_nonoverlapping(packet.as_ptr(), buffer as *mut u8, packet.len());
    packet.len() as c_int
}

unsafe extern "C" fn dtls_send(
    _ssl: *mut WolfSsl,
    buffer: *mut c_char,
    size: c_int,
    context: *mut c_void,
) -> c_int {
    let io = &*(context as *const DtlsIo);
    let result = if io.direct_receive {
        #[cfg(unix)]
        {
            libc::send(io.fd, buffer as *const c_void, size as usize, 0)
        }
        #[cfg(windows)]
        {
            send(io.fd, buffer, size, 0) as isize
        }
    } else {
        #[cfg(unix)]
        {
            libc::sendto(
                io.fd,
                buffer as *const c_void,
                size as usize,
                0,
                &io.peer as *const _ as *const libc::sockaddr,
                io.peer_size,
            )
        }
        #[cfg(windows)]
        {
            -1
        }
    };
    if result < 0 {
        -1
    } else {
        result as c_int
    }
}

pub struct Tun {
    fd: RawFd,
    macos_header: bool,
    name: String,
    #[cfg(windows)]
    session: std::sync::Arc<wintun::Session>,
}

pub struct ForwardingGuard {
    #[cfg(target_os = "linux")]
    interface: String,
    #[cfg(target_os = "linux")]
    network: String,
}

impl ForwardingGuard {
    pub fn enable(interface: &str, network: &str) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            run_command("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
            let mut guard = Self {
                interface: interface.to_owned(),
                network: network.to_owned(),
            };
            // Remove only our specifically tagged stale/duplicate rule.
            guard.remove_rule();
            run_command(
                "iptables",
                &[
                    "-I",
                    "FORWARD",
                    "1",
                    "-i",
                    interface,
                    "-o",
                    interface,
                    "-s",
                    network,
                    "-d",
                    network,
                    "-m",
                    "comment",
                    "--comment",
                    "autobricks-vpn-client-forward",
                    "-j",
                    "ACCEPT",
                ],
            )?;
            Ok(guard)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (interface, network);
            Ok(Self {})
        }
    }

    #[cfg(target_os = "linux")]
    fn remove_rule(&mut self) {
        use std::process::Stdio;

        loop {
            let rule_exists = Command::new("iptables")
                .args([
                    "-C",
                    "FORWARD",
                    "-i",
                    &self.interface,
                    "-o",
                    &self.interface,
                    "-s",
                    &self.network,
                    "-d",
                    &self.network,
                    "-m",
                    "comment",
                    "--comment",
                    "autobricks-vpn-client-forward",
                    "-j",
                    "ACCEPT",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
            if !rule_exists {
                break;
            }
            let removed = Command::new("iptables")
                .args([
                    "-D",
                    "FORWARD",
                    "-i",
                    &self.interface,
                    "-o",
                    &self.interface,
                    "-s",
                    &self.network,
                    "-d",
                    &self.network,
                    "-m",
                    "comment",
                    "--comment",
                    "autobricks-vpn-client-forward",
                    "-j",
                    "ACCEPT",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
            if !removed {
                break;
            }
        }
    }
}

impl Drop for ForwardingGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        self.remove_rule();
        // ip_forward is shared system state and is intentionally not restored.
    }
}

pub struct DnsGuard {
    interface: String,
    #[cfg(target_os = "macos")]
    services: Vec<(String, Vec<String>)>,
    #[cfg(windows)]
    nrpt_comment: String,
}

impl DnsGuard {
    pub fn apply(interface: &str, server: Ipv4Addr) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            run_command("resolvectl", &["dns", interface, &server.to_string()])?;
            if let Err(error) = run_command("resolvectl", &["domain", interface, "~."]) {
                let _ = Command::new("resolvectl")
                    .args(["revert", interface])
                    .status();
                return Err(error);
            }
            Ok(Self {
                interface: interface.to_owned(),
            })
        }
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("networksetup")
                .arg("-listallnetworkservices")
                .output()?;
            if !output.status.success() {
                return Err(io::Error::other("unable to list macOS network services"));
            }
            let services = String::from_utf8_lossy(&output.stdout)
                .lines()
                .skip(1)
                .filter(|service| !service.is_empty() && !service.starts_with('*'))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let mut guard = Self {
                interface: interface.to_owned(),
                services: Vec::new(),
            };
            for service in services {
                let old = Command::new("networksetup")
                    .args(["-getdnsservers", &service])
                    .output()?;
                if !old.status.success() {
                    return Err(io::Error::other(format!(
                        "unable to read DNS settings for {service}"
                    )));
                }
                let text = String::from_utf8_lossy(&old.stdout);
                let previous = if text.contains("aren't any DNS Servers") {
                    Vec::new()
                } else {
                    text.lines().map(str::to_owned).collect()
                };
                guard.services.push((service.clone(), previous));
                run_command(
                    "networksetup",
                    &["-setdnsservers", &service, &server.to_string()],
                )?;
            }
            Ok(guard)
        }
        #[cfg(windows)]
        {
            let nrpt_comment = format!("autobricks-vpn-{}", std::process::id());
            run_command(
                "powershell.exe",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "Add-DnsClientNrptRule -Namespace '.' -NameServers '{}' -Comment '{}'",
                        server, nrpt_comment
                    ),
                ],
            )?;
            Ok(Self {
                interface: interface.to_owned(),
                nrpt_comment,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = (interface, server);
            Err(io::Error::other("DNS configuration is unsupported"))
        }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("resolvectl")
                .args(["revert", &self.interface])
                .status();
        }
        #[cfg(target_os = "macos")]
        for (service, servers) in self.services.iter().rev() {
            let mut command = Command::new("networksetup");
            command.args(["-setdnsservers", service]);
            if servers.is_empty() {
                command.arg("Empty");
            } else {
                command.args(servers);
            }
            let _ = command.status();
        }
        #[cfg(windows)]
        {
            let _ = Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "Get-DnsClientNrptRule | Where-Object Comment -EQ '{}' | Remove-DnsClientNrptRule -Force",
                        self.nrpt_comment
                    ),
                ])
                .status();
        }
    }
}

impl Tun {
    pub fn open(requested_name: &str) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            Self::open_utun(requested_name)
        }
        #[cfg(target_os = "linux")]
        {
            Self::open_linux(requested_name)
        }
        #[cfg(windows)]
        {
            Self::open_windows(requested_name)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            let _ = requested_name;
            Err(io::Error::other("TUN is unsupported on this platform"))
        }
    }

    #[cfg(target_os = "macos")]
    #[allow(clippy::manual_c_str_literals)]
    fn open_utun(_requested_name: &str) -> io::Result<Self> {
        const CTL_NAME: &[u8] = b"com.apple.net.utun_control\0";
        #[repr(C)]
        struct CtlInfo {
            ctl_id: u32,
            ctl_name: [u8; 96],
        }
        #[repr(C)]
        struct SockAddrCtl {
            sc_len: u8,
            sc_family: u8,
            ss_sysaddr: u16,
            sc_id: u32,
            sc_unit: u32,
            sc_reserved: [u32; 5],
        }
        let mut info = CtlInfo {
            ctl_name: [0; 96],
            ctl_id: 0,
        };
        info.ctl_name[..CTL_NAME.len()].copy_from_slice(CTL_NAME);
        unsafe {
            let fd = libc::socket(32, libc::SOCK_DGRAM, 2);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(fd, 0xc0644e03u64, &mut info) < 0 {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }
            let address = SockAddrCtl {
                sc_len: mem::size_of::<SockAddrCtl>() as u8,
                sc_family: 32,
                ss_sysaddr: 2,
                sc_id: info.ctl_id,
                sc_unit: 0,
                sc_reserved: [0; 5],
            };
            if libc::connect(
                fd,
                &address as *const _ as *const libc::sockaddr,
                mem::size_of::<SockAddrCtl>() as u32,
            ) < 0
            {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }
            let mut name = [0u8; 16];
            let mut name_len = name.len() as libc::socklen_t;
            if libc::getsockopt(fd, 2, 2, name.as_mut_ptr() as *mut c_void, &mut name_len) < 0 {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }
            let name = CStr::from_bytes_until_nul(&name)
                .unwrap_or(CStr::from_bytes_with_nul(b"utun\0").unwrap())
                .to_string_lossy()
                .into_owned();
            Ok(Self {
                fd,
                macos_header: true,
                name,
            })
        }
    }

    #[cfg(target_os = "linux")]
    fn open_linux(requested_name: &str) -> io::Result<Self> {
        #[repr(C)]
        struct IfReq {
            name: [u8; libc::IFNAMSIZ],
            flags: libc::c_short,
            padding: [u8; 22],
        }
        const TUNSETIFF: libc::c_ulong = 0x400454ca;
        const IFF_TUN: libc::c_short = 0x0001;
        const IFF_NO_PI: libc::c_short = 0x1000;
        let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const c_char, libc::O_RDWR) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut request = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            padding: [0; 22],
        };
        for (slot, byte) in request.name.iter_mut().zip(requested_name.bytes()) {
            *slot = byte;
        }
        if unsafe { libc::ioctl(fd, TUNSETIFF, &mut request) } < 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error);
        }
        let name = String::from_utf8_lossy(&request.name)
            .trim_end_matches('\0')
            .to_string();
        Ok(Self {
            fd,
            macos_header: false,
            name,
        })
    }

    #[cfg(windows)]
    fn open_windows(requested_name: &str) -> io::Result<Self> {
        let dll = std::env::var("WINTUN_DLL").unwrap_or_else(|_| "wintun.dll".to_string());
        let wintun = unsafe { wintun::load_from_path(dll) }
            .map_err(|error| io::Error::other(format!("loading Wintun: {error}")))?;
        let adapter = wintun::Adapter::open(&wintun, requested_name)
            .or_else(|_| wintun::Adapter::create(&wintun, requested_name, "autobricks-vpn", None))
            .map_err(|error| io::Error::other(format!("opening Wintun adapter: {error}")))?;
        let session = std::sync::Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|error| io::Error::other(format!("starting Wintun session: {error}")))?,
        );
        Ok(Self {
            fd: 0,
            macos_header: false,
            name: requested_name.to_string(),
            session,
        })
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn configure_mtu(&self, mtu: u16) -> io::Result<()> {
        validate_mtu(mtu)?;
        #[cfg(target_os = "macos")]
        {
            run_command("ifconfig", &[&self.name, "mtu", &mtu.to_string()])
        }
        #[cfg(target_os = "linux")]
        {
            run_command(
                "ip",
                &["link", "set", "dev", &self.name, "mtu", &mtu.to_string()],
            )
        }
        #[cfg(windows)]
        {
            run_command(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "subinterface",
                    &self.name,
                    &format!("mtu={mtu}"),
                    "store=active",
                ],
            )
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            let _ = mtu;
            Err(io::Error::other(
                "TUN MTU configuration is unsupported on this platform",
            ))
        }
    }
    pub fn configure_ipv4(&self, address: &str, peer: &str, network: &str) -> io::Result<()> {
        let (network_address, prefix) = network
            .split_once('/')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "network must be CIDR"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid network prefix"))?;
        if prefix > 32
            || address.parse::<Ipv4Addr>().is_err()
            || peer.parse::<Ipv4Addr>().is_err()
            || network_address.parse::<Ipv4Addr>().is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid IPv4 TUN configuration",
            ));
        }
        #[cfg(target_os = "macos")]
        {
            let mask = Ipv4Addr::from(if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            });
            run_command(
                "ifconfig",
                &[
                    &self.name,
                    address,
                    peer,
                    "netmask",
                    &mask.to_string(),
                    "up",
                ],
            )?;
            run_command(
                "route",
                &[
                    "-n",
                    "add",
                    "-net",
                    network_address,
                    "-netmask",
                    &mask.to_string(),
                    "-interface",
                    &self.name,
                ],
            )
        }
        #[cfg(target_os = "linux")]
        {
            run_command(
                "ip",
                &[
                    "addr",
                    "replace",
                    &format!("{address}/{prefix}"),
                    "dev",
                    &self.name,
                ],
            )?;
            run_command("ip", &["link", "set", "dev", &self.name, "up"])?;
            run_command("ip", &["route", "replace", network, "dev", &self.name])
        }
        #[cfg(windows)]
        {
            let mask = Ipv4Addr::from(if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            });
            run_command(
                "netsh",
                &[
                    "interface",
                    "ip",
                    "set",
                    "address",
                    &format!("name={}", self.name),
                    "static",
                    address,
                    &mask.to_string(),
                    peer,
                ],
            )?;
            run_command(
                "route",
                &["ADD", network_address, "MASK", &mask.to_string(), peer],
            )
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            let _ = (address, peer, network);
            Err(io::Error::other(
                "TUN configuration is unsupported on this platform",
            ))
        }
    }
    pub fn read_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        #[cfg(windows)]
        {
            return match self
                .session
                .try_receive()
                .map_err(|error| io::Error::other(error.to_string()))?
            {
                Some(packet) if packet.bytes().len() <= buffer.len() => {
                    buffer[..packet.bytes().len()].copy_from_slice(packet.bytes());
                    Ok(packet.bytes().len())
                }
                Some(_) => Err(io::Error::other("TUN packet too large")),
                None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            };
        }
        #[cfg(unix)]
        let mut packet = [0u8; 2048];
        #[cfg(unix)]
        let target_ptr = if self.macos_header {
            packet.as_mut_ptr()
        } else {
            buffer.as_mut_ptr()
        };
        #[cfg(unix)]
        let target_len = if self.macos_header {
            packet.len()
        } else {
            buffer.len()
        };
        #[cfg(unix)]
        let count = unsafe { libc::read(self.fd, target_ptr as *mut c_void, target_len) };
        #[cfg(unix)]
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(unix)]
        let count = count as usize;
        #[cfg(unix)]
        if self.macos_header {
            if count <= 4 || count - 4 > buffer.len() {
                return Err(io::Error::other("TUN packet too large"));
            }
            buffer[..count - 4].copy_from_slice(&packet[4..count]);
            Ok(count - 4)
        } else {
            Ok(count)
        }
    }
    pub fn write_packet(&self, buffer: &[u8]) -> io::Result<usize> {
        #[cfg(windows)]
        {
            let mut packet = self
                .session
                .allocate_send_packet(buffer.len() as u16)
                .map_err(|error| io::Error::other(error.to_string()))?;
            packet.bytes_mut().copy_from_slice(buffer);
            self.session.send_packet(packet);
            return Ok(buffer.len());
        }
        #[cfg(unix)]
        let mut packet = [0u8; 2048];
        #[cfg(unix)]
        let output = if self.macos_header {
            if buffer.len() > packet.len() - 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TUN packet exceeds internal buffer",
                ));
            }
            let family: u32 = if buffer.first().is_some_and(|byte| byte >> 4 == 6) {
                30
            } else {
                2
            };
            packet[..4].copy_from_slice(&family.to_be_bytes());
            packet[4..4 + buffer.len()].copy_from_slice(buffer);
            &packet[..4 + buffer.len()]
        } else {
            buffer
        };
        #[cfg(unix)]
        let count = unsafe { libc::write(self.fd, output.as_ptr() as *const c_void, output.len()) };
        #[cfg(unix)]
        if count < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(if self.macos_header {
                (count as usize).saturating_sub(4)
            } else {
                count as usize
            })
        }
    }
}
impl Drop for Tun {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn run_command(program: &str, arguments: &[&str]) -> io::Result<()> {
    let status = Command::new(program).args(arguments).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{program} failed with status {status}"
        )))
    }
}

pub fn ipv4_packet_addresses(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || header_length > packet.len() {
        return None;
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length < header_length || total_length != packet.len() {
        return None;
    }
    Some((
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    ))
}

pub fn ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    ipv4_packet_addresses(packet).map(|(_, destination)| destination)
}
pub fn ipv4_source(packet: &[u8]) -> Option<Ipv4Addr> {
    ipv4_packet_addresses(packet).map(|(source, _)| source)
}

pub fn ipv4_is_broadcast(address: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if address == Ipv4Addr::BROADCAST {
        return true;
    }
    if prefix >= 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let broadcast = u32::from(network) | !mask;
    u32::from(address) == broadcast
}
pub fn ipv4_socket_addr_size() -> usize {
    #[cfg(unix)]
    return mem::size_of::<libc::sockaddr_in>();
    #[cfg(windows)]
    return 16;
}

pub fn socket_addr_storage(addr: SocketAddr) -> SocketAddrStorage {
    let mut storage: SocketAddrStorage = unsafe { mem::zeroed() };
    if let SocketAddr::V4(addr) = addr {
        #[cfg(unix)]
        {
            let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            #[cfg(target_os = "macos")]
            {
                sin.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
            }
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = addr.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            };
        }
        #[cfg(windows)]
        {
            storage.family = 2;
            storage.data[0..2].copy_from_slice(&addr.port().to_be_bytes());
            storage.data[2..6].copy_from_slice(&addr.ip().octets());
        }
    }
    storage
}

pub fn parse_ini_section(path: &str, section: &str) -> io::Result<HashMap<String, String>> {
    Ok(parse_ini_entries(path, section)?.into_iter().collect())
}

pub fn parse_ini_entries(path: &str, section: &str) -> io::Result<Vec<(String, String)>> {
    let text = std::fs::read_to_string(path)?;
    let mut values = Vec::new();
    let mut active = false;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            active = &line[1..line.len() - 1] == section;
            continue;
        }
        if active {
            if let Some((key, value)) = line.split_once('=') {
                values.push((key.trim().to_string(), value.trim().to_string()));
            }
        }
    }
    Ok(values)
}

pub fn parse_ipv4_cidr(value: &str) -> io::Result<(Ipv4Addr, u8)> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "network must be CIDR"))?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv4 network"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid network prefix"))?;
    if prefix > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid network prefix",
        ));
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if u32::from(address) & mask != u32::from(address) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CIDR address contains host bits",
        ));
    }
    Ok((address, prefix))
}

pub fn ipv4_in_cidr(address: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(address) & mask == u32::from(network)
}

pub fn normalize_sha256_fingerprint(value: &str) -> io::Result<String> {
    let normalized = value.replace(':', "").to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fingerprint must contain exactly 64 hexadecimal SHA-256 digits",
        ));
    }
    Ok(normalized)
}

pub fn validate_client_bindings(
    entries: Vec<(String, String)>,
    server_address: Ipv4Addr,
    network: &str,
) -> io::Result<HashMap<Ipv4Addr, String>> {
    let (network_address, network_prefix) = parse_ipv4_cidr(network)?;
    let mut fingerprints = HashSet::new();
    let mut bindings = HashMap::with_capacity(entries.len());
    for (ip, fingerprint) in entries {
        let address: Ipv4Addr = ip.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid client VPN address: {ip}"),
            )
        })?;
        if !ipv4_in_cidr(address, network_address, network_prefix) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("client address {address} is outside {network}"),
            ));
        }
        if address == server_address {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("client address {address} conflicts with the server"),
            ));
        }
        if bindings.contains_key(&address) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("duplicate client address: {address}"),
            ));
        }
        let fingerprint = normalize_sha256_fingerprint(&fingerprint).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid fingerprint for {address}: {error}"),
            )
        })?;
        if !fingerprints.insert(fingerprint.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("duplicate client fingerprint for {address}"),
            ));
        }
        bindings.insert(address, fingerprint);
    }
    Ok(bindings)
}

#[cfg(test)]
mod tests {
    use super::{
        ipv4_in_cidr, ipv4_is_broadcast, ipv4_packet_addresses, normalize_sha256_fingerprint,
        panic_gate, parse_ipv4_cidr, validate_client_bindings, validate_datagram_write,
        validate_private_key_file, IpRateLimiter, RateLimitDecision,
    };
    use std::io;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    use super::{classify_tun_error, TunErrorAction};

    #[test]
    fn panic_gate_returns_success_value() {
        assert_eq!(panic_gate("success", || Ok(42)).unwrap(), 42);
    }

    #[test]
    fn panic_gate_preserves_regular_error() {
        let error = panic_gate::<()>("regular error", || {
            Err(io::Error::new(io::ErrorKind::InvalidData, "bad packet"))
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "bad packet");
    }

    #[test]
    fn panic_gate_converts_panic_to_error() {
        let error = panic_gate::<()>("client packet", || panic!("malformed input")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "client packet panicked: malformed input");
    }

    #[test]
    fn rejects_partial_datagram_writes() {
        assert!(validate_datagram_write(1, 1).is_ok());
        let error = validate_datagram_write(0, 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(error.to_string(), "partial datagram write: 0/1 bytes");
    }

    #[test]
    fn validates_ipv4_cidr_membership() {
        let (network, prefix) = parse_ipv4_cidr("10.8.1.0/24").unwrap();
        assert!(ipv4_in_cidr("10.8.1.2".parse().unwrap(), network, prefix));
        assert!(!ipv4_in_cidr("10.8.2.2".parse().unwrap(), network, prefix));
        assert!(parse_ipv4_cidr("10.8.1.7/24").is_err());
    }

    #[test]
    fn identifies_limited_and_directed_broadcast() {
        let network: Ipv4Addr = "10.8.1.0".parse().unwrap();
        assert!(ipv4_is_broadcast(Ipv4Addr::BROADCAST, network, 24));
        assert!(ipv4_is_broadcast(
            "10.8.1.255".parse().unwrap(),
            network,
            24
        ));
        assert!(!ipv4_is_broadcast("10.8.1.2".parse().unwrap(), network, 24));
    }

    #[test]
    fn bans_thirtieth_handshake_for_ten_minutes() {
        let address = "192.0.2.10".parse().unwrap();
        let start = Instant::now();
        let mut limiter = IpRateLimiter::new(30, Duration::from_secs(60), Duration::from_secs(600));
        for attempt in 0..29 {
            assert_eq!(
                limiter.record_attempt(address, start + Duration::from_millis(attempt)),
                RateLimitDecision::Allowed
            );
        }
        assert_eq!(
            limiter.record_attempt(address, start + Duration::from_secs(1)),
            RateLimitDecision::BannedNow
        );
        assert!(limiter.check_ban(address, start + Duration::from_secs(600)));
        assert!(!limiter.check_ban(address, start + Duration::from_secs(601)));
    }

    #[test]
    fn validates_ipv4_packet_structure() {
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[12..16].copy_from_slice(&[10, 8, 1, 2]);
        packet[16..20].copy_from_slice(&[10, 8, 1, 1]);
        assert_eq!(
            ipv4_packet_addresses(&packet),
            Some(("10.8.1.2".parse().unwrap(), "10.8.1.1".parse().unwrap()))
        );

        let mut bad_ihl = packet;
        bad_ihl[0] = 0x44;
        assert_eq!(ipv4_packet_addresses(&bad_ihl), None);

        let mut bad_total_length = packet;
        bad_total_length[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(ipv4_packet_addresses(&bad_total_length), None);

        let mut trailing_data = packet.to_vec();
        trailing_data.push(0);
        assert_eq!(ipv4_packet_addresses(&trailing_data), None);
        assert_eq!(ipv4_packet_addresses(&packet[..19]), None);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_private_key_accessible_by_other_users() {
        use std::fs::{self, OpenOptions};
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "autobricks-vpn-key-permissions-{}",
            std::process::id()
        ));
        let _file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_private_key_file(path.to_str().unwrap()).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            validate_private_key_file(path.to_str().unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn classifies_tun_errors_without_retrying_permanent_failures() {
        assert_eq!(
            classify_tun_error(&io::Error::from(io::ErrorKind::WouldBlock)),
            TunErrorAction::Retry
        );
        assert_eq!(
            classify_tun_error(&io::Error::from(io::ErrorKind::Interrupted)),
            TunErrorAction::Retry
        );
        assert_eq!(
            classify_tun_error(&io::Error::from_raw_os_error(libc::ENOBUFS)),
            TunErrorAction::DropPacket
        );
        assert_eq!(
            classify_tun_error(&io::Error::from_raw_os_error(libc::EBADF)),
            TunErrorAction::Fatal
        );
        assert_eq!(
            classify_tun_error(&io::Error::from_raw_os_error(libc::ENODEV)),
            TunErrorAction::Fatal
        );
        assert_eq!(
            classify_tun_error(&io::Error::from_raw_os_error(libc::EIO)),
            TunErrorAction::Fatal
        );
    }

    #[test]
    fn normalizes_sha256_fingerprint() {
        let grouped = "AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA";
        assert_eq!(
            normalize_sha256_fingerprint(grouped).unwrap(),
            "aa".repeat(32)
        );
        assert!(normalize_sha256_fingerprint("not-a-fingerprint").is_err());
    }

    #[test]
    fn rejects_duplicate_client_bindings() {
        let fingerprint_a = "aa".repeat(32);
        let fingerprint_b = "bb".repeat(32);
        let server = "10.8.1.1".parse().unwrap();
        assert!(validate_client_bindings(
            vec![
                ("10.8.1.2".into(), fingerprint_a.clone()),
                ("10.8.1.2".into(), fingerprint_b),
            ],
            server,
            "10.8.1.0/24",
        )
        .is_err());
        assert!(validate_client_bindings(
            vec![
                ("10.8.1.2".into(), fingerprint_a.clone()),
                ("10.8.1.3".into(), fingerprint_a),
            ],
            server,
            "10.8.1.0/24",
        )
        .is_err());
    }
}
