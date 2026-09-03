use libc::{c_char, c_int, c_uchar, c_uint, c_void};
use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "macos")]
use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::RawFd;
use std::process::Command;
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::ptr;

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
type IoCallback =
    Option<unsafe extern "C" fn(*mut WolfSsl, *mut c_char, c_int, *mut c_void) -> c_int>;

const SUCCESS: c_int = 1;
const VERIFY_NONE: c_int = 0;
const VERIFY_PEER: c_int = 1;
const VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 2;
const ERROR_WANT_READ: c_int = 2;
const ERROR_WANT_WRITE: c_int = 3;
const SOCKET_ERROR: c_int = -308;

#[link(name = "wolfssl")]
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
    fn wolfSSL_EVP_sha256() -> *const WolfMd;
}

pub struct Config {
    pub server: bool,
    pub certificate_file: String,
    pub private_key_file: String,
    pub ca_file: Option<String>,
    pub mtu: u16,
}

pub struct Dtls {
    ctx: *mut WolfCtx,
    ssl: *mut WolfSsl,
    server: bool,
    nonblocking: bool,
}
unsafe impl Send for Dtls {}

impl Dtls {
    pub fn new(config: &Config) -> io::Result<Self> {
        let cert = CString::new(config.certificate_file.as_str()).map_err(invalid_input)?;
        let key = CString::new(config.private_key_file.as_str()).map_err(invalid_input)?;
        let ca = config
            .ca_file
            .as_ref()
            .map(|v| CString::new(v.as_str()).map_err(invalid_input))
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
            #[cfg(target_os = "macos")]
            if config.mtu > 0 {
                wolfSSL_CTX_dtls_set_mtu(ctx, config.mtu);
            }
            Ok(Self {
                ctx,
                ssl: ptr::null_mut(),
                server: config.server,
                nonblocking: false,
            })
        }
    }

    pub fn set_socket(&mut self, fd: RawFd) -> io::Result<()> {
        unsafe {
            self.ssl = wolfSSL_new(self.ctx);
            if self.ssl.is_null() || wolfSSL_set_fd(self.ssl, fd) != SUCCESS {
                return Err(io::Error::other("wolfSSL_set_fd failed"));
            }
        }
        Ok(())
    }

    pub fn set_nonblocking(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
        unsafe {
            wolfSSL_dtls_set_using_nonblock(self.ssl, if nonblocking { 1 } else { 0 });
        }
    }

    pub fn set_peer(&mut self, peer: &libc::sockaddr_storage, peer_size: usize) -> io::Result<()> {
        unsafe {
            check(wolfSSL_dtls_set_peer(
                self.ssl,
                peer as *const _ as *mut c_void,
                peer_size as c_uint,
            ))
        }
    }

    pub fn set_io(&mut self, io: &mut DtlsIo) {
        unsafe {
            wolfSSL_SSLSetIORecv(self.ssl, Some(dtls_recv));
            wolfSSL_SSLSetIOSend(self.ssl, Some(dtls_send));
            wolfSSL_SetIOReadCtx(self.ssl, io as *mut DtlsIo as *mut c_void);
            wolfSSL_SetIOWriteCtx(self.ssl, io as *mut DtlsIo as *mut c_void);
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
    pub fn fd(&self) -> RawFd {
        unsafe { wolfSSL_get_fd(self.ssl) }
    }
}

impl Drop for Dtls {
    fn drop(&mut self) {
        unsafe {
            wolfSSL_free(self.ssl);
            wolfSSL_CTX_free(self.ctx);
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
    peer: libc::sockaddr_storage,
    peer_size: libc::socklen_t,
    direct_receive: bool,
    incoming: VecDeque<Vec<u8>>,
}

impl DtlsIo {
    pub fn new(fd: RawFd, peer: libc::sockaddr_storage, peer_size: libc::socklen_t) -> Self {
        Self {
            fd,
            peer,
            peer_size,
            direct_receive: false,
            incoming: VecDeque::new(),
        }
    }

    pub fn new_client(fd: RawFd, peer: libc::sockaddr_storage, peer_size: libc::socklen_t) -> Self {
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
        let result = libc::recvfrom(
            io.fd,
            buffer as *mut c_void,
            size as usize,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        );
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
        libc::send(io.fd, buffer as *const c_void, size as usize, 0)
    } else {
        libc::sendto(
            io.fd,
            buffer as *const c_void,
            size as usize,
            0,
            &io.peer as *const _ as *const libc::sockaddr,
            io.peer_size,
        )
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
unsafe impl Send for Tun {}

pub struct ForwardingGuard {
    #[cfg(target_os = "linux")]
    interface: String,
    #[cfg(target_os = "linux")]
    network: String,
    #[cfg(target_os = "linux")]
    restore_ip_forward: bool,
}

impl ForwardingGuard {
    pub fn enable(interface: &str, network: &str) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let original = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?;
            let restore_ip_forward = original.trim() == "0";
            if restore_ip_forward {
                std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1\n")?;
            }

            let mut guard = Self {
                interface: interface.to_owned(),
                network: network.to_owned(),
                restore_ip_forward,
            };
            guard.remove_rule();
            if let Err(error) = run_command(
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
            ) {
                if restore_ip_forward {
                    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"0\n");
                }
                return Err(error);
            }
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
        let _ = Command::new("iptables")
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
            .stderr(Stdio::null())
            .status();
    }
}

impl Drop for ForwardingGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.remove_rule();
            if self.restore_ip_forward {
                if let Err(error) = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"0\n") {
                    eprintln!("[server] unable to restore ip_forward: {error}");
                }
            }
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
                return Err(io::Error::last_os_error());
            }
            let mut name = [0u8; 16];
            let mut name_len = name.len() as libc::socklen_t;
            if libc::getsockopt(fd, 2, 2, name.as_mut_ptr() as *mut c_void, &mut name_len) < 0 {
                return Err(io::Error::last_os_error());
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
            return Err(io::Error::last_os_error());
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
            fd: -1,
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
        if mtu < 576 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MTU must be at least 576",
            ));
        }
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
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
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
        let mut packet = [0u8; 2048];
        let target_ptr = if self.macos_header {
            packet.as_mut_ptr()
        } else {
            buffer.as_mut_ptr()
        };
        let target_len = if self.macos_header {
            packet.len()
        } else {
            buffer.len()
        };
        let count = unsafe { libc::read(self.fd, target_ptr as *mut c_void, target_len) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let count = count as usize;
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
        let mut packet = [0u8; 2048];
        let output = if self.macos_header {
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
        let count = unsafe { libc::write(self.fd, output.as_ptr() as *const c_void, output.len()) };
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

pub fn ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() >= 20 && packet[0] >> 4 == 4 {
        Some(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))
    } else {
        None
    }
}
pub fn ipv4_source(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() >= 20 && packet[0] >> 4 == 4 {
        Some(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))
    } else {
        None
    }
}
pub fn socket_addr_storage(addr: SocketAddr) -> libc::sockaddr_storage {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    if let SocketAddr::V4(addr) = addr {
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
    storage
}

pub fn parse_ini_section(path: &str, section: &str) -> io::Result<HashMap<String, String>> {
    let text = std::fs::read_to_string(path)?;
    let mut values = HashMap::new();
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
                values.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    Ok(values)
}
