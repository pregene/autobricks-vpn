//! Windows client UDP readiness. Never pass Wintun handles to WSAPoll.
use std::io;
use std::time::Duration;

#[repr(C)]
pub(crate) struct PollFd {
    pub fd: usize,
    pub events: i16,
    pub revents: i16,
}
pub(crate) const POLLIN: i16 = 0x0300;

#[link(name = "ws2_32")]
extern "system" {
    fn WSAPoll(fds: *mut PollFd, count: u32, timeout: i32) -> i32;
    fn WSAGetLastError() -> i32;
}

pub(crate) fn poll(fds: &mut [PollFd], timeout: Duration) -> io::Result<()> {
    let result = unsafe {
        WSAPoll(
            fds.as_mut_ptr(),
            fds.len() as u32,
            timeout.as_millis().min(i32::MAX as u128) as i32,
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    if fds
        .iter()
        .any(|fd| fd.revents & (0x0001 | 0x0002 | 0x0004) != 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "UDP socket reported a poll error",
        ));
    }
    Ok(())
}
