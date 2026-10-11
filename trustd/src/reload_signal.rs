//! Feed SIGHUP into the daemon's poll loop without doing work in a handler.
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::FromRawFd;

/// Call on the main thread before starting the daemon. SIGHUP stays blocked
/// on that thread for its lifetime and is consumed through the returned fd.
pub fn open() -> io::Result<File> {
    // SAFETY: both masks are initialized before use; the pointers remain live.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut previous: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGHUP);
    }
    let error = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    // SAFETY: mask is valid; -1 requests a new descriptor owned by this function.
    let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        // SAFETY: restore this thread's saved mask if no descriptor was created.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) };
        return Err(error);
    }
    // SAFETY: signalfd returned a new, uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Drain queued requests, coalescing them into one refresh in the main loop.
pub fn drain(signal: &mut File) -> io::Result<bool> {
    let mut pending = false;
    let mut record = [0u8; std::mem::size_of::<libc::signalfd_siginfo>()];
    loop {
        match signal.read(&mut record) {
            Ok(n) if n == record.len() => pending = true,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short signalfd record",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(pending),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn hangup_is_consumed_without_terminating_and_can_be_requested_again() {
        // The signal mask belongs only to this short-lived thread. Deliver the
        // signal to this thread too, so unrelated test threads cannot receive it.
        std::thread::spawn(|| {
            let mut fd = super::open().unwrap();
            assert!(!super::drain(&mut fd).unwrap());
            for _ in 0..2 {
                // SAFETY: the current thread is alive and has blocked SIGHUP.
                assert_eq!(
                    unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGHUP) },
                    0
                );
                assert!(super::drain(&mut fd).unwrap());
                assert!(!super::drain(&mut fd).unwrap());
            }
        })
        .join()
        .unwrap();
    }
}
