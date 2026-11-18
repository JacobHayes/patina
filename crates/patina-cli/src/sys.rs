//! Thin wrappers over libc used by the launcher and the supervisor.

use std::io;

pub fn cvt(r: libc::c_long) -> io::Result<libc::c_long> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

pub fn cvt_i(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

/// Shared mapping of a whole descriptor.
pub fn map_shared(fd: i32, len: usize) -> io::Result<*mut u8> {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        Err(io::Error::last_os_error())
    } else {
        Ok(p as *mut u8)
    }
}

/// Wait while `*addr == val`, at most `ms` milliseconds (shared futex).
pub fn futex_wait_ms(addr: *const u32, val: u32, ms: u64) {
    let ts = libc::timespec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr,
            libc::FUTEX_WAIT,
            val,
            &ts as *const libc::timespec,
        );
    }
}

pub fn futex_wake(addr: *const u32, n: u32) {
    unsafe {
        libc::syscall(libc::SYS_futex, addr, libc::FUTEX_WAKE, n);
    }
}

pub fn pidfd_open(pid: i32) -> io::Result<i32> {
    cvt(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) }).map(|r| r as i32)
}

/// SIGTERM (a sweep stopping its runs) as a descriptor: once the signal came it stays
/// readable, so every later wait sees it. Whoever waits on a sandbox or a checker then ends it,
/// waits until its processes are gone, and exits (`exit_terminated`): patina never leaves a
/// process behind when it is stopped. Installed on first use.
pub fn term_fd() -> i32 {
    static FD: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    static WRITE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
    extern "C" fn on_term(_: libc::c_int) {
        let fd = WRITE.load(std::sync::atomic::Ordering::Relaxed);
        if fd >= 0 {
            unsafe { libc::write(fd, b"t".as_ptr().cast(), 1) };
        }
    }
    *FD.get_or_init(|| unsafe {
        let mut p = [-1i32; 2];
        if libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) != 0 {
            return -1;
        }
        WRITE.store(p[1], std::sync::atomic::Ordering::Relaxed);
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_term as *const () as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        p[0]
    })
}

/// Exit as SIGTERM asked, once what this process started is gone.
pub fn exit_terminated() -> ! {
    std::process::exit(128 + libc::SIGTERM)
}

/// What `wait_fd` saw.
#[derive(PartialEq, Eq)]
pub enum Waited {
    Ready,
    Timeout,
    /// SIGTERM came (`sys::term_fd`).
    Terminated,
}

/// Wait until `fd` is readable, `deadline` passes or SIGTERM comes (`term_fd`).
pub fn wait_fd(fd: i32, deadline: std::time::Instant) -> Waited {
    let term = term_fd();
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Waited::Timeout;
        }
        let mut p = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: term,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ms = left.as_millis().clamp(1, i32::MAX as u128) as i32;
        let r = unsafe { libc::poll(p.as_mut_ptr(), 2, ms) };
        if r > 0 && p[1].revents != 0 {
            return Waited::Terminated;
        }
        if r > 0 {
            return Waited::Ready;
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Waited::Ready;
        }
    }
}

/// Is the descriptor readable within `ms` (0: just look)?
pub fn readable(fd: i32, ms: i32) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut p, 1, ms) > 0 }
}

pub fn write_fd(fd: i32, data: &[u8]) -> io::Result<()> {
    let mut off = 0;
    while off < data.len() {
        let r = unsafe { libc::write(fd, data[off..].as_ptr() as *const _, data.len() - off) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        off += r as usize;
    }
    Ok(())
}
