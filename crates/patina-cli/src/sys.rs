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
