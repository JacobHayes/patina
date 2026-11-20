//! What counter preemption does the same way on every architecture: the descriptor of
//! `/proc/self/mem` (the hops read and write program code through it), moving descriptors to
//! the runtime's hidden range, and asking the launcher's broker for a thread's counter
//! (`launcher::pmu` has the protocol).

use crate::raw::*;
use core::sync::atomic::{AtomicI32, Ordering::*};
use proto::ctl::*;
use proto::layout::*;

fn fail(what: u64, val: u64) -> ! {
    crate::sup::host_error(what as i64, val, HE_PMU)
}

/// `/proc/self/mem` of this process (hops write and read guest code through it).
pub static MEMFD: AtomicI32 = AtomicI32::new(-1);

pub fn memfd() -> u64 {
    let fd = MEMFD.load(Relaxed);
    if fd >= 0 {
        return fd as u64;
    }
    let path = b"/proc/self/mem\0";
    let r = crate::fdlim::transient(|| unsafe {
        sc4(
            nr::OPENAT,
            (-100i64) as u64,
            path.as_ptr() as u64,
            2 | 0x80000,
            0,
        )
    });
    if r < 0 {
        fail(PMU_E_OPEN, (-r) as u64);
    }
    let h = hide(r);
    MEMFD.store(h as i32, Relaxed);
    h as u64
}

/// Move a descriptor to the runtime's hidden range (close-on-exec).
pub fn hide(fd: i64) -> i64 {
    let h = crate::fdlim::hide(fd, FD_RT_DYN);
    if h < 0 {
        fail(PMU_E_OPEN, (-h) as u64);
    }
    h
}

#[repr(C)]
struct MsgHdr {
    name: u64,
    namelen: u32,
    _p: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: i32,
    _p2: u32,
}

/// Ask the launcher for a counter on this thread: send a thread pidfd, get the counter.
pub fn broker_open(tid: i32) -> i64 {
    const PIDFD_THREAD: u64 = 0x80;
    let pidfd =
        crate::fdlim::transient(|| unsafe { sc2(nr::PIDFD_OPEN, tid as u64, PIDFD_THREAD) });
    if pidfd < 0 {
        return pidfd;
    }
    let req = *b"patpmu01";
    let iov: [u64; 2] = [req.as_ptr() as u64, 8];
    // cmsghdr: len 20, SOL_SOCKET, SCM_RIGHTS, the descriptor.
    let cm: [u64; 3] = [20, 1 | (1 << 32), pidfd as u64];
    let m = MsgHdr {
        name: 0,
        namelen: 0,
        _p: 0,
        iov: iov.as_ptr() as u64,
        iovlen: 1,
        control: cm.as_ptr() as u64,
        controllen: 24,
        flags: 0,
        _p2: 0,
    };
    let r = unsafe {
        sc3(
            nr::SENDMSG,
            FD_PMU as u64,
            &m as *const MsgHdr as u64,
            0x4000,
        )
    };
    unsafe { sc1(nr::CLOSE, pidfd as u64) };
    if r < 0 {
        return r;
    }
    let mut rep: i64 = 0;
    let riov: [u64; 2] = [&mut rep as *mut i64 as u64, 8];
    let mut rcm: [u64; 3] = [0; 3];
    let mut rm = MsgHdr {
        name: 0,
        namelen: 0,
        _p: 0,
        iov: riov.as_ptr() as u64,
        iovlen: 1,
        control: rcm.as_mut_ptr() as u64,
        controllen: 24,
        flags: 0,
        _p2: 0,
    };
    // The counter arrives at the lowest free number: any, as it is hidden at once.
    let r = crate::fdlim::raised(|| unsafe {
        sc3(
            nr::RECVMSG,
            FD_PMU as u64,
            &mut rm as *mut MsgHdr as u64,
            0x4000_0000,
        )
    });
    if r < 8 {
        return if r < 0 { r } else { -e::EIO };
    }
    if rep < 0 {
        return rep;
    }
    if rcm[0] < 20 || rcm[1] != 1 | (1 << 32) {
        return -e::EIO;
    }
    (rcm[2] & 0xffff_ffff) as i64
}
