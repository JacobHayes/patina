//! arm64 epoll output preserves the kernel's field-copy and padding behavior.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{Probe, neg, page_size};
use libc::*;
use patina_dst_syscalls::Syscall;

pub fn run(p: &Probe) {
    let ep = p.epoll_create1(0);
    p.require("epoll_create1", ep >= 0);
    let ef = p.eventfd2(1, EFD_NONBLOCK);
    p.require("eventfd2", ef >= 0);
    p.require(
        "register readable eventfd",
        p.epoll_ctl(ep, EPOLL_CTL_ADD, ef, EPOLLIN as u32, 0xF2) == 0,
    );

    let page = page_size();
    let output = p.map_anon("epoll-output", page * 2, MAP_PRIVATE);
    output.fill(0, &[0xAA; 16]);
    let args = [
        ep as i64,
        output.base as i64,
        1,
        0,
        0,
        size_of::<u64>() as i64,
    ];
    let result = p.call_unrecorded(Syscall::N_epoll_pwait, args);
    p.record_result(Syscall::N_epoll_pwait, result);
    let fields = output.bytes(0, 4);
    let data = output.bytes(8, 8);
    p.check(
        "epoll_pwait leaves the prefilled event padding unchanged",
        result == 1
            && u32::from_ne_bytes(fields.try_into().unwrap()) == EPOLLIN as u32
            && output.bytes(4, 4) == [0xAA; 4]
            && u64::from_ne_bytes(data.try_into().unwrap()) == 0xF2,
    );

    let tail = page - size_of::<u64>();
    output.fill(tail, &[0xAA; 8]);
    p.require(
        "protect the second output page",
        p.mprotect(&output.at(page), page, PROT_NONE) == 0,
    );
    let result = p.call_unrecorded(
        Syscall::N_epoll_pwait,
        [
            ep as i64,
            (output.base + tail) as i64,
            1,
            0,
            0,
            size_of::<u64>() as i64,
        ],
    );
    p.record_result(Syscall::N_epoll_pwait, result);
    let prefix = output.bytes(tail, 8);
    p.check(
        "epoll_pwait stores events before data faults across PROT_NONE",
        result == neg(EFAULT)
            && u32::from_ne_bytes(prefix[..4].try_into().unwrap()) == EPOLLIN as u32
            && prefix[4..] == [0xAA; 4],
    );

    p.munmap(&output.at(0), output.len);
    p.close(ef);
    p.close(ep);
}

pub const SCENARIO: Scenario = Scenario {
    name: "readiness/epoll_f2",
    run,
    covers: &[
        Syscall::N_epoll_create1,
        Syscall::N_epoll_ctl,
        Syscall::N_epoll_pwait,
        Syscall::N_eventfd2,
        Syscall::N_mmap,
        Syscall::N_mprotect,
        Syscall::N_munmap,
        Syscall::N_close,
    ],
    symbols: &[
        "epoll_create1",
        "epoll_ctl",
        "epoll_pwait",
        "eventfd",
        "mmap",
        "mprotect",
        "munmap",
        "close",
    ],
    ..DEFAULTS
};
