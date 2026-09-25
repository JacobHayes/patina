//! proc/vfork — `vfork` (kernel/fork.c: `CLONE_VM | CLONE_VFORK`), a row
//! only x86_64's table has: the child runs in the caller's address space
//! while the caller is suspended, so a byte the child stores is the
//! caller's own once `vfork` returns there, and the caller resumes only
//! after the child has exited (its status then reaped by `wait4`).
//!
//! A vfork child may not return from the function that called `vfork`: it
//! would unwind the frame the suspended caller resumes in. So the scenario
//! has one vehicle, the instruction: the child's store and its `exit` run
//! in the same inline-assembly block as the `syscall`, touching no stack.
//! glibc's `syscall(2)` returns through its own frame, and glibc's `vfork`
//! is a process symbol the pre-run audit refuses (a probe binary importing
//! it would not run under patina at all), so neither is a vehicle here.
//!
//! Under patina `vfork` is a process-lifecycle trap by design
//! (docs/arcs/syscall-conformance.md §7): the child oracle runs natively
//! only.

use crate::catalog::{DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::observe::{Id, Norm};
use crate::probe::Probe;
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;
use std::sync::atomic::{AtomicU8, Ordering};

/// The child's exit status.
const CHILD_STATUS: i32 = 7;

/// `vfork` through the instruction. The child stores 1 into `mark` and
/// exits with [`CHILD_STATUS`] without leaving the block; the caller gets
/// the child's pid (or `-errno`).
fn vfork_storing(mark: &AtomicU8) -> i64 {
    let result: i64;
    // SAFETY: the child shares this address space and runs only the store
    // and the `exit` below, on registers the kernel preserved across the
    // instruction (every one but rax, rcx and r11); it never touches the
    // stack, so the suspended caller resumes in an intact frame.
    unsafe {
        std::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "mov byte ptr [rdx], 1",
            "mov eax, {exit}",
            "mov edi, {status}",
            "syscall",
            "2:",
            exit = const libc::SYS_exit,
            status = const CHILD_STATUS,
            inlateout("rax") Syscall::N_vfork.number() as i64 => result,
            in("rdx") mark.as_ptr(),
            lateout("rdi") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

pub fn run(p: &Probe) {
    let mark = AtomicU8::new(0);
    let child = vfork_storing(&mark);
    p.rec
        .event(Syscall::N_vfork.name(), child)
        .norm("ret", Norm::Identity(Id::Process))
        .emit();
    p.require("vfork", child > 0);
    p.check(
        "the child's store is seen once the caller resumes: they share one address space, and the caller waited for the child",
        mark.load(Ordering::SeqCst) == 1,
    );
    // `wait4(child, &status, 0, NULL)`, with both pids recorded as
    // identities.
    let mut status = 0i32;
    let reaped = p.call_unrecorded(
        Syscall::N_wait4,
        [child, &mut status as *mut i32 as i64, 0, 0, 0, 0],
    );
    p.rec
        .event(Syscall::N_wait4.name(), reaped)
        .arg("pid", child)
        .norm("args.pid", Norm::Identity(Id::Process))
        .norm("ret", Norm::Identity(Id::Process))
        .arg("options", 0)
        .field("status", status)
        .emit();
    p.check(
        "the child is reaped with its exit status",
        reaped == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == CHILD_STATUS,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/vfork",
    run,
    vehicles: &[Vehicle::Raw],
    covers: &[Syscall::N_vfork],
    gaps: &[Gap {
        status: Status::ByDesign,
        vehicles: &[Vehicle::Raw],
        what: "vfork is a process-lifecycle trap (docs/arcs/syscall-conformance.md §7); the child oracle runs natively only",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall vfork (nr 58, class process",
        },
    }],
    ..DEFAULTS
};
