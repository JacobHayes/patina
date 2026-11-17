//! Scheduling calls, threads and futexes.
use super::*;

const G: Group = Group::Sched;

pub const ROWS: &[Row] = &[
    Row::new(G, nr::SCHED_YIELD, Virt, C, "A Yield request to the supervisor."),
    Row::new(G, nr::SCHED_GETAFFINITY, Virt, C, "Reads as the configured CPU count.").outs(&[out(2, Len::Ret)]),
    Row::new(G, nr::SCHED_SETAFFINITY, Virt, C, "Recorded and ignored."),
    Row::new(G, nr::GETCPU, Virt, C, "CPU 0, node 0.").outs(&[out(0, Len::Fixed(4)), out(1, Len::Fixed(4))]),
    Row::new(G, nr::FUTEX, Virt, C, "Wait queues are supervisor state keyed by (address-space id, address), woken FIFO; the guest's word is read by the runtime while it holds the turn; timeouts are virtual deadlines. PI operations answer ENOSYS."),
    Row::new(G, nr::FUTEX_WAITV, Deny(errno::ENOSYS), C, "futex_waitv is refused; programs fall back to futex."),
    Row::new(G, nr::GET_ROBUST_LIST, Deny(errno::ENOSYS), C, "The robust list is recorded by the runtime and never walked; reading it back is refused."),
    Row::new(G, nr::CLONE, Place, C, "Threads (CLONE_VM with the thread flag set): the runtime performs the clone on a stack it owns (frame-copy trampoline); the child waits for its turn before running guest code. The guest's clear-tid word is emulated at exit; the kernel's points at a runtime word. Without CLONE_VM: a fork; CLONE_VM|CLONE_VFORK: a vfork through the same trampoline. Other flag sets end the run."),
    Row::new(G, nr::EXIT, Virt, C, "ThreadExit to the supervisor after the emulated clear-tid store and wake, then the real exit; the last thread of a process goes through the exit barrier."),
];
