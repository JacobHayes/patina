//! Scheduling calls, threads and futexes.
use super::*;

const G: Group = Group::Sched;

const PRIO: &str = "Nice values and scheduling policies are recorded per thread and read back (a new thread or process inherits its creator's); they change nothing in the schedule. What the kernel refuses an unprivileged process is refused (RLIMIT_NICE and RLIMIT_RTPRIO are 0): a lower nice value (setpriority EACCES, the others EPERM), a real-time or deadline policy, leaving SCHED_IDLE. Utilisation clamping answers EOPNOTSUPP.";

pub const ROWS: &[Row] = &[
    Row::new(G, nr::SCHED_YIELD, Virt, C, "A Yield request to the supervisor."),
    Row::new(G, nr::SCHED_GETAFFINITY, Virt, C, "Reads as the configured CPU count.").outs(&[out(2, Len::Ret { max: 1 })]),
    Row::new(G, nr::SCHED_SETAFFINITY, Virt, C, "Recorded and ignored.").refs(&[out(2, Len::Arg(1))]),
    Row::new(G, nr::GETPRIORITY, Virt, C, PRIO),
    Row::new(G, nr::SETPRIORITY, Virt, C, PRIO),
    Row::new(G, nr::SCHED_GETSCHEDULER, Virt, C, PRIO),
    Row::new(G, nr::SCHED_SETSCHEDULER, Virt, C, PRIO).refs(&[out(2, Len::Fixed(4))]),
    Row::new(G, nr::SCHED_GETPARAM, Virt, C, PRIO).outs(&[out(1, Len::Fixed(4))]),
    Row::new(G, nr::SCHED_SETPARAM, Virt, C, PRIO).refs(&[out(1, Len::Fixed(4))]),
    Row::new(G, nr::SCHED_GETATTR, Virt, C, PRIO).outs(&[out(1, Len::Fixed(48))]).refs(&[out(1, Len::Arg(2))]),
    Row::new(G, nr::SCHED_SETATTR, Virt, C, PRIO).refs(&[out(1, Len::Fixed(48))]),
    Row::new(G, nr::SCHED_GET_PRIORITY_MAX, Virt, C, "The kernel's answer: 99 for SCHED_FIFO and SCHED_RR, 0 for the other policies, EINVAL for an unknown one."),
    Row::new(G, nr::SCHED_GET_PRIORITY_MIN, Virt, C, "The kernel's answer: 1 for SCHED_FIFO and SCHED_RR, 0 for the other policies, EINVAL for an unknown one."),
    Row::new(G, nr::GETCPU, Virt, C, "CPU 0, machine 0.").outs(&[out(0, Len::Fixed(4)), out(1, Len::Fixed(4))]),
    Row::new(G, nr::FUTEX, Virt, C, "Wait queues are supervisor state keyed by (address-space id, address), woken FIFO; the guest's word is read by the runtime while it holds the turn; timeouts are virtual deadlines. PI operations answer ENOSYS.").refs(&[out(0, Len::Futex)]),
    Row::new(G, nr::FUTEX_WAITV, Deny(errno::ENOSYS), C, "futex_waitv is refused; programs fall back to futex."),
    Row::new(G, nr::GET_ROBUST_LIST, Deny(errno::ENOSYS), C, "The robust list is recorded by the runtime and never walked; reading it back is refused."),
    Row::new(G, nr::CLONE, Place, C, "Threads (CLONE_VM with the thread flag set): the runtime performs the clone on a stack it owns (frame-copy trampoline); the child waits for its turn before running guest code. The guest's clear-tid word is emulated at exit; the kernel's points at a runtime word. Without CLONE_VM: a fork; CLONE_VM|CLONE_VFORK: a vfork through the same trampoline. A flag that makes a namespace (CLONE_NEWUSER and the other CLONE_NEW* flags) answers EPERM, as unshare does, and is recorded. Other flag sets end the run."),
    Row::new(G, nr::EXIT, Virt, C, "ThreadExit to the supervisor after the emulated clear-tid store and wake, then the real exit; the last thread of a process goes through the exit barrier."),
];
