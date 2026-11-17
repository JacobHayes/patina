//! Signals. Dispositions, masks, pending sets and the alternate stack are runtime and
//! supervisor state; the kernel-level mask of a guest thread never changes.
//! A signal between guest tasks never becomes a kernel signal: it is delivered by a frame
//! the runtime builds at a trap exit of the receiving thread.
use super::*;

const G: Group = Group::Sig;

const SEND: &str = "A SigSend request: the supervisor marks the signal pending (standard signals coalesce, real-time signals queue) and wakes the receiving thread if it is parked; delivery happens at that thread's trap exit. Never a kernel signal.";
const ITIMER: &str = "ITIMER_REAL is a supervisor event in virtual time that raises SIGALRM (SI_KERNEL); ITIMER_VIRTUAL and ITIMER_PROF end the run.";

pub const ROWS: &[Row] = &[
    Row::new(G, nr::RT_SIGACTION, Virt, C, "Dispositions are virtual, kept by the runtime per process; the supervisor is told the kind (default, ignore, handler) when it changes. The kernel's handlers stay the runtime's own.")
        .outs(&[out(2, Len::Fixed(32))]),
    Row::new(G, nr::RT_SIGPROCMASK, Virt, C, "The guest's mask is virtual (runtime, mirrored in the thread's slot); the kernel mask keeps every asynchronous signal blocked and SIGSYS and the fault signals open.")
        .outs(&[out(2, Len::Fixed(8))]),
    Row::new(G, nr::SIGALTSTACK, Virt, C, "The guest's alternate stack is virtual and frames are built on it; the kernel's alternate stack is the runtime's own.")
        .outs(&[out(1, Len::Fixed(24))]),
    Row::new(G, nr::RT_SIGRETURN, Virt, C, "Emulated: registers, FP state, mask and alternate stack are copied from the guest's frame into the trap frame."),
    Row::new(G, nr::KILL, Virt, C, SEND),
    Row::new(G, nr::TKILL, Virt, C, SEND),
    Row::new(G, nr::TGKILL, Virt, C, SEND),
    Row::new(G, nr::RT_SIGQUEUEINFO, Virt, C, SEND).ins(&[out(2, Len::Fixed(128))]),
    Row::new(G, nr::RT_TGSIGQUEUEINFO, Virt, C, SEND).ins(&[out(3, Len::Fixed(128))]),
    Row::new(G, nr::RT_SIGPENDING, Virt, C, "Pending signals (the thread's and its process's) that the virtual mask blocks, from the slot's pending word.")
        .outs(&[out(0, Len::Fixed(8))]),
    Row::new(G, nr::RT_SIGTIMEDWAIT, Virt, C, "A SigWait request: a pending signal of the set is dequeued at once, otherwise the thread parks with a virtual deadline.")
        .outs(&[out(1, Len::Fixed(128))]),
    Row::new(G, nr::RT_SIGSUSPEND, Virt, C, "The temporary mask is virtual; a SigSuspend request parks the thread until a signal is deliverable."),
    Row::new(G, nr::PAUSE, Virt, C, "A SigSuspend request with the current mask."),
    Row::new(G, nr::ALARM, Virt, C, ITIMER),
    Row::new(G, nr::SETITIMER, Virt, C, ITIMER).outs(&[out(2, Len::Fixed(32))]),
    Row::new(G, nr::GETITIMER, Virt, C, ITIMER).outs(&[out(1, Len::Fixed(32))]),
    Row::new(G, nr::RESTART_SYSCALL, Virt, C, "Continues a sleep or futex wait interrupted by a signal that ran no handler, with its original virtual deadline (the kernel's restart block)."),
    Row::new(G, nr::SIGNALFD, Deny(errno::ENOSYS), C, "signalfd is refused."),
    Row::new(G, nr::SIGNALFD4, Deny(errno::ENOSYS), C, "signalfd is refused."),
];
