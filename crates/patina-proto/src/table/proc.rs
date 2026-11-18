//! Process identity, lifecycle, limits.
use super::*;

const G: Group = Group::Proc;

const PIDS: &str = "PIDs are allocated sequentially in a fresh PID namespace and creations are serialised, so they are a function of creation order.";
const CREDS: &str = "Fixed by the user namespace mapping.";
const RLIM: &str = "Answered from a fixed table (stack 8 MiB, nofile 1024/2048, others unlimited); sets are accepted and not enforced. The limits the kernel enforces underneath are set by the supervisor to fixed values, and a host hard limit below them ends the run as infra before the guest starts; reaching one (EFBIG, a refused clone) also ends it as infra.";

pub const ROWS: &[Row] = &[
    Row::new(G, nr::GETPID, Pass, A, PIDS),
    Row::new(G, nr::GETPPID, Pass, A, PIDS),
    Row::new(G, nr::GETTID, Pass, A, PIDS),
    Row::new(G, nr::GETUID, Pass, A, CREDS),
    Row::new(G, nr::GETEUID, Pass, A, CREDS),
    Row::new(G, nr::GETGID, Pass, A, CREDS),
    Row::new(G, nr::GETEGID, Pass, A, CREDS),
    Row::new(G, nr::EXIT_GROUP, Virt, C, "ProcExit to the supervisor, then the real exit_group; the supervisor holds the turn until the pidfd is readable (exit barrier)."),
    Row::new(G, nr::SET_TID_ADDRESS, Virt, C, "The clear-child-tid address is recorded by the runtime, which performs the clear itself at thread exit; returns the tid."),
    Row::new(G, nr::SET_ROBUST_LIST, Virt, C, "The robust-list head is recorded by the runtime; the kernel never walks it."),
    Row::new(G, nr::PRLIMIT64, Virt, C, RLIM).outs(&[out(3, Len::Fixed(16))]).refs(&[out(2, Len::Fixed(16))]),
    Row::new(G, nr::GETRLIMIT, Virt, C, RLIM).outs(&[out(1, Len::Fixed(16))]),
    Row::new(G, nr::SETRLIMIT, Virt, C, RLIM).refs(&[out(1, Len::Fixed(16))]),
    Row::new(G, nr::ARCH_PRCTL, Pass, A, "ARCH_SET_FS/GS and ARCH_GET_FS/GS are per-thread register state; other codes answer EINVAL as on a kernel without them.").refs(&[out(1, Len::Command)]),
    Row::new(G, nr::UNAME, Rewrite, A, "Host-stable release and version; the hostname is the UTS namespace's (\"sim\"); the domain name, a copy of the host's NIS domain, reads \"(none)\".").outs(&[out(0, Len::Fixed(390))]),
    Row::new(G, nr::CLONE3, Deny(errno::ENOSYS), C, "Refused so that libc falls back to clone."),
    Row::new(G, nr::RSEQ, Deny(errno::ENOSYS), C, "Refused; glibc and others accept ENOSYS silently."),
    Row::new(G, nr::PRCTL, Pass, A, "PR_SET_NAME, PR_GET_NAME, PR_GET_DUMPABLE and PR_SET_VMA act on sandbox state; PR_GET_TSC/PR_SET_TSC are virtual (the real counter always faults); PR_SET_PDEATHSIG/PR_GET_PDEATHSIG are virtual (raised by the supervisor at the parent's exit barrier); PR_SET_CHILD_SUBREAPER answers EINVAL (orphans always go to the supervisor, PID 1); any other option answers EINVAL and is recorded as prctl:OPTION (deny by default).").refs(&[out(1, Len::Command)]),
    // processes: processes.
    Row::new(G, nr::FORK, Place, A, FORK),
    Row::new(G, nr::VFORK, Place, A, VFORK),
    Row::new(G, nr::EXECVE, Virt, A, EXEC).ins(&[out(0, Len::CStr)]).refs(&[out(1, Len::StrVec), out(2, Len::StrVec)]),
    Row::new(G, nr::EXECVEAT, Virt, A, EXEC).ins(&[out(1, Len::CStr)]).refs(&[out(2, Len::StrVec), out(3, Len::StrVec)]).fd(0),
    Row::new(G, nr::WAIT4, Attempt, A, WAIT).outs(&[out(1, Len::Fixed(4)), out(3, Len::Fixed(144))]),
    Row::new(G, nr::WAITID, Attempt, A, WAIT).outs(&[out(2, Len::Fixed(128)), out(4, Len::Fixed(144))]),
    Row::new(G, nr::SETPGID, Pass, A, PGRP),
    Row::new(G, nr::GETPGRP, Pass, A, PGRP),
    Row::new(G, nr::SETSID, Pass, A, PGRP),
    Row::new(G, nr::GETPGID, Pass, A, PGRP),
    Row::new(G, nr::GETSID, Pass, A, PGRP),
];

const FORK: &str = "Real fork from the handler: the parent picks the child's slot under the turn and announces it (Forked); the child, a copy of the runtime, sleeps on that slot until it is given the turn. The supervisor opens a pidfd for the exit barrier. PIDs come from the fresh PID namespace in creation order.";
const VFORK: &str = "True vfork through the thread trampoline: VforkStart parks the parent, which then blocks in the kernel; the child holds the turn and the parent becomes runnable only at the child's post-exec Hello or its exit barrier.";
const EXEC: &str = "The runtime resolves the target (ELF, #! up to 4 levels) and reports the kernel's errors itself, sends Exec, and re-executes itself from descriptor 3004 with the target as argument; virtual ignored dispositions, the mask and pending signals cross in the supervisor's record.";
const WAIT: &str = "Real call with WNOHANG; nothing ready parks the thread (WaitPark) until a child of the process passes its exit barrier. The status of a death by virtual signal is rewritten from the supervisor's record; resource usage is zero.";
const PGRP: &str = "Process groups and sessions are the kernel's; the supervisor reads them back (getpgid) when it resolves kill(0), kill(-pgid).";
