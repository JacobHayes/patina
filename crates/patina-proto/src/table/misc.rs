//! Randomness, credentials and identity, system information, refused interfaces.
use super::*;

const G: Group = Group::Misc;

const NO_URING: &str = "Known-asynchronous interface: a kernel without io_uring answers ENOSYS and programs fall back.";
const NO_AIO: &str = "POSIX/Linux AIO completes on kernel threads at times the kernel chooses; a kernel without it answers ENOSYS.";
const NO_NOTIFY: &str =
    "File change notification is delivered asynchronously; a kernel without it answers ENOSYS.";
const NO_IPC: &str =
    "System V semaphores and message queues and POSIX message queues are not offered; a kernel without them answers ENOSYS (System V shared memory is offered).";
const NO_KEYS: &str =
    "Kernel keyrings are host-global state; a kernel without them answers ENOSYS.";
const PRIV: &str =
    "Privileged host operation; the sandbox has no capabilities, so the kernel would answer EPERM.";
const MOUNTS: &str = "Mounts and namespaces belong to the sandbox, not the guest; answered EPERM as for an unprivileged process.";
const OTHER_PROC: &str =
    "Reaches into another process or the kernel's object identity; not offered (ENOSYS).";
const OBSOLETE: &str = "Obsolete or removed interface; a current kernel answers ENOSYS.";
const CREDS: &str = "Fixed by the user namespace mapping (the guest has no capabilities, so changes other than to the same ids fail as the kernel decides).";
const UTS: &str = "Changes the UTS namespace of the sandbox (the guest has no capability, so the kernel answers EPERM).";

/// `capget`, `capset`: the header (version, pid) and the data records (`_LINUX_CAPABILITY_VERSION_3`: two).
const CAPS: &[Out] = &[out(0, Len::Fixed(8)), out(1, Len::Fixed(24))];

pub const ROWS: &[Row] = &[
    Row::new(G, nr::GETRANDOM, Virt, C, "Bytes from draw(Entropy, seq); flags are ignored and the call never waits.").outs(&[out(0, Len::Ret { max: 1 })]),
    Row::new(G, nr::SYSINFO, Virt, C, "Constants: uptime is the virtual clock, 16 GiB total and 12 GiB free memory, no swap, one process, unit 1.").outs(&[out(0, Len::Fixed(112))]),
    Row::new(G, nr::GETRUSAGE, Virt, C, "User time is the thread's trap charges; every other field (system time, page faults, context switches, max RSS) is 0.").outs(&[out(1, Len::Fixed(144))]),
    Row::new(G, nr::GET_MEMPOLICY, Virt, C, "The default policy with an empty machine mask."),
    Row::new(G, nr::GETGROUPS, Virt, C, "The list is the namespace's primary group alone: the launcher's supplementary groups are inherited and cannot be dropped without a capability, and unmapped ones read as the overflow id, so their number would show.").outs(&[out(1, Len::RetTimes { max: 0, size: 4 })]),
    Row::new(G, nr::SETGROUPS, Pass, A, CREDS).refs(&[out(1, Len::ArgTimes { arg: 0, size: 4 })]),
    Row::new(G, nr::SETRESUID, Pass, A, CREDS),
    Row::new(G, nr::GETRESUID, Pass, A, CREDS).outs(&[out(0, Len::Fixed(4)), out(1, Len::Fixed(4)), out(2, Len::Fixed(4))]),
    Row::new(G, nr::SETRESGID, Pass, A, CREDS),
    Row::new(G, nr::GETRESGID, Pass, A, CREDS).outs(&[out(0, Len::Fixed(4)), out(1, Len::Fixed(4)), out(2, Len::Fixed(4))]),
    Row::new(G, nr::SETUID, Pass, A, CREDS),
    Row::new(G, nr::SETGID, Pass, A, CREDS),
    Row::new(G, nr::SETREUID, Pass, A, CREDS),
    Row::new(G, nr::SETREGID, Pass, A, CREDS),
    Row::new(G, nr::SETFSUID, Pass, A, CREDS),
    Row::new(G, nr::SETFSGID, Pass, A, CREDS),
    Row::new(G, nr::CAPGET, Pass, A, "Capabilities are fixed by the user namespace (none for the guest).").refs(CAPS),
    Row::new(G, nr::CAPSET, Pass, A, "Capabilities can only be dropped; the result is a function of the call and the fixed starting set.").refs(CAPS),
    Row::new(G, nr::SETHOSTNAME, Pass, A, UTS).refs(&[out(0, Len::Arg(1))]),
    Row::new(G, nr::SETDOMAINNAME, Pass, A, UTS).refs(&[out(0, Len::Arg(1))]),
    Row::new(G, nr::IO_URING_SETUP, Deny(errno::ENOSYS), C, NO_URING),
    Row::new(G, nr::IO_URING_ENTER, Deny(errno::ENOSYS), C, NO_URING),
    Row::new(G, nr::IO_URING_REGISTER, Deny(errno::ENOSYS), C, NO_URING),
    Row::new(G, nr::IO_SETUP, Deny(errno::ENOSYS), C, NO_AIO),
    Row::new(G, nr::IO_DESTROY, Deny(errno::ENOSYS), C, NO_AIO),
    Row::new(G, nr::IO_GETEVENTS, Deny(errno::ENOSYS), C, NO_AIO),
    Row::new(G, nr::IO_SUBMIT, Deny(errno::ENOSYS), C, NO_AIO),
    Row::new(G, nr::IO_CANCEL, Deny(errno::ENOSYS), C, NO_AIO),
    Row::new(G, nr::IO_PGETEVENTS, Deny(errno::ENOSYS), C, NO_AIO),
    Row::new(G, nr::INOTIFY_INIT, Deny(errno::ENOSYS), C, NO_NOTIFY),
    Row::new(G, nr::INOTIFY_INIT1, Deny(errno::ENOSYS), C, NO_NOTIFY),
    Row::new(G, nr::INOTIFY_ADD_WATCH, Deny(errno::ENOSYS), C, NO_NOTIFY),
    Row::new(G, nr::INOTIFY_RM_WATCH, Deny(errno::ENOSYS), C, NO_NOTIFY),
    Row::new(G, nr::FANOTIFY_INIT, Deny(errno::ENOSYS), C, NO_NOTIFY),
    Row::new(G, nr::FANOTIFY_MARK, Deny(errno::ENOSYS), C, NO_NOTIFY),
    Row::new(G, nr::SEMGET, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::SEMOP, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::SEMCTL, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::SEMTIMEDOP, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::MSGGET, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::MSGSND, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::MSGRCV, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::MSGCTL, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::MQ_OPEN, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::MQ_UNLINK, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::MQ_TIMEDSEND, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::MQ_TIMEDRECEIVE, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::MQ_NOTIFY, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::MQ_GETSETATTR, Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, nr::ADD_KEY, Deny(errno::ENOSYS), C, NO_KEYS),
    Row::new(G, nr::REQUEST_KEY, Deny(errno::ENOSYS), C, NO_KEYS),
    Row::new(G, nr::KEYCTL, Deny(errno::ENOSYS), C, NO_KEYS),
    Row::new(G, nr::USERFAULTFD, Deny(errno::ENOSYS), C, "Page faults served by another thread at times the kernel chooses; not offered."),
    Row::new(G, nr::PERF_EVENT_OPEN, Deny(errno::ENOSYS), C, "Hardware counters are not repeatable; not offered."),
    Row::new(G, nr::BPF, Deny(errno::ENOSYS), C, "Kernel programs are host-global; not offered."),
    Row::new(G, nr::PROCESS_VM_READV, Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, nr::PROCESS_VM_WRITEV, Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, nr::KCMP, Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, nr::PIDFD_OPEN, Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, nr::PIDFD_SEND_SIGNAL, Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, nr::PIDFD_GETFD, Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, nr::PROCESS_MRELEASE, Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, nr::NAME_TO_HANDLE_AT, Deny(errno::ENOSYS), C, "File handles carry the filesystem's generation numbers; not offered."),
    Row::new(G, nr::OPEN_BY_HANDLE_AT, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::MOUNT, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::UMOUNT2, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::OPEN_TREE, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::MOVE_MOUNT, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::FSOPEN, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::FSCONFIG, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::FSMOUNT, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::FSPICK, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::MOUNT_SETATTR, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::STATMOUNT, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::LISTMOUNT, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::CHROOT, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::PIVOT_ROOT, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::UNSHARE, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::SETNS, Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, nr::PERSONALITY, Deny(errno::ENOSYS), C, "The launcher's ADDR_NO_RANDOMIZE persona must not show through (it varies under --vary aslr), and execution domains change kernel behaviour; refused."),
    Row::new(G, nr::QUOTACTL, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::QUOTACTL_FD, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::REBOOT, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::SWAPON, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::SWAPOFF, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::ACCT, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::INIT_MODULE, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::FINIT_MODULE, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::DELETE_MODULE, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::KEXEC_LOAD, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::KEXEC_FILE_LOAD, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::IOPL, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::IOPERM, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::SYSLOG, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::VHANGUP, Deny(errno::EPERM), C, PRIV),
    Row::new(G, nr::LOOKUP_DCOOKIE, Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, nr::NFSSERVCTL, Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, nr::USTAT, Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, nr::SYSFS, Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, nr::USELIB, Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, nr::CREATE_MODULE, Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, nr::GET_KERNEL_SYMS, Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, nr::QUERY_MODULE, Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, nr::LANDLOCK_CREATE_RULESET, Deny(errno::ENOSYS), C, "Sandboxing by the guest is not offered; a kernel without Landlock answers ENOSYS."),
    Row::new(G, nr::LANDLOCK_ADD_RULE, Deny(errno::ENOSYS), C, "Sandboxing by the guest is not offered."),
    Row::new(G, nr::LANDLOCK_RESTRICT_SELF, Deny(errno::ENOSYS), C, "Sandboxing by the guest is not offered."),
    Row::new(G, nr::CACHESTAT, Deny(errno::ENOSYS), C, "Page-cache residency is host state; a kernel without it answers ENOSYS."),
    Row::new(G, nr::LSM_GET_SELF_ATTR, Deny(errno::ENOSYS), C, "Security-module attributes are host configuration; not offered."),
    Row::new(G, nr::LSM_SET_SELF_ATTR, Deny(errno::ENOSYS), C, "Security-module attributes are host configuration; not offered."),
    Row::new(G, nr::LSM_LIST_MODULES, Deny(errno::ENOSYS), C, "Security-module attributes are host configuration; not offered."),
    Row::new(G, nr::SECCOMP, Deny(errno::EPERM), C, "A guest may not change the seccomp filter."),
];
