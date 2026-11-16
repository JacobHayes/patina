//! Randomness, credentials and identity, system information, refused interfaces.
use super::*;

const G: Group = Group::Misc;

/// A syscall number, checked at compile time against the kernel headers' name.
pub(crate) const fn n(nr: u32, name: &str) -> u32 {
    let have = match NAMES[nr as usize] {
        Some(h) => h.as_bytes(),
        None => panic!("number not in the kernel headers"),
    };
    let want = name.as_bytes();
    assert!(have.len() == want.len(), "syscall number and name disagree");
    let mut i = 0;
    while i < have.len() {
        assert!(have[i] == want[i], "syscall number and name disagree");
        i += 1;
    }
    nr
}

const NO_URING: &str = "Known-asynchronous interface: a kernel without io_uring answers ENOSYS and programs fall back.";
const NO_AIO: &str = "POSIX/Linux AIO completes on kernel threads at times the kernel chooses; a kernel without it answers ENOSYS.";
const NO_NOTIFY: &str =
    "File change notification is delivered asynchronously; a kernel without it answers ENOSYS.";
const NO_IPC: &str =
    "System V IPC and POSIX message queues are not offered; a kernel without them answers ENOSYS.";
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

pub const ROWS: &[Row] = &[
    Row::new(G, n(318, "getrandom"), Virt, C, "Bytes from draw(Entropy, seq); flags are ignored and the call never waits.").outs(&[out(0, Len::Ret)]),
    Row::new(G, n(99, "sysinfo"), Virt, C, "Constants: uptime is the virtual clock, 16 GiB total and 12 GiB free memory, no swap, one process, unit 1.").outs(&[out(0, Len::Fixed(112))]),
    Row::new(G, n(98, "getrusage"), Virt, C, "User time is the thread's trap charges; every other field (system time, page faults, context switches, max RSS) is 0.").outs(&[out(1, Len::Fixed(144))]),
    Row::new(G, n(239, "get_mempolicy"), Virt, C, "The default policy with an empty node mask."),
    Row::new(G, n(115, "getgroups"), Virt, C, "The list is the namespace's primary group alone: the launcher's supplementary groups are inherited and cannot be dropped without a capability, and unmapped ones read as the overflow id, so their number would show.").outs(&[out(1, Len::RetTimes(4))]),
    Row::new(G, n(116, "setgroups"), Pass, A, CREDS),
    Row::new(G, n(117, "setresuid"), Pass, A, CREDS),
    Row::new(G, n(118, "getresuid"), Pass, A, CREDS).outs(&[out(0, Len::Fixed(4)), out(1, Len::Fixed(4)), out(2, Len::Fixed(4))]),
    Row::new(G, n(119, "setresgid"), Pass, A, CREDS),
    Row::new(G, n(120, "getresgid"), Pass, A, CREDS).outs(&[out(0, Len::Fixed(4)), out(1, Len::Fixed(4)), out(2, Len::Fixed(4))]),
    Row::new(G, n(105, "setuid"), Pass, A, CREDS),
    Row::new(G, n(106, "setgid"), Pass, A, CREDS),
    Row::new(G, n(113, "setreuid"), Pass, A, CREDS),
    Row::new(G, n(114, "setregid"), Pass, A, CREDS),
    Row::new(G, n(122, "setfsuid"), Pass, A, CREDS),
    Row::new(G, n(123, "setfsgid"), Pass, A, CREDS),
    Row::new(G, n(125, "capget"), Pass, A, "Capabilities are fixed by the user namespace (none for the guest)."),
    Row::new(G, n(126, "capset"), Pass, A, "Capabilities can only be dropped; the result is a function of the call and the fixed starting set."),
    Row::new(G, n(170, "sethostname"), Pass, A, UTS),
    Row::new(G, n(171, "setdomainname"), Pass, A, UTS),
    Row::new(G, n(425, "io_uring_setup"), Deny(errno::ENOSYS), C, NO_URING),
    Row::new(G, n(426, "io_uring_enter"), Deny(errno::ENOSYS), C, NO_URING),
    Row::new(G, n(427, "io_uring_register"), Deny(errno::ENOSYS), C, NO_URING),
    Row::new(G, n(206, "io_setup"), Deny(errno::ENOSYS), C, NO_AIO),
    Row::new(G, n(207, "io_destroy"), Deny(errno::ENOSYS), C, NO_AIO),
    Row::new(G, n(208, "io_getevents"), Deny(errno::ENOSYS), C, NO_AIO),
    Row::new(G, n(209, "io_submit"), Deny(errno::ENOSYS), C, NO_AIO),
    Row::new(G, n(210, "io_cancel"), Deny(errno::ENOSYS), C, NO_AIO),
    Row::new(G, n(333, "io_pgetevents"), Deny(errno::ENOSYS), C, NO_AIO),
    Row::new(G, n(253, "inotify_init"), Deny(errno::ENOSYS), C, NO_NOTIFY),
    Row::new(G, n(294, "inotify_init1"), Deny(errno::ENOSYS), C, NO_NOTIFY),
    Row::new(G, n(254, "inotify_add_watch"), Deny(errno::ENOSYS), C, NO_NOTIFY),
    Row::new(G, n(255, "inotify_rm_watch"), Deny(errno::ENOSYS), C, NO_NOTIFY),
    Row::new(G, n(300, "fanotify_init"), Deny(errno::ENOSYS), C, NO_NOTIFY),
    Row::new(G, n(301, "fanotify_mark"), Deny(errno::ENOSYS), C, NO_NOTIFY),
    Row::new(G, n(29, "shmget"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(30, "shmat"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(31, "shmctl"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(67, "shmdt"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(64, "semget"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(65, "semop"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(66, "semctl"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(220, "semtimedop"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(68, "msgget"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(69, "msgsnd"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(70, "msgrcv"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(71, "msgctl"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(240, "mq_open"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(241, "mq_unlink"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(242, "mq_timedsend"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(243, "mq_timedreceive"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(244, "mq_notify"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(245, "mq_getsetattr"), Deny(errno::ENOSYS), C, NO_IPC),
    Row::new(G, n(248, "add_key"), Deny(errno::ENOSYS), C, NO_KEYS),
    Row::new(G, n(249, "request_key"), Deny(errno::ENOSYS), C, NO_KEYS),
    Row::new(G, n(250, "keyctl"), Deny(errno::ENOSYS), C, NO_KEYS),
    Row::new(G, n(323, "userfaultfd"), Deny(errno::ENOSYS), C, "Page faults served by another thread at times the kernel chooses; not offered."),
    Row::new(G, n(298, "perf_event_open"), Deny(errno::ENOSYS), C, "Hardware counters are not repeatable; not offered."),
    Row::new(G, n(321, "bpf"), Deny(errno::ENOSYS), C, "Kernel programs are host-global; not offered."),
    Row::new(G, n(310, "process_vm_readv"), Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, n(311, "process_vm_writev"), Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, n(312, "kcmp"), Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, n(434, "pidfd_open"), Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, n(424, "pidfd_send_signal"), Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, n(438, "pidfd_getfd"), Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, n(448, "process_mrelease"), Deny(errno::ENOSYS), C, OTHER_PROC),
    Row::new(G, n(303, "name_to_handle_at"), Deny(errno::ENOSYS), C, "File handles carry the filesystem's generation numbers; not offered."),
    Row::new(G, n(304, "open_by_handle_at"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(165, "mount"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(166, "umount2"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(428, "open_tree"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(429, "move_mount"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(430, "fsopen"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(431, "fsconfig"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(432, "fsmount"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(433, "fspick"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(442, "mount_setattr"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(457, "statmount"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(458, "listmount"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(161, "chroot"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(155, "pivot_root"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(272, "unshare"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(308, "setns"), Deny(errno::EPERM), C, MOUNTS),
    Row::new(G, n(135, "personality"), Deny(errno::ENOSYS), C, "The launcher's ADDR_NO_RANDOMIZE persona must not show through (it varies under --vary aslr), and execution domains change kernel behaviour; refused."),
    Row::new(G, n(179, "quotactl"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(443, "quotactl_fd"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(169, "reboot"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(167, "swapon"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(168, "swapoff"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(163, "acct"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(175, "init_module"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(313, "finit_module"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(176, "delete_module"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(246, "kexec_load"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(320, "kexec_file_load"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(172, "iopl"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(173, "ioperm"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(103, "syslog"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(153, "vhangup"), Deny(errno::EPERM), C, PRIV),
    Row::new(G, n(212, "lookup_dcookie"), Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, n(180, "nfsservctl"), Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, n(136, "ustat"), Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, n(139, "sysfs"), Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, n(134, "uselib"), Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, n(174, "create_module"), Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, n(177, "get_kernel_syms"), Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, n(178, "query_module"), Deny(errno::ENOSYS), C, OBSOLETE),
    Row::new(G, n(444, "landlock_create_ruleset"), Deny(errno::ENOSYS), C, "Sandboxing by the guest is not offered; a kernel without Landlock answers ENOSYS."),
    Row::new(G, n(445, "landlock_add_rule"), Deny(errno::ENOSYS), C, "Sandboxing by the guest is not offered."),
    Row::new(G, n(446, "landlock_restrict_self"), Deny(errno::ENOSYS), C, "Sandboxing by the guest is not offered."),
    Row::new(G, n(451, "cachestat"), Deny(errno::ENOSYS), C, "Page-cache residency is host state; a kernel without it answers ENOSYS."),
    Row::new(G, n(459, "lsm_get_self_attr"), Deny(errno::ENOSYS), C, "Security-module attributes are host configuration; not offered."),
    Row::new(G, n(460, "lsm_set_self_attr"), Deny(errno::ENOSYS), C, "Security-module attributes are host configuration; not offered."),
    Row::new(G, n(461, "lsm_list_modules"), Deny(errno::ENOSYS), C, "Security-module attributes are host configuration; not offered."),
    Row::new(G, n(317, "seccomp"), Deny(errno::EPERM), C, "A guest may not change the seccomp filter."),
];
