//! Scenario entry tests and their one-test-per-catalog-entry coverage detector.

#[cfg(test)]
mod tests {
    use crate::conform;
    use patina_dst_conformance::catalog;

    #[test]
    fn every_scenario_has_one_test() {
        let source = include_str!("native_conformance.rs");
        for scenario in catalog::SCENARIOS {
            let call = format!("conform(\"{}\");", scenario.name);
            assert_eq!(
                source.matches(&call).count(),
                1,
                "{} needs exactly one test calling {call}",
                scenario.name
            );
        }
    }

    #[test]
    fn abi_newer_than_virtual() {
        conform("abi/newer_than_virtual");
    }

    #[test]
    fn asyncio_aio() {
        conform("asyncio/aio");
    }

    #[test]
    fn asyncio_io_uring() {
        conform("asyncio/io_uring");
    }

    #[test]
    fn cred_caps() {
        conform("cred/caps");
    }

    #[test]
    fn cred_groups() {
        conform("cred/groups");
    }

    #[test]
    fn cred_ids() {
        conform("cred/ids");
    }

    #[test]
    fn entropy_getentropy() {
        conform("entropy/getentropy");
    }

    #[test]
    fn entropy_getentropy_fault() {
        conform("entropy/getentropy_fault");
    }

    #[test]
    fn entropy_getrandom() {
        conform("entropy/getrandom");
    }

    #[test]
    fn entropy_urandom() {
        conform("entropy/urandom");
    }

    #[test]
    fn fd_anon_inode() {
        conform("fd/anon_inode");
    }

    #[test]
    fn fd_pipes() {
        conform("fd/pipes");
    }

    #[test]
    fn fd_pty() {
        conform("fd/pty");
    }

    #[test]
    fn fd_stdio() {
        conform("fd/stdio");
    }

    #[test]
    fn fd_table() {
        conform("fd/table");
    }

    #[test]
    fn fd_termios() {
        conform("fd/termios");
    }

    #[test]
    fn fs_cache() {
        conform("fs/cache");
    }

    #[test]
    fn fs_chmod() {
        conform("fs/chmod");
    }

    #[test]
    fn fs_copy() {
        conform("fs/copy");
    }

    #[test]
    fn fs_dirent() {
        conform("fs/dirent");
    }

    #[test]
    fn fs_fifo() {
        conform("fs/fifo");
    }

    #[test]
    fn fs_fortify() {
        conform("fs/fortify");
    }

    #[test]
    fn fs_getdents() {
        conform("fs/getdents");
    }

    #[test]
    fn fs_handles() {
        conform("fs/handles");
    }

    #[test]
    fn fs_inotify() {
        conform("fs/inotify");
    }

    #[test]
    fn fs_ioctl() {
        conform("fs/ioctl");
    }

    #[test]
    fn fs_legacy_paths() {
        conform("fs/legacy_paths");
    }

    #[test]
    fn fs_lfs64() {
        conform("fs/lfs64");
    }

    #[test]
    fn fs_libc_io() {
        conform("fs/libc_io");
    }

    #[test]
    fn fs_libc_times() {
        conform("fs/libc_times");
    }

    #[test]
    fn fs_metadata() {
        conform("fs/metadata");
    }

    #[test]
    fn fs_mount() {
        conform("fs/mount");
    }

    #[test]
    fn fs_mount_api() {
        conform("fs/mount_api");
    }

    #[test]
    fn fs_mount_query() {
        conform("fs/mount_query");
    }

    #[test]
    fn fs_names() {
        conform("fs/names");
    }

    #[test]
    fn fs_open_tree() {
        conform("fs/open_tree");
    }

    #[test]
    fn fs_openat2() {
        conform("fs/openat2");
    }

    #[test]
    fn fs_owner() {
        conform("fs/owner");
    }

    #[test]
    fn fs_paths() {
        conform("fs/paths");
    }

    #[test]
    fn fs_posix_fadvise() {
        conform("fs/posix_fadvise");
    }

    #[test]
    fn fs_realpath() {
        conform("fs/realpath");
    }

    #[test]
    fn fs_renameat2() {
        conform("fs/renameat2");
    }

    #[test]
    fn fs_rw() {
        conform("fs/rw");
    }

    #[test]
    fn fs_size() {
        conform("fs/size");
    }

    #[test]
    fn fs_sparse() {
        conform("fs/sparse");
    }

    #[test]
    fn fs_splice() {
        conform("fs/splice");
    }

    #[test]
    fn fs_statfs() {
        conform("fs/statfs");
    }

    #[test]
    fn fs_statvfs() {
        conform("fs/statvfs");
    }

    #[test]
    fn fs_sync() {
        conform("fs/sync");
    }

    #[test]
    fn fs_times() {
        conform("fs/times");
    }

    #[test]
    fn fs_vectored_io() {
        conform("fs/vectored_io");
    }

    #[test]
    fn fs_xattr() {
        conform("fs/xattr");
    }

    #[test]
    fn ipc_mqueue() {
        conform("ipc/mqueue");
    }

    #[test]
    fn ipc_sysv_msg() {
        conform("ipc/sysv_msg");
    }

    #[test]
    fn ipc_sysv_sem() {
        conform("ipc/sysv_sem");
    }

    #[test]
    fn ipc_sysv_shm() {
        conform("ipc/sysv_shm");
    }

    #[test]
    fn mem_brk() {
        conform("mem/brk");
    }

    #[test]
    fn mem_membarrier() {
        conform("mem/membarrier");
    }

    #[test]
    fn mem_memfd() {
        conform("mem/memfd");
    }

    #[test]
    fn mem_mincore() {
        conform("mem/mincore");
    }

    #[test]
    fn mem_mlock() {
        conform("mem/mlock");
    }

    #[test]
    fn mem_mmap() {
        conform("mem/mmap");
    }

    #[test]
    fn mem_mmap_file() {
        conform("mem/mmap_file");
    }

    #[test]
    fn mem_mremap() {
        conform("mem/mremap");
    }

    #[test]
    fn mem_msync() {
        conform("mem/msync");
    }

    #[test]
    fn mem_numa() {
        conform("mem/numa");
    }

    #[test]
    fn mem_pkeys() {
        conform("mem/pkeys");
    }

    #[test]
    fn mem_process_madvise() {
        conform("mem/process_madvise");
    }

    #[test]
    fn mem_protect() {
        conform("mem/protect");
    }

    #[test]
    fn mem_remap_file_pages() {
        conform("mem/remap_file_pages");
    }

    #[test]
    fn mem_secret() {
        conform("mem/secret");
    }

    #[test]
    fn mem_shadow_stack() {
        conform("mem/shadow_stack");
    }

    #[test]
    fn mem_userfaultfd() {
        conform("mem/userfaultfd");
    }

    #[test]
    fn net_fortify() {
        conform("net/fortify");
    }

    #[test]
    fn net_getaddrinfo() {
        conform("net/getaddrinfo");
    }

    #[test]
    fn net_getifaddrs() {
        conform("net/getifaddrs");
    }

    #[test]
    fn net_ifconfig() {
        conform("net/ifconfig");
    }

    #[test]
    fn net_inet6() {
        conform("net/inet6");
    }

    #[test]
    fn net_inet6_mapped() {
        conform("net/inet6_mapped");
    }

    #[test]
    fn net_ipctl() {
        conform("net/ipctl");
    }

    #[test]
    fn net_ipopts() {
        conform("net/ipopts");
    }

    #[test]
    fn net_mmsg() {
        conform("net/mmsg");
    }

    #[test]
    fn net_msg() {
        conform("net/msg");
    }

    #[test]
    fn net_netlink() {
        conform("net/netlink");
    }

    #[test]
    fn net_pending() {
        conform("net/pending");
    }

    #[test]
    fn net_privileged() {
        conform("net/privileged");
    }

    #[test]
    fn net_scm() {
        conform("net/scm");
    }

    #[test]
    fn net_sockopt() {
        conform("net/sockopt");
    }

    #[test]
    fn net_sockopt_fault() {
        conform("net/sockopt_fault");
    }

    #[test]
    fn net_tcp() {
        conform("net/tcp");
    }

    #[test]
    fn net_udp() {
        conform("net/udp");
    }

    #[test]
    fn net_unix_dgram() {
        conform("net/unix_dgram");
    }

    #[test]
    fn net_unix_seqpacket() {
        conform("net/unix_seqpacket");
    }

    #[test]
    fn net_unix_stream() {
        conform("net/unix_stream");
    }

    #[test]
    fn proc_absent() {
        conform("proc/absent");
    }

    #[test]
    fn proc_dl() {
        conform("proc/dl");
    }

    #[test]
    fn proc_environ() {
        conform("proc/environ");
    }

    #[test]
    fn proc_exec() {
        conform("proc/exec");
    }

    #[test]
    fn proc_exit() {
        conform("proc/exit");
    }

    #[test]
    fn proc_ids() {
        conform("proc/ids");
    }

    #[test]
    fn proc_kcmp() {
        conform("proc/kcmp");
    }

    #[test]
    fn proc_namespaces() {
        conform("proc/namespaces");
    }

    #[test]
    fn proc_pidfd() {
        conform("proc/pidfd");
    }

    #[test]
    fn proc_pidfd_spawn() {
        conform("proc/pidfd_spawn");
    }

    #[test]
    fn proc_prctl() {
        conform("proc/prctl");
    }

    #[test]
    fn proc_ptrace() {
        conform("proc/ptrace");
    }

    #[test]
    fn proc_seccomp() {
        conform("proc/seccomp");
    }

    #[test]
    fn proc_spawn() {
        conform("proc/spawn");
    }

    #[test]
    fn proc_traps() {
        conform("proc/traps");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn proc_vfork() {
        conform("proc/vfork");
    }

    #[test]
    fn proc_vm_rw() {
        conform("proc/vm_rw");
    }

    #[test]
    fn proc_wait() {
        conform("proc/wait");
    }

    #[test]
    fn readiness_epoll() {
        conform("readiness/epoll");
    }

    #[test]
    fn readiness_epoll_edges() {
        conform("readiness/epoll_edges");
    }

    #[test]
    fn readiness_fanotify() {
        conform("readiness/fanotify");
    }

    #[test]
    fn readiness_inotify() {
        conform("readiness/inotify");
    }

    #[test]
    fn readiness_poll() {
        conform("readiness/poll");
    }

    #[test]
    fn readiness_poll_fault() {
        conform("readiness/poll_fault");
    }

    #[test]
    fn readiness_select() {
        conform("readiness/select");
    }

    #[test]
    fn sched_affinity() {
        conform("sched/affinity");
    }

    #[test]
    fn sched_attr() {
        conform("sched/attr");
    }

    #[test]
    fn sched_ioprio() {
        conform("sched/ioprio");
    }

    #[test]
    fn sched_policy() {
        conform("sched/policy");
    }

    #[test]
    fn sched_priority() {
        conform("sched/priority");
    }

    #[test]
    fn signal_abort() {
        conform("signal/abort");
    }

    #[test]
    fn signal_altstack() {
        conform("signal/altstack");
    }

    #[test]
    fn signal_basic() {
        conform("signal/basic");
    }

    #[test]
    fn signal_block() {
        conform("signal/block");
    }

    #[test]
    fn signal_core_term() {
        conform("signal/core_term");
    }

    #[test]
    fn signal_default() {
        conform("signal/default");
    }

    #[test]
    fn signal_describe() {
        conform("signal/describe");
    }

    #[test]
    fn signal_eintr() {
        conform("signal/eintr");
    }

    #[test]
    fn signal_fault() {
        conform("signal/fault");
    }

    #[test]
    fn signal_handler_flags() {
        conform("signal/handler_flags");
    }

    #[test]
    fn signal_mask() {
        conform("signal/mask");
    }

    #[test]
    fn signal_one_wake() {
        conform("signal/one_wake");
    }

    #[test]
    fn signal_per_thread() {
        conform("signal/per_thread");
    }

    #[test]
    fn signal_pipe_term() {
        conform("signal/pipe_term");
    }

    #[test]
    fn signal_queue() {
        conform("signal/queue");
    }

    #[test]
    fn signal_raw_action() {
        conform("signal/raw_action");
    }

    #[test]
    fn signal_restart() {
        conform("signal/restart");
    }

    #[test]
    fn signal_restorer() {
        conform("signal/restorer");
    }

    #[test]
    fn signal_wait() {
        conform("signal/wait");
    }

    #[test]
    fn signal_wrappers() {
        conform("signal/wrappers");
    }

    #[test]
    fn sys_admin() {
        conform("sys/admin");
    }

    #[test]
    fn sys_bpf() {
        conform("sys/bpf");
    }

    #[test]
    fn sys_hostname() {
        conform("sys/hostname");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_ioport() {
        conform("sys/ioport");
    }

    #[test]
    fn sys_keys() {
        conform("sys/keys");
    }

    #[test]
    fn sys_keys_session() {
        conform("sys/keys_session");
    }

    #[test]
    fn sys_landlock() {
        conform("sys/landlock");
    }

    #[test]
    fn sys_lsm() {
        conform("sys/lsm");
    }

    #[test]
    fn sys_nss() {
        conform("sys/nss");
    }

    #[test]
    fn sys_perf() {
        conform("sys/perf");
    }

    #[test]
    fn sys_personality() {
        conform("sys/personality");
    }

    #[test]
    fn sys_quota() {
        conform("sys/quota");
    }

    #[test]
    fn sys_rlimit() {
        conform("sys/rlimit");
    }

    #[test]
    fn sys_rlimit64() {
        conform("sys/rlimit64");
    }

    #[test]
    fn sys_root() {
        conform("sys/root");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_sysfs() {
        conform("sys/sysfs");
    }

    #[test]
    fn sys_sysinfo() {
        conform("sys/sysinfo");
    }

    #[test]
    fn sys_uname() {
        conform("sys/uname");
    }

    #[test]
    fn thread_cond() {
        conform("thread/cond");
    }

    #[test]
    fn thread_exit() {
        conform("thread/exit");
    }

    #[test]
    fn thread_futex() {
        conform("thread/futex");
    }

    #[test]
    fn thread_futex2() {
        conform("thread/futex2");
    }

    #[test]
    fn thread_lifecycle() {
        conform("thread/lifecycle");
    }

    #[test]
    fn thread_main_exit() {
        conform("thread/main_exit");
    }

    #[test]
    fn thread_mutex() {
        conform("thread/mutex");
    }

    #[test]
    fn thread_pthread_kill() {
        conform("thread/pthread_kill");
    }

    #[test]
    fn thread_robust_list() {
        conform("thread/robust_list");
    }

    #[test]
    fn thread_rseq() {
        conform("thread/rseq");
    }

    #[test]
    fn thread_rwlock() {
        conform("thread/rwlock");
    }

    #[test]
    fn thread_tid_clear() {
        conform("thread/tid_clear");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn thread_tls() {
        conform("thread/tls");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn thread_tls_cpu() {
        conform("thread/tls_cpu");
    }

    #[test]
    fn time_clock_res() {
        conform("time/clock_res");
    }

    #[test]
    fn time_clock_set() {
        conform("time/clock_set");
    }

    #[test]
    fn time_clocks() {
        conform("time/clocks");
    }

    #[test]
    fn time_cputime() {
        conform("time/cputime");
    }

    #[test]
    fn time_fault() {
        conform("time/fault");
    }

    #[test]
    fn time_itimer() {
        conform("time/itimer");
    }

    #[test]
    fn time_libc_clocks() {
        conform("time/libc_clocks");
    }

    #[test]
    fn time_libc_fault() {
        conform("time/libc_fault");
    }

    #[test]
    fn time_localtime() {
        conform("time/localtime");
    }

    #[test]
    fn time_posix_timer() {
        conform("time/posix_timer");
    }

    #[test]
    fn time_timerfd() {
        conform("time/timerfd");
    }

    #[test]
    fn time_timerfd_fault() {
        conform("time/timerfd_fault");
    }
}
