//! The strace leak filter: which host syscalls a shim-linked scenario binary,
//! run directly under `strace -f`, issued outside the deterministic boundary.
//!
//! Default-deny over every class [`STRACE_EVENTS`] traces: a line survives
//! (is an escape) unless it is the loader prelude, process-local memory or
//! thread-lifecycle bookkeeping, I/O on stdio or a descriptor opened on a
//! trusted loader path, or the ONE signal allowance — the shim's delivery
//! vehicle, which obtains a kernel-built frame by signalling the calling
//! thread itself: `tgkill(pid, tid, …)` / `rt_tgsigqueueinfo(pid, tid, …)` with
//! `pid` the traced process and `tid` the thread issuing the call, or
//! `tkill(tid, …)` with that tid. Target == self, any signal number; never a
//! signal-name list, never a process-directed `kill`/`rt_sigqueueinfo`. A
//! modeled row reaching the host (a `kill`, a `rt_sigpending`, a `signalfd4`)
//! is an escape.

use std::collections::BTreeSet;

/// The `strace -e` expression the leak run traces.
pub const STRACE_EVENTS: &str = concat!(
    "trace=%file,%network,%desc,%memory,%clock,%process,%signal,%ipc,",
    "nanosleep,gettimeofday,futex,rt_sigaction,rt_sigprocmask,rt_sigreturn,",
    "sigaltstack,sched_yield,exit_group,exit,getrandom"
);

/// Process-local rows with no filesystem, network, clock or entropy reach: the
/// loader and allocator, signal-frame bookkeeping, and the rows a managed
/// thread's host `pthread_create` issues.
const PROCESS_LOCAL: &[&str] = &[
    "execve",
    "brk",
    "arch_prctl",
    "mmap",
    "mmap2",
    "munmap",
    "mprotect",
    "madvise",
    "futex",
    "sched_yield",
    "sigaltstack",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "exit",
    "exit_group",
    "close",
    "clone",
    "clone3",
    "set_robust_list",
    "rseq",
    "set_tid_address",
    "gettid",
    "prlimit64",
    "sched_getaffinity",
];

fn trusted_path(args: &str) -> bool {
    let so = args
        .match_indices(".so")
        .any(|(at, _)| matches!(args[at + 3..].chars().next(), None | Some('.' | '"')));
    so || args.contains("\"/etc/ld.so.cache\"")
        || args.contains("\"/etc/ld.so.preload\"")
        || args.contains("\"/proc/self/maps\"")
}

fn leading_fd(args: &str) -> Option<&str> {
    let end = args
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(args.len());
    (end > 0).then(|| &args[..end])
}

fn self_directed(name: &str, args: &str, pid: &str, caller: &str) -> bool {
    let parts: Vec<&str> = args.split(',').map(str::trim).collect();
    match name {
        "tgkill" | "rt_tgsigqueueinfo" => parts.len() >= 3 && parts[0] == pid && parts[1] == caller,
        "tkill" => parts.len() >= 2 && parts[0] == caller,
        _ => false,
    }
}

/// The escaped calls in `strace -f` output (each line as strace wrote it,
/// without the pid prefix). Empty means the run stayed inside the boundary.
pub fn escapes(strace: &str) -> Vec<String> {
    let mut pid = String::new();
    let mut trusted: BTreeSet<String> = BTreeSet::new();
    let mut escaped = Vec::new();
    for raw in strace.lines() {
        let (caller, line) = match raw.split_once(' ') {
            Some((prefix, rest)) if prefix.chars().all(|c| c.is_ascii_digit()) => {
                (prefix.to_string(), rest.trim_start())
            }
            _ => (String::new(), raw),
        };
        if pid.is_empty() && line.starts_with("execve(") {
            pid.clone_from(&caller);
        }
        if line.starts_with("--- ") || line.starts_with("+++ ") || line.starts_with("<... ") {
            // Signal deliveries and exits are not calls; a call split across two
            // lines by a concurrent thread is judged on its `unfinished` half,
            // and the `resumed` half carries only the return value.
            continue;
        }
        let line = match line.strip_suffix(" <unfinished ...>") {
            Some(head) => format!("{head})"),
            None => line.to_string(),
        };
        let Some((name, rest)) = line.split_once('(') else {
            escaped.push(line);
            continue;
        };
        let args = rest;
        let returned = line
            .rsplit_once('=')
            .map(|(_, value)| value.trim())
            .and_then(leading_fd);
        if matches!(name, "openat" | "openat2" | "open") && trusted_path(args) {
            if let Some(fd) = returned {
                trusted.insert(fd.to_string());
            }
        }
        if name == "close" {
            if let Some(fd) = leading_fd(args) {
                trusted.remove(fd);
            }
        }
        if PROCESS_LOCAL.contains(&name) {
            continue;
        }
        if matches!(name, "tgkill" | "tkill" | "rt_tgsigqueueinfo")
            && self_directed(name, args, &pid, &caller)
        {
            continue;
        }
        if name == "getrandom" && args.contains("GRND_NONBLOCK") {
            continue;
        }
        if matches!(
            name,
            "openat" | "openat2" | "open" | "newfstatat" | "readlink" | "readlinkat"
        ) && trusted_path(args)
        {
            continue;
        }
        if matches!(name, "faccessat" | "faccessat2" | "access")
            && args.contains("\"/etc/ld.so.preload\"")
        {
            continue;
        }
        if matches!(name, "read" | "pread64" | "fstat" | "fcntl" | "lseek") {
            if let Some(fd) = leading_fd(args) {
                if matches!(fd, "0" | "1" | "2" | "3") || trusted.contains(fd) {
                    continue;
                }
            }
        }
        if name == "write"
            && args.len() >= 2
            && matches!(&args[..1], "0" | "1" | "2" | "3")
            && matches!(&args[1..2], "," | ")")
        {
            continue;
        }
        escaped.push(line);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::escapes;

    fn calls(escaped: Vec<String>) -> Vec<String> {
        escaped
            .into_iter()
            .map(|line| match line.rsplit_once(" = ") {
                Some((call, _)) => call.trim_end().to_string(),
                None => line,
            })
            .collect()
    }

    #[test]
    fn a_host_file_open_escapes() {
        let trace = "4242 execve(\"/x/probe\", [\"/x/probe\"], 0x7ffd /* 3 vars */) = 0\n\
                     4242 openat(AT_FDCWD, \"/etc/hostname\", O_RDONLY) = 3\n\
                     4242 exit_group(0)                        = ?\n";
        assert_eq!(
            calls(escapes(trace)),
            ["openat(AT_FDCWD, \"/etc/hostname\", O_RDONLY)"]
        );
    }

    #[test]
    fn the_loader_prelude_stays_inside() {
        let trace = "4242 execve(\"/x/probe\", [\"/x/probe\"], 0x7ffd /* 3 vars */) = 0\n\
                     4242 openat(AT_FDCWD, \"/etc/ld.so.cache\", O_RDONLY|O_CLOEXEC) = 3\n\
                     4242 fstat(3, {st_mode=S_IFREG|0644, st_size=1}) = 0\n\
                     4242 close(3)                             = 0\n\
                     4242 openat(AT_FDCWD, \"/lib/x86_64-linux-gnu/libc.so.6\", O_RDONLY|O_CLOEXEC) = 3\n\
                     4242 read(3, \"\\177ELF\", 832)           = 832\n\
                     4242 close(3)                             = 0\n\
                     4242 write(1, \"{}\\n\", 3)                 = 3\n\
                     4242 exit_group(0)                        = ?\n";
        assert!(escapes(trace).is_empty(), "{:?}", escapes(trace));
    }

    #[test]
    fn a_read_on_a_closed_trusted_descriptor_escapes() {
        let trace = "4242 execve(\"/x/probe\", [\"/x/probe\"], 0x7ffd /* 3 vars */) = 0\n\
                     4242 openat(AT_FDCWD, \"/etc/ld.so.cache\", O_RDONLY|O_CLOEXEC) = 7\n\
                     4242 close(7)                             = 0\n\
                     4242 read(7, \"x\", 1)                     = 1\n";
        assert_eq!(calls(escapes(trace)), ["read(7, \"x\", 1)"]);
    }

    /// The self-signal allowance is exactly "to the calling thread": the
    /// synthetic lines are the ones the shim's delivery vehicle and the
    /// modeled rows produce.
    #[test]
    fn only_signals_to_the_calling_thread_stay_inside() {
        let trace = r#"4242 execve("/x/probe", ["/x/probe"], 0x7ffd /* 3 vars */) = 0
4242 tgkill(4242, 4242, SIGUSR1)          = 0
4242 --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_TKILL, si_pid=4242, si_uid=1000} ---
4242 rt_sigreturn({mask=[]})              = 0
4243 tgkill(4242, 4243, SIGRT_3)          = 0
4243 tkill(4243, SIGTERM)                 = 0
4243 rt_tgsigqueueinfo(4242, 4243, SIGUSR2, {si_signo=SIGUSR2, si_code=SI_QUEUE, si_pid=1, si_uid=1000}) = 0
4242 tgkill(4242, 4243, SIGUSR1)          = 0
4242 tgkill(4243, 4243, SIGUSR1)          = 0
4243 tkill(4242, SIGUSR1)                 = 0
4242 kill(4242, SIGUSR1)                  = 0
4242 rt_sigqueueinfo(4242, SIGUSR1, {si_signo=SIGUSR1, si_code=SI_QUEUE, si_pid=1, si_uid=1000}) = 0
4242 rt_sigpending([], 8)                 = 0
4242 signalfd4(-1, [USR1], 8, SFD_NONBLOCK) = 5
4242 exit_group(0)                        = ?
"#;
        assert_eq!(
            calls(escapes(trace)),
            [
                "tgkill(4242, 4243, SIGUSR1)",
                "tgkill(4243, 4243, SIGUSR1)",
                "tkill(4242, SIGUSR1)",
                "kill(4242, SIGUSR1)",
                "rt_sigqueueinfo(4242, SIGUSR1, {si_signo=SIGUSR1, si_code=SI_QUEUE, si_pid=1, si_uid=1000})",
                "rt_sigpending([], 8)",
                "signalfd4(-1, [USR1], 8, SFD_NONBLOCK)",
            ]
        );
    }

    #[test]
    fn an_unfinished_call_is_judged_on_its_arguments() {
        let trace = "4242 execve(\"/x/probe\", [\"/x/probe\"], 0x7ffd /* 3 vars */) = 0\n\
                     4243 openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY <unfinished ...>\n\
                     4242 <... openat resumed>)                 = 3\n";
        assert_eq!(
            calls(escapes(trace)),
            ["openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY)"]
        );
    }
}
