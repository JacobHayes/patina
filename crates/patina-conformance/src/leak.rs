//! The strace leak filter: which host syscalls a shim-linked scenario binary,
//! run directly under `strace -f`, issued outside the deterministic boundary.
//!
//! Default-deny over every class [`STRACE_EVENTS`] traces: a call survives
//! (is an escape) unless it is the loader prelude, process-local memory or
//! thread-lifecycle bookkeeping, I/O on stdio or a descriptor opened on a
//! trusted loader path, or the ONE signal allowance — the shim's delivery
//! vehicle, which obtains a kernel-built frame by signalling the calling
//! thread itself: `tgkill(pid, tid, …)` / `rt_tgsigqueueinfo(pid, tid, …)` with
//! `pid` the traced process and `tid` the thread issuing the call, or
//! `tkill(tid, …)` with that tid. Target == self, any signal number; never a
//! signal-name list, never a process-directed `kill`/`rt_sigqueueinfo`. A
//! modeled row reaching the host (a `kill`, a `rt_sigpending`, a `signalfd4`)
//! is an escape. strace's `???` for a thread killed at its syscall-entry stop
//! is not a call: the kernel aborted it (see `Filter::judge`).

use std::collections::{BTreeMap, BTreeSet};

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

/// The escaped calls in `strace -f` output (each call as strace wrote it,
/// without the pid prefix). Empty means the run stayed inside the boundary.
///
/// A call another thread's output split into `NAME(args <unfinished ...>` and
/// `<... NAME resumed>rest` is rejoined per thread and judged whole, with its
/// return value. A call its thread never returned from (the thread's `+++`
/// line or the end of the log arrives first) is judged on its arguments. A
/// resumed half with no matching unfinished half is an escape: nothing that
/// strace wrote goes unjudged.
pub fn escapes(strace: &str) -> Vec<String> {
    let mut filter = Filter::default();
    let mut unfinished: BTreeMap<String, String> = BTreeMap::new();
    for raw in strace.lines() {
        let (caller, line) = match raw.split_once(' ') {
            Some((prefix, rest)) if prefix.chars().all(|c| c.is_ascii_digit()) => {
                (prefix.to_string(), rest.trim_start())
            }
            _ => (String::new(), raw),
        };
        if filter.pid.is_empty() && line.starts_with("execve(") {
            filter.pid.clone_from(&caller);
        }
        if line.starts_with("--- ") {
            // A signal delivery, not a call.
            continue;
        }
        if line.starts_with("+++ ") {
            if let Some(head) = unfinished.remove(&caller) {
                filter.judge(&caller, format!("{head})"), true);
            }
            continue;
        }
        let line = match line.strip_prefix("<... ") {
            Some(resumed) => match rejoin(resumed, unfinished.remove(&caller)) {
                Some(call) => call,
                None => {
                    filter.escaped.push(line.to_string());
                    continue;
                }
            },
            None => line.to_string(),
        };
        if let Some(head) = line.strip_suffix(" <unfinished ...>") {
            if let Some(earlier) = unfinished.insert(caller.clone(), head.to_string()) {
                filter.judge(&caller, format!("{earlier})"), false);
            }
            continue;
        }
        filter.judge(&caller, line, false);
    }
    for (caller, head) in unfinished {
        filter.judge(&caller, format!("{head})"), false);
    }
    filter.escaped
}

/// `head` (an unfinished half, `NAME(args`) completed by the resumed half
/// `NAME resumed>rest`, or `None` when the two do not belong together.
fn rejoin(resumed: &str, head: Option<String>) -> Option<String> {
    let (name, rest) = resumed.split_once(" resumed>")?;
    let head = head?;
    let rest = rest.strip_prefix(" <unfinished ...>").unwrap_or(rest);
    (head.split_once('(')?.0 == name).then(|| format!("{head}{rest}"))
}

#[derive(Default)]
struct Filter {
    /// The traced process (its first `execve`'s pid).
    pid: String,
    /// Descriptors open on a trusted loader path.
    trusted: BTreeSet<String>,
    escaped: Vec<String>,
}

impl Filter {
    /// Judge one whole call issued by thread `caller`; `torn_down` when the
    /// thread was gone before the call returned.
    fn judge(&mut self, caller: &str, line: String, torn_down: bool) {
        let Some((name, args)) = line.split_once('(') else {
            self.escaped.push(line);
            return;
        };
        // strace names a call `???` when it could not read the thread's
        // registers at the syscall-entry stop (`get_scno` failing; it is
        // printed whatever `-e` selects). With the tracee in that stop, the one
        // failure is ESRCH: a SIGKILL (a sibling's `exit_group`) took it out
        // of the stop, and the kernel then aborts the call before it runs
        // (`ptrace_report_syscall_entry` returns `fatal_signal_pending`). Such
        // an entry ends with the thread's death — the `+++` line, or the
        // exit-event `= ?` with no return value — and is not a host syscall.
        // A `???` that returned anything, or never saw its thread die, is.
        if name == "???" {
            let aborted = match args.strip_suffix("= ?") {
                Some(call) => call.trim_end() == ")",
                None => torn_down && args == ")",
            };
            if !aborted {
                self.escaped.push(line);
            }
            return;
        }
        let returned = line
            .rsplit_once('=')
            .map(|(_, value)| value.trim())
            .and_then(leading_fd);
        if matches!(name, "openat" | "openat2" | "open") && trusted_path(args) {
            if let Some(fd) = returned {
                self.trusted.insert(fd.to_string());
            }
        }
        if name == "close" {
            if let Some(fd) = leading_fd(args) {
                self.trusted.remove(fd);
            }
        }
        if PROCESS_LOCAL.contains(&name) {
            return;
        }
        if matches!(name, "tgkill" | "tkill" | "rt_tgsigqueueinfo")
            && self_directed(name, args, &self.pid, caller)
        {
            return;
        }
        if name == "getrandom" && args.contains("GRND_NONBLOCK") {
            return;
        }
        if matches!(
            name,
            "openat" | "openat2" | "open" | "newfstatat" | "readlink" | "readlinkat"
        ) && trusted_path(args)
        {
            return;
        }
        if matches!(name, "faccessat" | "faccessat2" | "access")
            && args.contains("\"/etc/ld.so.preload\"")
        {
            return;
        }
        if matches!(name, "read" | "pread64" | "fstat" | "fcntl" | "lseek") {
            if let Some(fd) = leading_fd(args) {
                if matches!(fd, "0" | "1" | "2" | "3") || self.trusted.contains(fd) {
                    return;
                }
            }
        }
        if name == "write"
            && args.len() >= 2
            && matches!(&args[..1], "0" | "1" | "2" | "3")
            && matches!(&args[1..2], "," | ")")
        {
            return;
        }
        self.escaped.push(line);
    }
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

    /// Threads split each other's calls; each is rejoined on its own thread
    /// and judged whole, and a call a dying thread never returned from is
    /// judged on its arguments.
    #[test]
    fn interleaved_split_calls_are_judged_per_thread() {
        let trace = r#"4242 execve("/x/probe", ["/x/probe"], 0x7ffd /* 3 vars */) = 0
4243 openat(AT_FDCWD, "/etc/passwd", O_RDONLY <unfinished ...>
4244 read(9,  <unfinished ...>
4242 futex(0x7f00, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>
4243 <... openat resumed>)            = 5
4242 <... futex resumed>)             = 0
4242 exit_group(0 <unfinished ...>
4244 <... read resumed> <unfinished ...>) = ?
4242 <... exit_group resumed>)        = ?
4244 +++ exited with 0 +++
4243 +++ exited with 0 +++
4242 +++ exited with 0 +++
"#;
        assert_eq!(
            calls(escapes(trace)),
            ["openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY)", "read(9, )"]
        );
    }

    /// A trusted open split by another thread still trusts the descriptor its
    /// resumed half returns.
    #[test]
    fn a_split_trusted_open_trusts_its_descriptor() {
        let trace = r#"4242 execve("/x/probe", ["/x/probe"], 0x7ffd /* 3 vars */) = 0
4243 openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libgcc_s.so.1", O_RDONLY|O_CLOEXEC <unfinished ...>
4242 futex(0x7f00, FUTEX_WAKE_PRIVATE, 1) = 0
4243 <... openat resumed>)            = 7
4243 read(7, "\177ELF", 832)          = 832
"#;
        assert!(escapes(trace).is_empty(), "{:?}", escapes(trace));
    }

    /// A call whose thread died before it returned is still judged.
    #[test]
    fn a_call_cut_short_by_exit_group_is_judged() {
        let trace = r#"4242 execve("/x/probe", ["/x/probe"], 0x7ffd /* 3 vars */) = 0
4243 openat(AT_FDCWD, "/etc/hostname", O_RDONLY <unfinished ...>
4242 exit_group(0)                     = ?
4243 +++ exited with 0 +++
4242 +++ exited with 0 +++
"#;
        assert_eq!(
            calls(escapes(trace)),
            ["openat(AT_FDCWD, \"/etc/hostname\", O_RDONLY)"]
        );
    }

    /// A resumed half with no unfinished half on its own thread (or one
    /// naming a different call) is not silently dropped.
    #[test]
    fn an_unpaired_resumed_half_escapes() {
        let trace = r#"4242 execve("/x/probe", ["/x/probe"], 0x7ffd /* 3 vars */) = 0
4243 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC <unfinished ...>
4242 <... openat resumed>)            = 3
4244 read(3,  <unfinished ...>
4244 <... write resumed>)             = 1
"#;
        assert_eq!(
            calls(escapes(trace)),
            ["<... openat resumed>)", "<... write resumed>)"]
        );
    }

    /// strace's `???` for a thread a sibling's `exit_group` killed at its
    /// syscall-entry stop, in all three shapes strace 6.8 writes it (the
    /// first two recorded on this host): the thread's `+++` line, the exit
    /// event's `<... ??? resumed>) = ?`, and that event on the same line.
    #[test]
    fn a_thread_killed_at_syscall_entry_is_not_a_call() {
        let trace = r#"1156461 execve("/x/probe", ["/x/probe"], 0x7ffd /* 3 vars */) = 0
1156461 exit_group(0 <unfinished ...>
1156465 ???( <unfinished ...>
1156463 rt_sigprocmask(SIG_SETMASK, [],  <unfinished ...>
1156464 ???( <unfinished ...>
1156461 <... exit_group resumed>)       = ?
1156463 <... rt_sigprocmask resumed> <unfinished ...>) = ?
1156464 <... ??? resumed>)              = ?
1156462 ???()                           = ?
1156465 +++ exited with 0 +++
1156464 +++ exited with 0 +++
1156463 +++ exited with 0 +++
1156462 +++ exited with 0 +++
1156461 +++ exited with 0 +++
"#;
        assert!(escapes(trace).is_empty(), "{:?}", escapes(trace));
    }

    /// A `???` is excused only by its thread's death before a return: one
    /// that returned a value (or whose value strace could not fetch), or
    /// whose thread never dies in the log, is an escape.
    #[test]
    fn a_nameless_call_that_did_not_die_escapes() {
        let trace = r#"4242 execve("/x/probe", ["/x/probe"], 0x7ffd /* 3 vars */) = 0
4243 ???( <unfinished ...>
4244 ???( <unfinished ...>
4243 <... ??? resumed>)              = 0
4244 <... ??? resumed>)              = ? <unavailable>
4245 ???()                           = 0x3
4246 ???( <unfinished ...>
4242 exit_group(0)                   = ?
4242 +++ exited with 0 +++
"#;
        assert_eq!(calls(escapes(trace)), ["???()"; 4]);
    }

    /// The planted escape of `strace_leak_filter_flags_a_planted_escape`,
    /// surrounded by teardown noise, is still the one escape.
    #[test]
    fn a_planted_escape_survives_teardown_noise() {
        let trace = r#"4242 execve("/x/probe", ["/x/probe"], 0x7ffd /* 3 vars */) = 0
4242 openat(AT_FDCWD, "/etc/hostname", O_RDONLY) = 3
4242 exit_group(0 <unfinished ...>
4243 ???( <unfinished ...>
4242 <... exit_group resumed>)       = ?
4243 +++ exited with 0 +++
4242 +++ exited with 0 +++
"#;
        assert_eq!(
            calls(escapes(trace)),
            ["openat(AT_FDCWD, \"/etc/hostname\", O_RDONLY)"]
        );
    }
}
