//! proc/procfs — the files of `/proc` a program reads to describe the
//! machine and its processes (fs/proc), held to what the caller can learn
//! from the system calls the same figures come from:
//!
//! * `/proc` is procfs (`statfs`: `PROC_SUPER_MAGIC`, the page as its block),
//!   a `0555` directory owned by root, with inode 1 (`PROC_ROOT_INO`);
//!   `/proc/self` is a link reading the caller's pid, and the listing has
//!   `self`, the caller's directory and init's (pid 1) among its entries,
//!   with the machine's files as regular files; a name no entry has is
//!   `ENOENT`, and so is a pid past `PID_MAX_LIMIT`;
//! * the machine's files are `0444` regular files of size 0, root's;
//!   `/proc/uptime` is the boot clock in centiseconds, truncated
//!   (`uptime_proc_show`), between two readings of `CLOCK_BOOTTIME`, and an
//!   idle time that is never negative; `/proc/loadavg` counts the threads
//!   running (the caller's at least) out of all of them; `/proc/stat` has
//!   the summed `cpu` line, `btime` the realtime clock less the boot clock
//!   (to the second, either way), a positive process count and at least the
//!   caller running; `/proc/meminfo`'s total and swap are `sysinfo`'s, and its
//!   free memory at most the total; `/proc/vmstat`'s free pages too;
//! * `/proc/self/task` lists the caller's thread, running by its `stat`; a
//!   thread waiting in a `read` sleeps by its own, and its `status` names
//!   the process (`Tgid`) and the thread (`Pid`); the directory is walked
//!   at every `getdents64`, so it lists threads made and gone between two
//!   calls as they are, and a gone thread's directory and `stat`, opened
//!   while it lived, are `ENOENT` and `ESRCH`;
//! * `/proc/self/stat` and `/proc/self/status` name the caller as its own
//!   calls do: its pid, parent, group, session and ids, its name as
//!   `PR_GET_NAME` reads it (and again after `PR_SET_NAME` renames it), the
//!   running state (it is reading the file), a niceness `getpriority`'s
//!   answer gives and the `SCHED_OTHER` priority `20 + nice`, at least one
//!   thread, CPU time between two `times` readings and a start no later
//!   than now;
//! * a file's text is a `seq_file`'s: a read racing a close on another
//!   thread reads or finds the descriptor closed, a read continues in the
//!   text the last one made, a read of no bytes makes none, an `EFAULT` read moves
//!   nothing, two threads' reads of one description read on from each
//!   other, `SEEK_END` is `EINVAL`; epoll takes a machine file (its
//!   `proc_reg_poll` answers every readiness) but no process file or
//!   directory, which have no `poll` (`EPERM`); `pidfd_send_signal` takes
//!   the caller's `/proc/<pid>` directory as its process (`tgid_pidfd_to_pid`)
//!   and no other procfs descriptor (`EBADF`); `sendfile` reads a machine
//!   file into a pipe but no process file (`EINVAL`), and `copy_file_range`
//!   out of procfs is `EXDEV`;
//! * a description keeps `O_DIRECTORY` (`F_GETFL`), a directory's `dup`
//!   shares its position, two opens of a file contend for `flock`, and the
//!   descriptor calls answer as procfs answers them (`fchmod` `EPERM`,
//!   `ftruncate`/`fsync`/`fdatasync` `EINVAL`, `fallocate` `EBADF`,
//!   `fstatfs` procfs's);
//! * a new name is `ENOENT` to every call that would make it (procfs's
//!   lookups answer first), an entry `EEXIST` to `mkdir`; removing a machine
//!   file or a process directory is `EACCES`;
//! * `/proc/net` is root's link to `self/net`, the caller's `0555`
//!   directory (its `..` the caller's process directory), which lists the
//!   socket tables (`tcp`, `udp`, `tcp6`, `udp6`, `unix`) as root's `0444`
//!   files; each table begins with the header its `seq_show` writes, at the
//!   width it pads to; epoll takes one (`proc_reg_poll`), and `sendfile`
//!   from one is `EINVAL` (`proc_reg_file_ops` has no `splice_read`).
//!
//! The figures themselves (times, counts, sizes) are the host's natively and
//! the virtual machine's under patina, so they are related here, never
//! recorded; every call that reads them is unrecorded and the relations are
//! the scenario's checks.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{AT_FDCWD, Probe, neg, page_size};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `PROC_SUPER_MAGIC` (include/uapi/linux/magic.h).
const PROC_SUPER_MAGIC: i64 = 0x9fa0;
/// `PROC_ROOT_INO`.
const PROC_ROOT_INO: u64 = 1;
/// `PID_MAX_LIMIT` on a 64-bit kernel: no pid is above it.
const PID_MAX_LIMIT: i64 = 4 * 1024 * 1024;
/// `PR_SET_NAME`/`PR_GET_NAME`'s buffer, `TASK_COMM_LEN`.
const COMM_LEN: usize = 16;

/// The machine's files the model answers.
const MACHINE_FILES: [&str; 5] = ["stat", "uptime", "vmstat", "loadavg", "meminfo"];

/// The socket tables of `/proc/<pid>/net` the model answers, with the header
/// line each one's `seq_show` writes, and the width it pads its lines to
/// (`seq_setwidth`; `tcp`'s `TMPSZ - 1`, `udp`'s 127), where it pads them.
const NET_TABLES: [(&str, &str, usize); 5] = [
    (
        "tcp",
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  \
         timeout inode",
        149,
    ),
    (
        "udp",
        "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  \
         timeout inode ref pointer drops",
        127,
    ),
    (
        "tcp6",
        "  sl  local_address                         remote_address                        st \
         tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
        0,
    ),
    (
        "udp6",
        "  sl  local_address                         remote_address                        st \
         tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops",
        0,
    ),
    (
        "unix",
        "Num       RefCount Protocol Flags    Type St Inode Path",
        0,
    ),
];

fn open(p: &Probe, path: &str, flags: i32) -> i64 {
    let c = std::ffi::CString::new(path).unwrap();
    p.call_unrecorded(
        Syscall::N_openat,
        [
            i64::from(AT_FDCWD),
            c.as_ptr() as i64,
            i64::from(flags | O_CLOEXEC),
            0,
            0,
            0,
        ],
    )
}

fn close(p: &Probe, fd: i64) {
    p.call_unrecorded(Syscall::N_close, [fd, 0, 0, 0, 0, 0]);
}

/// One `read` of up to `len` bytes.
fn read(p: &Probe, fd: i64, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let r = p.call_unrecorded(
        Syscall::N_read,
        [fd, buf.as_mut_ptr() as i64, len as i64, 0, 0, 0],
    );
    (r >= 0).then(|| {
        buf.truncate(r as usize);
        buf
    })
}

/// A file's whole text, read to its end in one go.
fn text(p: &Probe, path: &str) -> Option<String> {
    let fd = open(p, path, O_RDONLY);
    if fd < 0 {
        return None;
    }
    let mut all = Vec::new();
    let read_all = loop {
        match read(p, fd, 4096) {
            Some(chunk) if chunk.is_empty() => break true,
            Some(chunk) => all.extend(chunk),
            None => break false,
        }
    };
    close(p, fd);
    read_all.then(|| String::from_utf8(all).ok()).flatten()
}

fn clock(p: &Probe, id: clockid_t) -> i128 {
    let mut ts = [0i64; 2];
    let r = p.call_unrecorded(
        Syscall::N_clock_gettime,
        [i64::from(id), ts.as_mut_ptr() as i64, 0, 0, 0, 0],
    );
    p.require("clock_gettime answers", r == 0);
    i128::from(ts[0]) * 1_000_000_000 + i128::from(ts[1])
}

fn call0(p: &Probe, row: Syscall) -> i64 {
    p.call_unrecorded(row, [0; 6])
}

/// `utime + stime` of the caller, in clock ticks (`times`).
fn cpu_ticks(p: &Probe) -> i64 {
    let mut tms = [0i64; 4];
    let r = p.call_unrecorded(Syscall::N_times, [tms.as_mut_ptr() as i64, 0, 0, 0, 0, 0]);
    p.require("times answers", r != -1);
    tms[0] + tms[1]
}

/// The caller's name (`PR_GET_NAME`), up to its NUL.
fn comm(p: &Probe) -> String {
    let mut buf = [0u8; COMM_LEN];
    let r = p.call_unrecorded(
        Syscall::N_prctl,
        [i64::from(PR_GET_NAME), buf.as_mut_ptr() as i64, 0, 0, 0, 0],
    );
    p.require("PR_GET_NAME answers", r == 0);
    let end = buf.iter().position(|byte| *byte == 0).unwrap_or(COMM_LEN);
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn set_comm(p: &Probe, name: &str) {
    let mut buf = [0u8; COMM_LEN];
    buf[..name.len()].copy_from_slice(name.as_bytes());
    let r = p.call_unrecorded(
        Syscall::N_prctl,
        [i64::from(PR_SET_NAME), buf.as_ptr() as i64, 0, 0, 0, 0],
    );
    p.require("PR_SET_NAME answers", r == 0);
}

/// `newfstatat` without following: `(mode, uid, size, ino)`.
fn stat(p: &Probe, path: &str) -> Option<(u32, u32, i64, u64)> {
    let c = std::ffi::CString::new(path).unwrap();
    // SAFETY: all-zero is a valid `stat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = p.call_unrecorded(
        Syscall::N_newfstatat,
        [
            i64::from(AT_FDCWD),
            c.as_ptr() as i64,
            &mut st as *mut libc::stat as i64,
            i64::from(AT_SYMLINK_NOFOLLOW),
            0,
            0,
        ],
    );
    (r == 0).then_some((st.st_mode, st.st_uid, st.st_size, st.st_ino))
}

/// The value of `key` in a keyed file (`Key:\tvalue` or `key value`).
fn keyed<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?;
        let rest = rest.strip_prefix(':').unwrap_or(rest);
        rest.starts_with([' ', '\t']).then(|| rest.trim())
    })
}

fn number(field: Option<&str>) -> Option<i64> {
    field?.split_whitespace().next()?.parse().ok()
}

/// `seconds.centiseconds` in centiseconds.
fn centiseconds(field: &str) -> Option<i64> {
    let (seconds, fraction) = field.split_once('.')?;
    (fraction.len() == 2).then_some(())?;
    Some(seconds.parse::<i64>().ok()? * 100 + fraction.parse::<i64>().ok()?)
}

/// A directory's entries, `(name, d_type)`, as `getdents64` lists them;
/// `None` when it does not open as a directory.
fn listing(p: &Probe, path: &str) -> Option<Vec<(String, u8)>> {
    let fd = open(p, path, O_RDONLY | O_DIRECTORY);
    if fd < 0 {
        return None;
    }
    let mut entries: Vec<(String, u8)> = Vec::new();
    while let Ok(more) = dents(p, fd, 4096)
        && !more.is_empty()
    {
        entries.extend(more);
    }
    close(p, fd);
    Some(entries)
}

/// One `getdents64` of up to `len` bytes on `fd`: the entries it returned
/// (none at the end), or its `-errno`.
fn dents(p: &Probe, fd: i64, len: usize) -> Result<Vec<(String, u8)>, i64> {
    let mut buf = vec![0u8; len];
    let n = p.call_unrecorded(
        Syscall::N_getdents64,
        [fd, buf.as_mut_ptr() as i64, buf.len() as i64, 0, 0, 0],
    );
    if n < 0 {
        return Err(n);
    }
    let mut entries = Vec::new();
    let mut at = 0;
    while at < n as usize {
        let reclen = u16::from_ne_bytes([buf[at + 16], buf[at + 17]]) as usize;
        let kind = buf[at + 18];
        let name = &buf[at + 19..at + reclen];
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        entries.push((String::from_utf8_lossy(&name[..end]).into_owned(), kind));
        at += reclen;
    }
    Ok(entries)
}

fn root(p: &Probe) {
    let c = std::ffi::CString::new("/proc").unwrap();
    // SAFETY: all-zero is a valid `statfs`.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    let r = p.call_unrecorded(
        Syscall::N_statfs,
        [
            c.as_ptr() as i64,
            &mut fs as *mut libc::statfs as i64,
            0,
            0,
            0,
            0,
        ],
    );
    p.check(
        "/proc is procfs, with the page as its block",
        r == 0 && fs.f_type == PROC_SUPER_MAGIC && fs.f_bsize == page_size() as i64,
    );
    p.check(
        "/proc is root's 0555 directory with procfs's root inode",
        stat(p, "/proc").is_some_and(|(mode, uid, _, ino)| {
            mode == S_IFDIR | 0o555 && uid == 0 && ino == PROC_ROOT_INO
        }),
    );
    let pid = call0(p, Syscall::N_getpid);
    let mut link = [0u8; 32];
    let c = std::ffi::CString::new("/proc/self").unwrap();
    let r = p.call_unrecorded(
        Syscall::N_readlinkat,
        [
            i64::from(AT_FDCWD),
            c.as_ptr() as i64,
            link.as_mut_ptr() as i64,
            link.len() as i64,
            0,
            0,
        ],
    );
    p.check(
        "/proc/self reads the caller's pid",
        r > 0 && link[..r as usize] == *pid.to_string().as_bytes(),
    );
    let entries = listing(p, "/proc");
    p.require("/proc opens as a directory", entries.is_some());
    let entries = entries.unwrap_or_default();
    let has = |name: &str, kind: u8| {
        entries
            .iter()
            .any(|entry| *entry == (name.to_owned(), kind))
    };
    p.check("the listing has self, a link", has("self", DT_LNK));
    p.check(
        "the listing has the caller's directory and init's",
        has(&pid.to_string(), DT_DIR) && has("1", DT_DIR),
    );
    p.check(
        "the listing has the machine's files, regular files",
        MACHINE_FILES.iter().all(|name| has(name, DT_REG)),
    );
    p.check(
        "a name no entry has is ENOENT",
        open(p, "/proc/patina-no-such-entry", O_RDONLY) == neg(ENOENT),
    );
    p.check(
        "a pid past PID_MAX_LIMIT is ENOENT",
        open(p, &format!("/proc/{}", PID_MAX_LIMIT + 1), O_RDONLY) == neg(ENOENT),
    );
}

fn machine(p: &Probe) {
    p.check(
        "the machine's files are root's 0444 regular files of size 0",
        MACHINE_FILES.iter().all(|name| {
            stat(p, &format!("/proc/{name}")).is_some_and(|(mode, uid, size, _)| {
                mode == S_IFREG | 0o444 && uid == 0 && size == 0
            })
        }),
    );
    let before = clock(p, CLOCK_BOOTTIME);
    let uptime = text(p, "/proc/uptime").unwrap_or_default();
    let after = clock(p, CLOCK_BOOTTIME);
    let figures: Vec<Option<i64>> = uptime.split_whitespace().map(centiseconds).collect();
    let centis = |ns: i128| (ns / 10_000_000) as i64;
    p.check(
        "/proc/uptime is the boot clock in centiseconds, and a non-negative idle time",
        uptime.ends_with('\n')
            && figures.len() == 2
            && figures[0].is_some_and(|up| centis(before) <= up && up <= centis(after))
            && figures[1].is_some_and(|idle| idle >= 0),
    );
    let loadavg = text(p, "/proc/loadavg").unwrap_or_default();
    let fields: Vec<&str> = loadavg.split_whitespace().collect();
    let tasks = fields.get(3).and_then(|field| field.split_once('/'));
    let tasks = tasks
        .and_then(|(running, all)| Some((running.parse::<i64>().ok()?, all.parse::<i64>().ok()?)));
    p.check(
        "/proc/loadavg has three loads, the running threads out of all, and the last pid",
        fields.len() == 5
            && fields[..3].iter().all(|load| centiseconds(load).is_some())
            && tasks.is_some_and(|(running, all)| 1 <= running && running <= all)
            && fields[4].parse::<i64>().is_ok_and(|last| last > 0),
    );
    let realtime = clock(p, CLOCK_REALTIME);
    let boottime = clock(p, CLOCK_BOOTTIME);
    let stat = text(p, "/proc/stat").unwrap_or_default();
    let booted = ((realtime - boottime) / 1_000_000_000) as i64;
    p.check(
        "/proc/stat sums the CPUs' time on its first line",
        stat.lines().next().is_some_and(|line| {
            let mut words = line.split_whitespace();
            words.next() == Some("cpu") && {
                let times: Vec<_> = words.map(str::parse::<u64>).collect();
                times.len() >= 4 && times.iter().all(Result::is_ok)
            }
        }),
    );
    p.check(
        "/proc/stat's btime is the realtime clock less the boot clock",
        number(keyed(&stat, "btime")).is_some_and(|btime| (btime - booted).abs() <= 1),
    );
    p.check(
        "/proc/stat counts processes made and the caller running",
        number(keyed(&stat, "processes")).is_some_and(|made| made > 0)
            && number(keyed(&stat, "procs_running")).is_some_and(|running| running >= 1),
    );
    // SAFETY: all-zero is a valid `sysinfo`.
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    let r = p.call_unrecorded(
        Syscall::N_sysinfo,
        [&mut info as *mut libc::sysinfo as i64, 0, 0, 0, 0, 0],
    );
    p.require("sysinfo answers", r == 0);
    let kib = |units: u64| (units * u64::from(info.mem_unit) / 1024) as i64;
    let meminfo = text(p, "/proc/meminfo").unwrap_or_default();
    let total = number(keyed(&meminfo, "MemTotal"));
    p.check(
        "/proc/meminfo's total and swap are sysinfo's, its free memory at most the total",
        total == Some(kib(info.totalram))
            && number(keyed(&meminfo, "SwapTotal")) == Some(kib(info.totalswap))
            && number(keyed(&meminfo, "MemFree")).is_some_and(|free| Some(free) <= total)
            && ["MemTotal", "MemFree", "SwapTotal"]
                .iter()
                .all(|key| keyed(&meminfo, key).is_some_and(|value| value.ends_with(" kB"))),
    );
    let vmstat = text(p, "/proc/vmstat").unwrap_or_default();
    p.check(
        "/proc/vmstat's free pages are at most the memory",
        number(keyed(&vmstat, "nr_free_pages"))
            .is_some_and(|pages| Some(pages * page_size() as i64 / 1024) <= total),
    );
}

/// `/proc/self/stat`'s fields after the name, the name, and the whole text.
fn self_stat(p: &Probe) -> Option<(String, Vec<String>)> {
    let stat = text(p, "/proc/self/stat")?;
    let open = stat.find(" (")?;
    let close = stat.rfind(") ")?;
    p.check(
        "/proc/self/stat starts with the pid",
        stat[..open].parse::<i64>().ok() == Some(call0(p, Syscall::N_getpid)),
    );
    let rest = stat[close + 2..]
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    Some((stat[open + 2..close].to_owned(), rest))
}

fn process(p: &Probe) {
    let pid = call0(p, Syscall::N_getpid);
    let ppid = call0(p, Syscall::N_getppid);
    let pgrp = p.call_unrecorded(Syscall::N_getpgid, [0; 6]);
    let sid = p.call_unrecorded(Syscall::N_getsid, [0; 6]);
    // `getpriority` answers `20 - nice`.
    let nice = 20
        - p.call_unrecorded(
            Syscall::N_getpriority,
            [i64::from(PRIO_PROCESS), 0, 0, 0, 0, 0],
        );
    let now = clock(p, CLOCK_BOOTTIME);
    let ticks_per_second = i128::from(unsafe { sysconf(_SC_CLK_TCK) });
    let cpu_before = cpu_ticks(p);
    let stat = self_stat(p);
    let cpu_after = cpu_ticks(p);
    let name = comm(p);
    let field =
        |rest: &[String], at: usize| rest.get(at).and_then(|field| field.parse::<i64>().ok());
    p.check(
        "/proc/self/stat names the caller, running, by its name",
        stat.as_ref().is_some_and(|(comm, rest)| {
            *comm == name
                && rest.first().map(String::as_str) == Some("R")
                && field(rest, 1) == Some(ppid)
                && field(rest, 2) == Some(pgrp)
                && field(rest, 3) == Some(sid)
        }),
    );
    p.check(
        "its CPU time lies between two times readings",
        stat.as_ref()
            .and_then(|(_, rest)| Some(field(rest, 11)? + field(rest, 12)?))
            .is_some_and(|cpu| cpu_before <= cpu && cpu <= cpu_after),
    );
    p.check(
        "its niceness is getpriority's, its priority 20 plus it",
        stat.as_ref().is_some_and(|(_, rest)| {
            field(rest, 16) == Some(nice) && field(rest, 15) == Some(20 + nice)
        }),
    );
    p.check(
        "it has a thread, and started no later than now",
        stat.as_ref().is_some_and(|(_, rest)| {
            field(rest, 17).is_some_and(|threads| threads >= 1)
                && field(rest, 19).is_some_and(|start| {
                    i128::from(start) * 1_000_000_000 <= now * ticks_per_second
                })
        }),
    );
    let status = text(p, "/proc/self/status").unwrap_or_default();
    let ids = |key: &str| -> Option<Vec<i64>> {
        keyed(&status, key)?
            .split_whitespace()
            .map(|id| id.parse().ok())
            .collect()
    };
    let (uid, euid) = (call0(p, Syscall::N_getuid), call0(p, Syscall::N_geteuid));
    let (gid, egid) = (call0(p, Syscall::N_getgid), call0(p, Syscall::N_getegid));
    p.check(
        "/proc/self/status names the caller as its calls do",
        keyed(&status, "Name") == Some(name.as_str())
            && number(keyed(&status, "Pid")) == Some(pid)
            && number(keyed(&status, "Tgid")) == Some(pid)
            && number(keyed(&status, "PPid")) == Some(ppid)
            && keyed(&status, "State").is_some_and(|state| state.starts_with('R'))
            && ids("Uid").is_some_and(|ids| ids.len() == 4 && ids[..2] == [uid, euid])
            && ids("Gid").is_some_and(|ids| ids.len() == 4 && ids[..2] == [gid, egid]),
    );
    let renamed = "patina-procfs";
    set_comm(p, renamed);
    let after = self_stat(p);
    let status = text(p, "/proc/self/status").unwrap_or_default();
    set_comm(p, &name);
    p.check(
        "the name follows PR_SET_NAME",
        after.is_some_and(|(comm, _)| comm == renamed) && keyed(&status, "Name") == Some(renamed),
    );
}

/// `lseek(fd, 0, SEEK_CUR)`.
fn position(p: &Probe, fd: i64) -> i64 {
    p.call_unrecorded(Syscall::N_lseek, [fd, 0, i64::from(SEEK_CUR), 0, 0, 0])
}

/// The first line of `/proc/self/status` read in two: `head` bytes, then,
/// once the caller is renamed `rename`, the rest (`None` when a read fails).
fn status_name(p: &Probe, head: usize, rename: &str) -> Option<String> {
    let fd = open(p, "/proc/self/status", O_RDONLY);
    p.require("/proc/self/status opens", fd >= 0);
    let first = read(p, fd, head)?;
    set_comm(p, rename);
    let rest = read(p, fd, 4096)?;
    close(p, fd);
    let whole = String::from_utf8([first, rest].concat()).ok()?;
    whole.lines().next().map(str::to_owned)
}

/// How a file's text is kept between reads: a read goes on in the text the
/// last one made (a rename between them shows in neither), a read of no
/// bytes makes none (the next read shows a rename after it), a read into
/// memory the caller cannot reach (`EFAULT`) moves nothing, and two threads
/// reading a byte each from one description read consecutive bytes.
fn reads(p: &Probe) {
    let name = comm(p);
    set_comm(p, "alpha");
    p.check(
        "a read continues the text the last one made, from before a rename",
        status_name(p, 8, "bravo").as_deref() == Some("Name:\talpha"),
    );
    set_comm(p, "alpha");
    p.check(
        "a read of no bytes makes no text",
        status_name(p, 0, "bravo").as_deref() == Some("Name:\tbravo"),
    );
    set_comm(p, &name);
    let fd = open(p, "/proc/meminfo", O_RDONLY);
    p.require("/proc/meminfo opens", fd >= 0);
    let refused = p.call_unrecorded(Syscall::N_read, [fd, 1, 8, 0, 0, 0]);
    p.check(
        "a read into unreachable memory is EFAULT and moves nothing",
        refused == neg(EFAULT) && position(p, fd) == 0,
    );
    close(p, fd);
    p.check(
        "two threads reading a byte each from one description read consecutive bytes",
        (0..4).all(|_| shared_bytes(p) == b"Me"),
    );
}

/// The bytes two threads read, one each and at once, from one description
/// of `/proc/meminfo`, in order.
fn shared_bytes(p: &Probe) -> Vec<u8> {
    let fd = open(p, "/proc/meminfo", O_RDONLY);
    p.require("/proc/meminfo opens", fd >= 0);
    let gate = std::sync::Barrier::new(2);
    let mut bytes: Vec<u8> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    gate.wait();
                    let mut byte = 0u8;
                    // SAFETY: one writable byte.
                    let n = unsafe { libc::read(fd as c_int, (&raw mut byte).cast(), 1) };
                    (n == 1).then_some(byte)
                })
            })
            .collect();
        workers
            .into_iter()
            .filter_map(|worker| worker.join().ok().flatten())
            .collect()
    });
    close(p, fd);
    bytes.sort_unstable();
    bytes
}

/// What a description is: `F_GETFL` keeps `O_DIRECTORY`; a `dup` of a
/// directory reads on from where it is (one position); two opens of one
/// file contend for `flock` (it is the inode's); a mode change is `EPERM`
/// (`proc_setattr`), a truncation or sync `EINVAL` (no write access, no
/// `fsync`), an allocation `EBADF` (not open for writing); `fstatfs` names
/// procfs.
fn descriptions(p: &Probe) {
    let dir = open(p, "/proc/self", O_RDONLY | O_DIRECTORY);
    p.require("/proc/self opens as a directory", dir >= 0);
    let flags = p.call_unrecorded(Syscall::N_fcntl, [dir, i64::from(F_GETFL), 0, 0, 0, 0]);
    p.check(
        "F_GETFL keeps O_DIRECTORY",
        flags >= 0 && flags & i64::from(O_DIRECTORY) != 0,
    );
    let twin = p.call_unrecorded(Syscall::N_dup, [dir, 0, 0, 0, 0, 0]);
    p.require("dup answers", twin >= 0);
    let first = one_entry(p, dir);
    let second = one_entry(p, twin);
    p.check(
        "a dup of a directory reads on where it is, at one position",
        first.as_deref() == Some(".")
            && second.as_deref() == Some("..")
            && position(p, dir) == position(p, twin),
    );
    let rewound = p.call_unrecorded(Syscall::N_lseek, [twin, 0, i64::from(SEEK_SET), 0, 0, 0]);
    p.check(
        "a seek through the dup moves the directory",
        rewound == 0 && one_entry(p, dir).as_deref() == Some("."),
    );
    let lock = |fd: i64| {
        p.call_unrecorded(
            Syscall::N_flock,
            [fd, i64::from(LOCK_EX | LOCK_NB), 0, 0, 0, 0],
        )
    };
    let a = open(p, "/proc/meminfo", O_RDONLY);
    let b = open(p, "/proc/meminfo", O_RDONLY);
    p.check(
        "two opens of one file contend for flock",
        a >= 0 && b >= 0 && lock(a) == 0 && lock(b) == neg(EWOULDBLOCK),
    );
    let file = open(p, "/proc/self/status", O_RDONLY);
    p.require("/proc/self/status opens", file >= 0);
    let call = |row: Syscall, args: [i64; 6]| p.call_unrecorded(row, args);
    p.check(
        "fchmod of a procfs file or directory is EPERM",
        call(Syscall::N_fchmod, [file, 0o444, 0, 0, 0, 0]) == neg(EPERM)
            && call(Syscall::N_fchmod, [dir, 0o555, 0, 0, 0, 0]) == neg(EPERM),
    );
    p.check(
        "ftruncate, fsync and fdatasync are EINVAL, fallocate EBADF",
        call(Syscall::N_ftruncate, [file, 0, 0, 0, 0, 0]) == neg(EINVAL)
            && call(Syscall::N_fsync, [file, 0, 0, 0, 0, 0]) == neg(EINVAL)
            && call(Syscall::N_fdatasync, [file, 0, 0, 0, 0, 0]) == neg(EINVAL)
            && call(Syscall::N_fallocate, [file, 0, 0, 16, 0, 0]) == neg(EBADF),
    );
    // SAFETY: all-zero is a valid `statfs`.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    let r = call(
        Syscall::N_fstatfs,
        [file, &mut fs as *mut libc::statfs as i64, 0, 0, 0, 0],
    );
    p.check(
        "fstatfs names procfs",
        r == 0 && fs.f_type == PROC_SUPER_MAGIC,
    );
    for each in [file, a, b, twin, dir] {
        close(p, each);
    }
}

/// The name of the one entry a 24-byte `getdents64` returns (`.` and `..`
/// fill one record each).
fn one_entry(p: &Probe, fd: i64) -> Option<String> {
    let mut buf = [0u8; 24];
    let n = p.call_unrecorded(
        Syscall::N_getdents64,
        [fd, buf.as_mut_ptr() as i64, buf.len() as i64, 0, 0, 0],
    );
    (n > 0).then(|| {
        let name = &buf[19..];
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        String::from_utf8_lossy(&name[..end]).into_owned()
    })
}

/// What procfs answers a call that would make or remove a name: a new
/// name is `ENOENT` (procfs's lookups answer it before any creation is
/// judged), an existing one `EEXIST`; removing a machine file or a process
/// directory is `EACCES` (`may_delete`: `/proc` is `0555`).
fn names(p: &Probe) {
    const NEW: &str = "/proc/patina-new";
    const OWN_NEW: &str = "/proc/self/patina-new";
    let c = |path: &str| std::ffi::CString::new(path).unwrap();
    let at = |row: Syscall, path: &str, rest: [i64; 4]| {
        let path = c(path);
        p.call_unrecorded(
            row,
            [
                i64::from(AT_FDCWD),
                path.as_ptr() as i64,
                rest[0],
                rest[1],
                rest[2],
                rest[3],
            ],
        )
    };
    let create = |path: &str| open(p, path, O_CREAT | O_WRONLY);
    let mkdir = |path: &str| at(Syscall::N_mkdirat, path, [0o755, 0, 0, 0]);
    p.check(
        "creating a new name in procfs is ENOENT",
        create(NEW) == neg(ENOENT) && create(OWN_NEW) == neg(ENOENT),
    );
    p.check(
        "mkdir of a new name is ENOENT, of an entry EEXIST",
        mkdir(NEW) == neg(ENOENT)
            && mkdir(OWN_NEW) == neg(ENOENT)
            && mkdir("/proc/uptime") == neg(EEXIST),
    );
    let target = c("a");
    let link = c(NEW);
    p.check(
        "symlink and mknod of a new name are ENOENT",
        p.call_unrecorded(
            Syscall::N_symlinkat,
            [
                target.as_ptr() as i64,
                i64::from(AT_FDCWD),
                link.as_ptr() as i64,
                0,
                0,
                0,
            ],
        ) == neg(ENOENT)
            && at(
                Syscall::N_mknodat,
                NEW,
                [i64::from(S_IFIFO | 0o600), 0, 0, 0],
            ) == neg(ENOENT),
    );
    p.check(
        "unlinking a machine file or removing a process directory is EACCES",
        at(Syscall::N_unlinkat, "/proc/uptime", [0; 4]) == neg(EACCES)
            && at(
                Syscall::N_unlinkat,
                "/proc/1",
                [i64::from(AT_REMOVEDIR), 0, 0, 0],
            ) == neg(EACCES),
    );
}

/// The state letter of a `stat` line (the field after the name).
fn state_of(stat: &str) -> Option<char> {
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.trim_start().chars().next())
}

/// The most `pread`s of a thread's `stat` [`threads`] polls through for the
/// thread to reach its next wait: seconds of reads natively, where the
/// thread runs beside the poller, and a bound under patina, where it runs
/// only at the poller's scheduling points.
const POLLED_READS: usize = 1_000_000;

/// `/proc/self/task`: the caller's thread is listed, its `stat` names it
/// running; a second thread sleeping in a `read` of an empty pipe shows
/// sleeping (`S`), and its `status` gives the process as `Tgid` and the
/// thread as `Pid`. Woken while the caller does nothing but read its `stat`
/// from one description, it reaches its next wait within [`POLLED_READS`]:
/// each read that makes the text again lets it run.
fn threads(p: &Probe) {
    let pid = call0(p, Syscall::N_getpid);
    let me = i64::from(crate::signals::gettid());
    let entries = listing(p, "/proc/self/task").unwrap_or_default();
    p.check(
        "/proc/self/task lists the caller's thread",
        entries.contains(&(me.to_string(), DT_DIR)),
    );
    let own = text(p, &format!("/proc/self/task/{me}/stat")).unwrap_or_default();
    p.check(
        "the caller's thread is running, by its stat",
        own.starts_with(&format!("{me} (")) && state_of(&own) == Some('R'),
    );
    let pipe = || {
        let mut ends = [0i32; 2];
        let r = p.call_unrecorded(
            Syscall::N_pipe2,
            [ends.as_mut_ptr() as i64, i64::from(O_CLOEXEC), 0, 0, 0, 0],
        );
        p.require("pipe2 answers", r == 0);
        ends
    };
    let (ends, next) = (pipe(), pipe());
    let tid = std::sync::atomic::AtomicI32::new(0);
    let woken = std::sync::atomic::AtomicBool::new(false);
    let (sleeping, status, polled) = std::thread::scope(|scope| {
        scope.spawn(|| {
            tid.store(
                crate::signals::gettid(),
                std::sync::atomic::Ordering::SeqCst,
            );
            let mut byte = 0u8;
            // SAFETY: one writable byte.
            unsafe { libc::read(ends[0], (&raw mut byte).cast(), 1) };
            woken.store(true, std::sync::atomic::Ordering::SeqCst);
            // SAFETY: one writable byte.
            unsafe { libc::read(next[0], (&raw mut byte).cast(), 1) };
        });
        p.rec.quiet(|| {
            crate::signals::wait_until(std::time::Duration::from_millis(1), || {
                tid.load(std::sync::atomic::Ordering::SeqCst) != 0
            })
        });
        let worker = tid.load(std::sync::atomic::Ordering::SeqCst);
        let path = format!("/proc/self/task/{worker}/stat");
        let sleeping = p.rec.quiet(|| {
            crate::signals::wait_until(std::time::Duration::from_millis(1), || {
                text(p, &path).as_deref().and_then(state_of) == Some('S')
            })
        });
        let status = text(p, &format!("/proc/self/task/{worker}/status")).unwrap_or_default();
        let fd = open(p, &path, O_RDONLY);
        // SAFETY: one readable byte.
        unsafe { libc::write(ends[1], b"x".as_ptr().cast(), 1) };
        let mut buf = [0u8; 512];
        let polled = fd >= 0
            && (0..POLLED_READS).any(|_| {
                // Read after the flag, so a sleep it shows is the next wait's.
                let past = woken.load(std::sync::atomic::Ordering::SeqCst);
                let n = p.call_unrecorded(
                    Syscall::N_pread64,
                    [fd, buf.as_mut_ptr() as i64, buf.len() as i64, 0, 0, 0],
                );
                past && n > 0
                    && std::str::from_utf8(&buf[..n as usize])
                        .ok()
                        .and_then(state_of)
                        == Some('S')
            });
        if fd >= 0 {
            close(p, fd);
        }
        // SAFETY: one readable byte.
        unsafe { libc::write(next[1], b"x".as_ptr().cast(), 1) };
        (sleeping, (worker, status), polled)
    });
    let (worker, status) = status;
    p.check("a thread waiting in a read sleeps, by its stat", sleeping);
    p.check(
        "a thread woken while the caller only reads its stat reaches its next wait",
        polled,
    );
    p.check(
        "a thread's status names the process as Tgid and the thread as Pid",
        keyed(&status, "Tgid") == Some(pid.to_string().as_str())
            && keyed(&status, "Pid") == Some(worker.to_string().as_str()),
    );
    for end in ends.into_iter().chain(next) {
        close(p, i64::from(end));
    }
}

/// How many times [`lifecycle`] races a close against a read.
const CLOSE_RACES: usize = 16;

/// What procfs keeps as threads come and go, and as a descriptor goes
/// while a read is under way on it: a read racing a close on another
/// thread reads the file or finds the descriptor closed (`EBADF`), the
/// read under way keeping the file; `/proc/self/task` is walked at every
/// `getdents64`, so a thread made after its first call is listed by the
/// next, and one that was there at the first call but has gone since is
/// not; a gone thread's directory, opened while
/// it lived, lists `ENOENT`, and its `stat`, opened then, reads `ESRCH`.
fn lifecycle(p: &Probe) {
    let mut answered = true;
    for _ in 0..CLOSE_RACES {
        let fd = open(p, "/proc/meminfo", O_RDONLY);
        p.require("/proc/meminfo opens", fd >= 0);
        let mut buf = [0u8; 128];
        let n = std::thread::scope(|scope| {
            scope.spawn(|| {
                // SAFETY: closes the scenario's own descriptor.
                unsafe { libc::close(fd as i32) };
            });
            p.call_unrecorded(
                Syscall::N_read,
                [fd, buf.as_mut_ptr() as i64, buf.len() as i64, 0, 0, 0],
            )
        });
        answered &= n > 0 || n == neg(EBADF);
    }
    p.check(
        "a read racing a close on another thread reads, or finds the descriptor closed",
        answered,
    );
    let names = |entries: &[(String, u8)]| -> Vec<String> {
        entries.iter().map(|(name, _)| name.clone()).collect()
    };
    let dots = |fd: i64| dents(p, fd, 48).map(|entries| names(&entries));
    let tasks = open(p, "/proc/self/task", O_RDONLY | O_DIRECTORY);
    let after = open(p, "/proc/self/task", O_RDONLY | O_DIRECTORY);
    p.require("/proc/self/task opens", tasks >= 0 && after >= 0);
    let first = dots(tasks);
    let mut ends = [0i32; 2];
    let r = p.call_unrecorded(
        Syscall::N_pipe2,
        [ends.as_mut_ptr() as i64, i64::from(O_CLOEXEC), 0, 0, 0, 0],
    );
    p.require("pipe2 answers", r == 0);
    let tid = std::sync::atomic::AtomicI32::new(0);
    let (made, first_after, worker, dead, dead_stat) = std::thread::scope(|scope| {
        scope.spawn(|| {
            tid.store(
                crate::signals::gettid(),
                std::sync::atomic::Ordering::SeqCst,
            );
            let mut byte = 0u8;
            // SAFETY: one writable byte.
            unsafe { libc::read(ends[0], (&raw mut byte).cast(), 1) };
        });
        p.rec.quiet(|| {
            crate::signals::wait_until(std::time::Duration::from_millis(1), || {
                tid.load(std::sync::atomic::Ordering::SeqCst) != 0
            })
        });
        let worker = tid.load(std::sync::atomic::Ordering::SeqCst);
        let made = dents(p, tasks, 4096).map(|entries| names(&entries));
        let first_after = dots(after);
        let dead = open(
            p,
            &format!("/proc/self/task/{worker}"),
            O_RDONLY | O_DIRECTORY,
        );
        let dead_stat = open(p, &format!("/proc/self/task/{worker}/stat"), O_RDONLY);
        // SAFETY: one readable byte.
        unsafe { libc::write(ends[1], b"x".as_ptr().cast(), 1) };
        (made, first_after, worker, dead, dead_stat)
    });
    // The joined thread leaves procfs once the kernel has released it.
    let path = format!("/proc/self/task/{worker}");
    p.rec.quiet(|| {
        crate::signals::wait_until(std::time::Duration::from_millis(1), || {
            stat(p, &path).is_none()
        })
    });
    let worker = worker.to_string();
    let walked = |first: Result<Vec<String>, i64>| {
        first.as_deref() == Ok(&[".".to_owned(), "..".to_owned()][..])
    };
    p.check(
        "a task directory's next getdents64 lists a thread made after its first",
        walked(first) && made.is_ok_and(|names| names.contains(&worker)),
    );
    let gone = dents(p, after, 4096).map(|entries| names(&entries));
    p.check(
        "and does not list a thread gone since",
        walked(first_after)
            && gone.is_ok_and(|names| !names.is_empty() && !names.contains(&worker)),
    );
    p.check(
        "a gone thread's directory, opened while it lived, lists ENOENT",
        dead >= 0 && dents(p, dead, 4096) == Err(neg(ENOENT)),
    );
    let mut buf = [0u8; 64];
    p.check(
        "and its stat, opened then, reads ESRCH",
        dead_stat >= 0
            && p.call_unrecorded(
                Syscall::N_read,
                [
                    dead_stat,
                    buf.as_mut_ptr() as i64,
                    buf.len() as i64,
                    0,
                    0,
                    0,
                ],
            ) == neg(ESRCH),
    );
    for fd in [tasks, after, dead, dead_stat]
        .into_iter()
        .chain(ends.map(i64::from))
    {
        close(p, fd);
    }
}

fn behaviour(p: &Probe) {
    let fd = open(p, "/proc/uptime", O_RDONLY);
    p.require("/proc/uptime opens", fd >= 0);
    p.check(
        "SEEK_END is EINVAL",
        p.call_unrecorded(Syscall::N_lseek, [fd, 0, i64::from(SEEK_END), 0, 0, 0]) == neg(EINVAL),
    );
    let epoll = p.call_unrecorded(
        Syscall::N_epoll_create1,
        [i64::from(EPOLL_CLOEXEC), 0, 0, 0, 0, 0],
    );
    p.require("epoll_create1 answers", epoll >= 0);
    let add = |target: i64| {
        let mut event = epoll_event {
            events: EPOLLIN as u32,
            u64: 0,
        };
        p.call_unrecorded(
            Syscall::N_epoll_ctl,
            [
                epoll,
                i64::from(EPOLL_CTL_ADD),
                target,
                &mut event as *mut epoll_event as i64,
                0,
                0,
            ],
        )
    };
    p.check("epoll takes a machine file", add(fd) == 0);
    let mut ready = [epoll_event { events: 0, u64: 0 }; 1];
    let n = p.call_unrecorded(
        Syscall::N_epoll_pwait,
        [epoll, ready.as_mut_ptr() as i64, 1, 0, 0, 0],
    );
    p.check(
        "a machine file is ready at once",
        n == 1 && ready[0].events & EPOLLIN as u32 != 0,
    );
    let own = open(p, "/proc/self/stat", O_RDONLY);
    let dir = open(p, "/proc", O_RDONLY | O_DIRECTORY);
    p.check(
        "epoll takes no process file or directory (EPERM)",
        own >= 0 && dir >= 0 && add(own) == neg(EPERM) && add(dir) == neg(EPERM),
    );
    transfers(p, own);
    let me = open(p, "/proc/self", O_RDONLY | O_DIRECTORY);
    let signal =
        |target: i64| p.call_unrecorded(Syscall::N_pidfd_send_signal, [target, 0, 0, 0, 0, 0]);
    p.check(
        "pidfd_send_signal takes the caller's process directory, not procfs's root or a file",
        me >= 0 && signal(me) == 0 && signal(dir) == neg(EBADF) && signal(fd) == neg(EBADF),
    );
    for each in [me, own, dir, fd, epoll] {
        close(p, each);
    }
}

/// `sendfile` reads a machine file's text into a pipe (`splice_read`) but
/// no process file (`own`, which has none: `EINVAL`); `copy_file_range`
/// out of procfs is `EXDEV` (another filesystem, with no copy operation).
fn transfers(p: &Probe, own: i64) {
    let mut ends = [0i32; 2];
    let r = p.call_unrecorded(
        Syscall::N_pipe2,
        [ends.as_mut_ptr() as i64, i64::from(O_CLOEXEC), 0, 0, 0, 0],
    );
    p.require("pipe2 answers", r == 0);
    let (reader, writer) = (i64::from(ends[0]), i64::from(ends[1]));
    let uptime = open(p, "/proc/uptime", O_RDONLY);
    p.require("/proc/uptime opens", uptime >= 0);
    let sent = p.call_unrecorded(Syscall::N_sendfile, [writer, uptime, 0, 4096, 0, 0]);
    let piped = read(p, reader, 4096).unwrap_or_default();
    p.check(
        "sendfile reads a machine file's text into a pipe",
        sent > 0
            && piped.len() as i64 == sent
            && String::from_utf8_lossy(&piped)
                .split_whitespace()
                .filter_map(centiseconds)
                .count()
                == 2,
    );
    p.check(
        "sendfile from a process file is EINVAL",
        own >= 0
            && p.call_unrecorded(Syscall::N_sendfile, [writer, own, 0, 4096, 0, 0]) == neg(EINVAL),
    );
    let path = std::ffi::CString::new(format!("{}/procfs-copy", p.dir())).unwrap();
    let out = p.call_unrecorded(
        Syscall::N_openat,
        [
            i64::from(AT_FDCWD),
            path.as_ptr() as i64,
            i64::from(O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC),
            0o600,
            0,
            0,
        ],
    );
    p.require("a file to copy into opens", out >= 0);
    p.check(
        "copy_file_range out of procfs is EXDEV",
        p.call_unrecorded(Syscall::N_copy_file_range, [uptime, 0, out, 0, 64, 0]) == neg(EXDEV),
    );
    for each in [out, uptime, reader, writer] {
        close(p, each);
    }
}

/// What `readlinkat` reads at `path`.
fn link(p: &Probe, path: &str) -> Option<Vec<u8>> {
    let c = std::ffi::CString::new(path).unwrap();
    let mut buf = [0u8; 64];
    let r = p.call_unrecorded(
        Syscall::N_readlinkat,
        [
            i64::from(AT_FDCWD),
            c.as_ptr() as i64,
            buf.as_mut_ptr() as i64,
            buf.len() as i64,
            0,
            0,
        ],
    );
    (r >= 0).then(|| buf[..r as usize].to_vec())
}

/// `/proc/net` and the caller's `net` directory: the link, the directory's
/// owner and parent, the tables' kind and owner, each table's header, and
/// a table's `poll` (`proc_reg_poll`) with no `splice_read`.
fn net(p: &Probe) {
    let pid = call0(p, Syscall::N_getpid);
    let euid = call0(p, Syscall::N_geteuid);
    p.check(
        "/proc/net is root's link reading self/net",
        link(p, "/proc/net").as_deref() == Some(b"self/net".as_slice())
            && stat(p, "/proc/net")
                .is_some_and(|(mode, uid, _, _)| mode == S_IFLNK | 0o777 && uid == 0),
    );
    let own = stat(p, &format!("/proc/{pid}"));
    p.check(
        "/proc/self/net is the caller's 0555 directory, whose .. is the caller's directory",
        stat(p, "/proc/self/net")
            .is_some_and(|(mode, uid, _, _)| mode == S_IFDIR | 0o555 && i64::from(uid) == euid)
            && own.is_some()
            && stat(p, "/proc/net/..").map(|(.., ino)| ino) == own.map(|(.., ino)| ino),
    );
    let entries = listing(p, "/proc/net").unwrap_or_default();
    p.check(
        "the net directory lists the socket tables as regular files",
        NET_TABLES
            .iter()
            .all(|(name, ..)| entries.contains(&((*name).to_owned(), DT_REG))),
    );
    p.check(
        "the socket tables are root's 0444 regular files of size 0",
        NET_TABLES.iter().all(|(name, ..)| {
            stat(p, &format!("/proc/net/{name}")).is_some_and(|(mode, uid, size, _)| {
                mode == S_IFREG | 0o444 && uid == 0 && size == 0
            })
        }),
    );
    p.check(
        "each socket table begins with its header line, padded as its seq_show pads it",
        NET_TABLES.iter().all(|(name, header, width)| {
            text(p, &format!("/proc/net/{name}")).is_some_and(|table| {
                table.split_inclusive('\n').next() == Some(&format!("{header:<width$}\n"))
            })
        }),
    );
    let table = open(p, "/proc/net/unix", O_RDONLY);
    p.require("/proc/net/unix opens", table >= 0);
    let epoll = p.call_unrecorded(
        Syscall::N_epoll_create1,
        [i64::from(EPOLL_CLOEXEC), 0, 0, 0, 0, 0],
    );
    p.require("epoll_create1 answers", epoll >= 0);
    let mut event = epoll_event {
        events: EPOLLIN as u32,
        u64: 0,
    };
    let added = p.call_unrecorded(
        Syscall::N_epoll_ctl,
        [
            epoll,
            i64::from(EPOLL_CTL_ADD),
            table,
            &mut event as *mut epoll_event as i64,
            0,
            0,
        ],
    );
    p.check("epoll takes a socket table", added == 0);
    let mut ends = [0i32; 2];
    let r = p.call_unrecorded(
        Syscall::N_pipe2,
        [ends.as_mut_ptr() as i64, i64::from(O_CLOEXEC), 0, 0, 0, 0],
    );
    p.require("pipe2 answers", r == 0);
    let (reader, writer) = (i64::from(ends[0]), i64::from(ends[1]));
    p.check(
        "sendfile from a socket table is EINVAL (no splice_read)",
        p.call_unrecorded(Syscall::N_sendfile, [writer, table, 0, 4096, 0, 0]) == neg(EINVAL),
    );
    for each in [reader, writer, epoll, table] {
        close(p, each);
    }
}

pub fn run(p: &Probe) {
    root(p);
    machine(p);
    process(p);
    reads(p);
    descriptions(p);
    names(p);
    threads(p);
    lifecycle(p);
    net(p);
    behaviour(p);
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/procfs",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_openat,
        Syscall::N_read,
        Syscall::N_lseek,
        Syscall::N_newfstatat,
        Syscall::N_statfs,
        Syscall::N_readlinkat,
        Syscall::N_getdents64,
        Syscall::N_epoll_ctl,
        Syscall::N_sendfile,
        Syscall::N_copy_file_range,
        Syscall::N_pidfd_send_signal,
        Syscall::N_fcntl,
        Syscall::N_flock,
        Syscall::N_fchmod,
        Syscall::N_fstatfs,
    ],
    ..DEFAULTS
};
