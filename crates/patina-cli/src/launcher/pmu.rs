//! The counter broker: opens retired-branch counters for the sandbox's threads.
//!
//! `perf_event_open` needs `CAP_PERFMON` in the initial user namespace (this host also has
//! `perf_event_paranoid` 4); nothing inside the sandbox has it. The launcher does, when its
//! executable carries the file capability (`setcap cap_perfmon+ep` on a copy of `patina`) or it
//! runs as root. Capabilities never reach the sandbox: `exec` of bwrap (no file capabilities)
//! drops them, ambient ones are cleared first, and bwrap sets no_new_privs.
//!
//! Protocol, on a `SOCK_SEQPACKET` pair whose sandbox end is descriptor `FD_PMU`: the runtime
//! sends 8 bytes and a thread pidfd (`SCM_RIGHTS`); the broker reads the host tid from the
//! pidfd's fdinfo, checks that the task descends from this incarnation's bwrap, opens the one
//! event it ever opens for that task, and answers 8 bytes (0 or -errno) with the counter.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::OnceLock;
use std::thread::JoinHandle;

/// The event attribute: raw `event`, user mode only, overflow every `PERIOD` branches with a
/// synchronous SIGTRAP to the counted thread, removed at `execve`.
fn attr(event: u64) -> [u8; 128] {
    let mut a = [0u8; 128];
    a[0..4].copy_from_slice(&4u32.to_le_bytes()); // PERF_TYPE_RAW
    a[4..8].copy_from_slice(&128u32.to_le_bytes()); // PERF_ATTR_SIZE_VER7
    a[8..16].copy_from_slice(&event.to_le_bytes());
    a[16..24].copy_from_slice(&proto::pmu::PERIOD.to_le_bytes());
    // pinned, exclude_kernel, exclude_hv, remove_on_exec, sigtrap
    let flags: u64 = 1 << 2 | 1 << 5 | 1 << 6 | 1 << 36 | 1 << 37;
    a[40..48].copy_from_slice(&flags.to_le_bytes());
    a[120..128].copy_from_slice(&proto::pmu::SIG_DATA.to_le_bytes());
    a
}

fn perf_open(event: u64, tid: i32) -> io::Result<OwnedFd> {
    const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 8;
    let a = attr(event);
    let r = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            a.as_ptr(),
            tid,
            -1i32,
            -1i32,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(r as RawFd) })
}

/// The retired-conditional-branch event of this CPU, if its family is supported. Elsewhere
/// counter preemption is refused, not attempted. On an Intel Xeon 6975P-C
/// (`BR_INST_RETIRED.CONDITIONAL`, 0x01c4) the stops differed from those reached by stepping
/// branch by branch, and one seed moved between CPUs gave a different digest each run; a run
/// must not mean something different on another host. A seed run with counters reproduces
/// on the same CPU family.
fn event() -> Result<u64, String> {
    let r = std::arch::x86_64::__cpuid(0);
    let mut v = [0u8; 12];
    v[0..4].copy_from_slice(&r.ebx.to_le_bytes());
    v[4..8].copy_from_slice(&r.edx.to_le_bytes());
    v[8..12].copy_from_slice(&r.ecx.to_le_bytes());
    let sig = std::arch::x86_64::__cpuid(1).eax;
    let base = (sig >> 8) & 0xf;
    let family = if base == 0xf {
        base + ((sig >> 20) & 0xff)
    } else {
        base
    };
    let model = ((sig >> 4) & 0xf)
        | if base >= 0x6 {
            ((sig >> 16) & 0xf) << 4
        } else {
            0
        };
    let vendor = String::from_utf8_lossy(&v).to_string();
    if &v == b"AuthenticAMD" && proto::pmu::AMD_FAMILIES.contains(&family) {
        return Ok(proto::pmu::EVENT_AMD);
    }
    Err(format!(
        "this CPU ({vendor} family {family:#x} model {model:#x}) is not supported: counter \
         preemption is checked exact on AMD family 0x1a (Zen 5) only"
    ))
}

/// Can this launcher open counters? The event, or why not. Checked once per process by
/// opening the event on the calling thread.
pub fn available() -> Result<u64, String> {
    static S: OnceLock<Result<u64, String>> = OnceLock::new();
    S.get_or_init(|| {
        let ev = event()?;
        match perf_open(ev, 0) {
            Ok(_) => Ok(ev),
            Err(e) if matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => Err(format!(
                "perf_event_open: {e}: counters need CAP_PERFMON. Give it to patina with \
                 `sudo setcap cap_perfmon+ep $(command -v patina)`, or run as root"
            )),
            Err(e) => Err(format!(
                "perf_event_open: {e}: this host exposes no usable branch counter (a VM may hide the PMU)"
            )),
        }
    })
    .clone()
}

/// Is `tid` (host) a thread of a descendant of `root` (host pid)?
fn descends(tid: i32, root: i32) -> bool {
    let field = |pid: i32, key: &str| -> Option<i32> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        s.lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|v| v.trim().parse().ok())
    };
    let Some(mut p) = field(tid, "Tgid:") else {
        return false;
    };
    for _ in 0..256 {
        if p == root {
            return true;
        }
        match field(p, "PPid:") {
            Some(q) if q > 1 => p = q,
            _ => return false,
        }
    }
    false
}

/// The host tid of a thread pidfd.
fn pidfd_tid(fd: RawFd) -> Option<i32> {
    let s = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .and_then(|v| v.trim().parse().ok())
        .filter(|&t: &i32| t > 0)
}

fn recv(fd: RawFd) -> io::Result<Option<Option<OwnedFd>>> {
    let mut buf = [0u8; 8];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: 8,
    };
    let mut cbuf = [0u64; 8];
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    m.msg_control = cbuf.as_mut_ptr() as *mut _;
    m.msg_controllen = std::mem::size_of_val(&cbuf);
    let r = unsafe { libc::recvmsg(fd, &mut m, libc::MSG_CMSG_CLOEXEC) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    if r == 0 {
        return Ok(None);
    }
    let mut got = None;
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&m);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let n = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / 4;
                let p = libc::CMSG_DATA(c) as *const i32;
                for i in 0..n {
                    let f = OwnedFd::from_raw_fd(*p.add(i));
                    if got.is_none() {
                        got = Some(f);
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&m, c);
        }
    }
    Ok(Some(got))
}

fn reply(fd: RawFd, r: Result<OwnedFd, i32>) {
    let val: i64 = match &r {
        Ok(_) => 0,
        Err(e) => -(*e as i64),
    };
    let bytes = val.to_le_bytes();
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut _,
        iov_len: 8,
    };
    let mut cbuf = [0u64; 4];
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    if let Ok(f) = &r {
        m.msg_control = cbuf.as_mut_ptr() as *mut _;
        m.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as usize;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&m);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as usize;
            *(libc::CMSG_DATA(c) as *mut i32) = f.as_raw_fd();
        }
    }
    unsafe { libc::sendmsg(fd, &m, libc::MSG_NOSIGNAL) };
}

/// A running broker for one incarnation.
pub struct Broker {
    ours: OwnedFd,
    thread: Option<JoinHandle<()>>,
}

/// The pair: (the sandbox end, to place at `FD_PMU`; our end, served once bwrap runs).
pub fn pair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [0i32; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(format!("socketpair: {}", io::Error::last_os_error()));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

impl Broker {
    /// Serve requests from tasks under `root` (the bwrap child's host pid).
    pub fn start(ours: OwnedFd, event: u64, root: i32) -> Result<Broker, String> {
        let fd = ours.as_raw_fd();
        let thread = std::thread::Builder::new()
            .name("patina-pmu".into())
            .spawn(move || loop {
                let req = match recv(fd) {
                    Ok(Some(r)) => r,
                    Ok(None) => return,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return,
                };
                let Some(pidfd) = req else {
                    reply(fd, Err(libc::EINVAL));
                    continue;
                };
                let r = match pidfd_tid(pidfd.as_raw_fd()) {
                    None => Err(libc::ESRCH),
                    Some(tid) if !descends(tid, root) => Err(libc::EPERM),
                    Some(tid) => {
                        perf_open(event, tid).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
                    }
                };
                drop(pidfd);
                reply(fd, r);
            })
            .map_err(|e| format!("broker thread: {e}"))?;
        Ok(Broker {
            ours,
            thread: Some(thread),
        })
    }

    /// After the sandbox is gone.
    pub fn stop(mut self) {
        unsafe { libc::shutdown(self.ours.as_raw_fd(), libc::SHUT_RDWR) };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
