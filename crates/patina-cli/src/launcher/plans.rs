//! The plan broker (load-time points): answers the runtime's request for the plan of
//! a file it is about to map executable (`proto::plan` has the protocol, `rewrite::cache` the
//! answer). It runs in the launcher, outside the sandbox: the plan cache is never reachable
//! from inside, and the runtime gets one read-only descriptor of a plan file at a time.
//!
//! The answer is a function of the file's bytes and the patina build only, so it is the same
//! on every host and in every run; making a plan costs wall time, never virtual time (the
//! guest thread that asked holds the turn and waits).

pub use crate::rewrite::cache::Planner;
use proto::plan::*;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::thread::JoinHandle;

/// One request: the file offset, the program's name for the file, and the file.
fn recv(fd: RawFd) -> io::Result<Option<(u64, String, Option<File>)>> {
    let mut buf = vec![0u8; 16 + 4096];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let mut cbuf = [0u64; 8];
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    m.msg_control = cbuf.as_mut_ptr() as *mut _;
    m.msg_controllen = std::mem::size_of_val(&cbuf) as _;
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
                    let f = File::from_raw_fd(*p.add(i));
                    if got.is_none() {
                        got = Some(f);
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&m, c);
        }
    }
    let r = r as usize;
    if r < 16 || buf[..8] != REQUEST {
        return Ok(Some((0, String::new(), None)));
    }
    let off = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let path = String::from_utf8_lossy(&buf[16..r]).to_string();
    Ok(Some((off, path, got)))
}

fn reply(fd: RawFd, w: &[u64; REPLY_WORDS], plan: Option<&File>) {
    let mut bytes = [0u8; 8 * REPLY_WORDS];
    for (i, v) in w.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&v.to_le_bytes());
    }
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut _,
        iov_len: bytes.len(),
    };
    let mut cbuf = [0u64; 4];
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    if let Some(f) = plan {
        m.msg_control = cbuf.as_mut_ptr() as *mut _;
        m.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&m);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as _;
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

impl Broker {
    /// Serve requests on `ours` (the peer of the sandbox's `FD_PLAN`) from `planner`, on the
    /// sandbox's CPU `cpu`: the guest thread that asks waits for the answer, and a wakeup on the
    /// same CPU is a plain switch, not a cross-CPU wakeup (which costs more than the answer).
    pub fn start(
        ours: OwnedFd,
        planner: Arc<Planner>,
        cpu: usize,
        busy: &'static std::sync::atomic::AtomicU64,
    ) -> Result<Broker, String> {
        let fd = ours.as_raw_fd();
        let mut cpu = Some(cpu);
        let mut token = 0u64;
        let thread = std::thread::Builder::new()
            .name("patina-plans".into())
            .spawn(move || loop {
                if let Some(c) = cpu.take() {
                    unsafe {
                        let mut set: libc::cpu_set_t = std::mem::zeroed();
                        libc::CPU_SET(c, &mut set);
                        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
                    }
                }
                let (off, path, file) = match recv(fd) {
                    Ok(Some(r)) => r,
                    Ok(None) => return,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return,
                };
                let mut w = [0u64; REPLY_WORDS];
                let Some(file) = file else {
                    w[R_STATUS] = (-(libc::EINVAL as i64)) as u64;
                    reply(fd, &w, None);
                    continue;
                };
                // How long the asking thread's wait counts as progress (`sup::stall::Planning`).
                token += 1;
                let size = file.metadata().map_or(0, |m| m.len());
                let budget = crate::rewrite::cache::planning_budget(size).as_secs();
                busy.store(
                    crate::sup::stall::planning_word(token, budget),
                    std::sync::atomic::Ordering::Relaxed,
                );
                let answer = planner.answer(&file, off, &path);
                busy.store(0, std::sync::atomic::Ordering::Relaxed);
                match answer {
                    Ok((w, plan)) => reply(fd, &w, plan.as_ref()),
                    Err(e) => {
                        eprintln!("patina: plan of {path}: {e}");
                        w[R_STATUS] = (-(libc::EIO as i64)) as u64;
                        reply(fd, &w, None);
                    }
                }
            })
            .map_err(|e| format!("plan broker thread: {e}"))?;
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
