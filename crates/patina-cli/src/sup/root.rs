//! The roots of guest process trees the supervisor forks itself: main's command, and main's
//! `ready` probe runner (`ready`). Each is forked with the descriptors the first had
//! (`Roots::fds`) and the run's environment, the runtime executed from `FD_RT`.

use super::{Sup, Verdict};
use proto::layout::*;
use std::ffi::CString;

/// A root's command: the program's guest path and the runtime's arguments (`rt`, the program,
/// its argv).
#[derive(Clone, Debug)]
pub struct Cmd {
    pub exe: String,
    pub argv: Vec<String>,
}

#[derive(Default)]
pub struct Roots {
    /// The descriptors the first root was forked with, and the environment every root gets.
    pub fds: Vec<i32>,
    pub env: Vec<CString>,
}

/// The descriptors this process has open.
pub fn open_fds() -> Vec<i32> {
    let mut v: Vec<i32> = std::fs::read_dir("/proc/self/fd")
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
                .collect()
        })
        .unwrap_or_default();
    // Not the directory's own descriptor, closed by now.
    v.retain(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
    v.sort();
    v
}

impl Sup {
    /// Fork a root, as `main` forked the first: the same descriptors, process
    /// state and environment, the runtime executed from `FD_RT`.
    pub(super) fn fork_root(&mut self, cmd: &Cmd) -> i32 {
        let cs = |v: &[String]| -> Vec<CString> {
            v.iter()
                .map(|s| CString::new(s.as_bytes()).unwrap_or_default())
                .collect()
        };
        let argv_c = cs(&cmd.argv);
        let mut argv: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
        argv.push(std::ptr::null());
        let mut envp: Vec<*const libc::c_char> =
            self.roots.env.iter().map(|c| c.as_ptr()).collect();
        envp.push(std::ptr::null());
        let mut close: Vec<i32> = open_fds()
            .into_iter()
            .filter(|f| *f > 2 && !self.roots.fds.contains(f))
            .collect();
        close.extend([FD_OUTCOME, FD_EXPORT, FD_SHM]);
        if self.machine_count() > 0 {
            close.push(FD_MACHINES);
        }
        let empty = c"";
        let guest_cpu = self
            .ctl
            .guest_cpu
            .load(std::sync::atomic::Ordering::Relaxed);
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            self.finish(Verdict::new("infra", "fork failed"));
        }
        if pid == 0 {
            unsafe {
                if guest_cpu != u64::MAX {
                    let mut set: libc::cpu_set_t = std::mem::zeroed();
                    libc::CPU_SET(guest_cpu as usize, &mut set);
                    let _ =
                        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
                }
                for fd in &close {
                    libc::close(*fd);
                }
                if !super::inherit::child() {
                    libc::_exit(126);
                }
                libc::syscall(
                    libc::SYS_execveat,
                    FD_RT,
                    empty.as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
                libc::_exit(127);
            }
        }
        pid
    }
}
