//! thread/lifecycle — set_tid_address return value, futex mismatch semantics,
//! and main-thread raw exit while another thread keeps the process alive
//! (checked in a child oracle).

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use std::sync::atomic::AtomicU32;
    use std::thread;
    use syscall_conformance::calls::{neg, Probe};

    const WAIT: i32 = FUTEX_WAIT;

    fn main_exit_child_status() -> c_int {
        unsafe {
            let mut fds = [0; 2];
            pipe(fds.as_mut_ptr());
            let pid = fork();
            if pid == 0 {
                close(fds[0]);
                thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(80));
                    write(fds[1], b"a".as_ptr() as *const _, 1);
                    close(fds[1]);
                });
                syscall(SYS_exit, 0);
                _exit(99);
            }
            close(fds[1]);
            let mut b = [0u8; 1];
            let n = read(fds[0], b.as_mut_ptr() as *mut _, 1);
            close(fds[0]);
            let mut status = 0;
            waitpid(pid, &mut status, 0);
            if n == 1 { status } else { 0x7f00 }
        }
    }

    pub fn run(p: &Probe) {
        let word = AtomicU32::new(0);
        let mut own = 0i32;
        let my_tid = p.set_tid_address(&mut own as *mut i32);
        p.check("set_tid_address returns the caller tid", my_tid == p.gettid());

        let st = main_exit_child_status();
        p.rec.event("wait_status", 0)
            .arg("case", "main-thread-raw-exit")
            .field("exited", WIFEXITED(st))
            .field("code", WEXITSTATUS(st))
            .emit();
        p.check("main thread raw exit leaves process alive until other threads finish", WIFEXITED(st) && WEXITSTATUS(st) == 0);
        p.check("futex wait with mismatched value is EAGAIN", p.futex(&word, WAIT, 1, None) == neg(EAGAIN));
    }
}

syscall_conformance::probe_main!("thread/lifecycle", scenario::run);
