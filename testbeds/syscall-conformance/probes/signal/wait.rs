//! signal/wait — synchronous dequeue rows: `rt_sigtimedwait` returns a
//! queued payload with `SI_QUEUE`, `signalfd`/`signalfd4` (flags, CLOEXEC,
//! the 128-byte `signalfd_siginfo` with its sender fields), a signalfd in
//! epoll is readable exactly while a matching signal is pending
//! (fs/signalfd.c signalfd_poll: EPOLLIN iff next_signal(&pending, &mask)),
//! and an unblocked signal with a handler is handled, never queued to the
//! signalfd (kernel/signal.c: a signalfd only dequeues what the mask keeps
//! pending).

#[cfg(target_os = "linux")]
mod scenario {
    use syscall_conformance::signals as support;

    use libc::*;
    use std::mem::size_of;
    use syscall_conformance::calls::{neg, Probe};
    use syscall_conformance::observe::Norm;
    use syscall_conformance::vehicle::Sys;

    fn read_sfd(p: &Probe, fd: i32) -> Option<signalfd_siginfo> {
        let mut info: signalfd_siginfo = unsafe { std::mem::zeroed() };
        let n = p.call_unrecorded(
            Sys::Read,
            [
                fd as i64,
                &mut info as *mut signalfd_siginfo as i64,
                size_of::<signalfd_siginfo>() as i64,
                0,
                0,
                0,
            ],
        );
        p.rec
            .event("read", n)
            .arg("fd", fd)
            .norm("args.fd", Norm::Relative("fd"))
            .arg("len", size_of::<signalfd_siginfo>())
            .emit();
        if n == size_of::<signalfd_siginfo>() as i64 {
            p.rec
                .event("signalfd_siginfo", 0)
                .field("ssi_signo", info.ssi_signo)
                .field("ssi_code", info.ssi_code)
                .field("ssi_pid", info.ssi_pid)
                .norm("fields.ssi_pid", Norm::Identity)
                .field("ssi_uid", info.ssi_uid)
                .norm("fields.ssi_uid", Norm::Identity)
                .field("ssi_int", info.ssi_int)
                .emit();
            Some(info)
        } else {
            None
        }
    }

    fn queued_info(pid: pid_t, uid: uid_t, sig: c_int, value: i32) -> siginfo_t {
        let mut info: siginfo_t = unsafe { std::mem::zeroed() };
        info.si_signo = sig;
        info.si_code = SI_QUEUE;
        #[allow(deprecated)]
        {
            // The union starts at offset 16: _pad[0] is padding, then
            // si_pid, si_uid, si_value (the layout glibc's sigqueue fills).
            info._pad[1] = pid;
            info._pad[2] = uid as i32;
            info._pad[3] = value;
        }
        info
    }

    pub fn run(p: &Probe) {
        support::reset();
        let pid = p.getpid() as pid_t;
        let uid = p.getuid() as uid_t;
        let sig = 34;
        let set = support::one_set(sig);
        p.check(
            "block realtime signal",
            p.rt_sigprocmask(SIG_BLOCK, Some(&set), None, 8) == 0,
        );

        let sfd = p.signalfd4(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
        p.require("signalfd4", sfd >= 0);
        p.check(
            "empty nonblocking signalfd read is EAGAIN",
            p.read(sfd, size_of::<signalfd_siginfo>()).0 == neg(EAGAIN),
        );
        p.check(
            "a signalfd read buffer shorter than signalfd_siginfo is EINVAL",
            p.read(sfd, 64).0 == neg(EINVAL),
        );
        p.check(
            "signalfd fd has FD_CLOEXEC",
            p.fcntl(sfd, F_GETFD, 0) == FD_CLOEXEC as i64,
        );
        p.check(
            "signalfd4 with an unknown flag is EINVAL",
            p.signalfd4(-1, &set, 0x4000) == neg(EINVAL) as i32,
        );
        let q = queued_info(pid, uid, sig, 0x1234);
        p.check(
            "queue signal for signalfd",
            p.rt_sigqueueinfo(pid, sig, &q) == 0,
        );
        let info = read_sfd(p, sfd).expect("queued signalfd read");
        p.check(
            "signalfd reports the signal number",
            info.ssi_signo == sig as u32,
        );
        p.check("signalfd reports SI_QUEUE", info.ssi_code == SI_QUEUE);
        p.check(
            "signalfd carries the queued payload",
            info.ssi_int == 0x1234,
        );
        p.check(
            "signalfd exposes the sender identity",
            info.ssi_pid == pid as u32 && info.ssi_uid == uid,
        );

        // Readiness: only while a matching signal is pending.
        let epfd = p.epoll_create1(0);
        p.require("epoll_create1", epfd >= 0);
        p.check(
            "watch the signalfd",
            p.epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, EPOLLIN as u32, 9) == 0,
        );
        let (n, _) = p.epoll_wait(epfd, 4, 0);
        p.check("an empty signalfd is not readable", n == 0);
        p.check("kill(self) with the signal blocked", p.kill(pid, sig) == 0);
        let (n, events) = p.epoll_wait(epfd, 4, 0);
        p.check(
            "a pending matching signal makes the signalfd readable",
            n == 1 && events == vec![(9, EPOLLIN as u32)],
        );
        p.check(
            "the read dequeues it",
            read_sfd(p, sfd).is_some_and(|i| i.ssi_signo == sig as u32 && i.ssi_code == SI_USER),
        );
        let (n, _) = p.epoll_wait(epfd, 4, 0);
        p.check("after the read the signalfd is not readable", n == 0);

        // An unblocked handled signal is delivered, never queued to the signalfd.
        support::install(SIGUSR2, 0, false);
        let both = support::set_of(&[sig, SIGUSR2]);
        let sfd_both = p.signalfd4(-1, &both, SFD_NONBLOCK);
        p.require("signalfd4 over {34, SIGUSR2}", sfd_both >= 0);
        p.check(
            "kill(self, SIGUSR2) while unblocked with a handler",
            p.kill(pid, SIGUSR2) == 0,
        );
        p.check(
            "the handler ran before kill returned",
            support::count() == 1,
        );
        p.check(
            "nothing reached the signalfd",
            p.read(sfd_both, size_of::<signalfd_siginfo>()).0 == neg(EAGAIN),
        );
        p.check(
            "signalfd4(fd, newmask) narrows an existing signalfd",
            p.signalfd4(sfd_both, &set, SFD_NONBLOCK) == sfd_both,
        );

        let sfd2 = if Sys::Signalfd.has_number() {
            let sfd2 = p.signalfd(-1, &set);
            p.require("legacy signalfd", sfd2 >= 0);
            p.check(
                "legacy signalfd does not set CLOEXEC",
                p.fcntl(sfd2, F_GETFD, 0) == 0,
            );
            Some(sfd2)
        } else {
            eprintln!("signal/wait: SKIPPED 1 legacy signalfd row (no architecture number)");
            None
        };
        let q = queued_info(pid, uid, sig, 0x55);
        p.check(
            "queue signal for sigtimedwait",
            p.rt_sigqueueinfo(pid, sig, &q) == 0,
        );
        let mut si: siginfo_t = unsafe { std::mem::zeroed() };
        p.check(
            "rt_sigtimedwait returns the signum",
            p.rt_sigtimedwait(&set, Some(&mut si), Some(0), 8) == sig as i64,
        );
        p.check("rt_sigtimedwait preserves SI_QUEUE", si.si_code == SI_QUEUE);
        p.check(
            "rt_sigtimedwait fills siginfo",
            si.si_signo == sig && si.si_code == SI_QUEUE,
        );
        p.check(
            "rt_sigtimedwait with a sigset size other than 8 is EINVAL",
            p.rt_sigtimedwait(&set, Some(&mut si), Some(0), 4) == neg(EINVAL),
        );
        p.check(
            "rt_sigtimedwait with a negative timeout is EINVAL",
            p.rt_sigtimedwait(&set, Some(&mut si), Some(-1), 8) == neg(EINVAL),
        );
        p.close(sfd);
        p.close(sfd_both);
        if let Some(sfd2) = sfd2 {
            p.close(sfd2);
        }
        p.close(epfd);
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&set), None, 8);
    }
}

syscall_conformance::probe_main!("signal/wait", scenario::run);
