//! signal/wait — libc sigwait/sigtimedwait shapes plus signalfd/signalfd4,
//! including SFD_NONBLOCK/CLOEXEC and the stable signalfd_siginfo sender fields.

#[cfg(target_os = "linux")]
mod scenario {
    #[path = "support.rs"]
    mod support;

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
        p.rec.event("read", n)
            .arg("fd", fd)
            .norm("args.fd", Norm::Relative("fd"))
            .arg("len", size_of::<signalfd_siginfo>())
            .emit();
        if n == size_of::<signalfd_siginfo>() as i64 {
            p.rec.event("signalfd_siginfo", 0)
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
            info._pad[0] = pid;
            info._pad[1] = uid as i32;
            info._pad[2] = value;
        }
        info
    }

    pub fn run(p: &Probe) {
        let pid = p.getpid() as pid_t;
        let uid = p.getuid() as uid_t;
        let sig = 34;
        let set = support::one_set(sig);
        p.check("block realtime signal", p.rt_sigprocmask(SIG_BLOCK, Some(&set), None, 8) == 0);

        let sfd = p.signalfd4(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
        p.require("signalfd4", sfd >= 0);
        p.check("empty nonblocking signalfd read is EAGAIN", p.read(sfd, size_of::<signalfd_siginfo>()).0 == neg(EAGAIN));
        p.check("signalfd fd has FD_CLOEXEC", p.fcntl(sfd, F_GETFD, 0) == FD_CLOEXEC as i64);
        let q = queued_info(pid, uid, sig, 0x1234);
        p.check("queue signal for signalfd", p.rt_sigqueueinfo(pid, sig, &q) == 0);
        let info = read_sfd(p, sfd).expect("queued signalfd read");
        p.check("signalfd reports the signal number", info.ssi_signo == sig as u32);
        p.check("signalfd reports SI_QUEUE", info.ssi_code == SI_QUEUE);
        p.check("signalfd exposes nonzero sender metadata", info.ssi_pid != 0 && info.ssi_uid != 0);

        let sfd2 = p.signalfd(-1, &set);
        p.require("legacy signalfd", sfd2 >= 0);
        p.check("legacy signalfd does not set CLOEXEC", p.fcntl(sfd2, F_GETFD, 0) == 0);
        let q = queued_info(pid, uid, sig, 0x55);
        p.check("queue signal for sigtimedwait", p.rt_sigqueueinfo(pid, sig, &q) == 0);
        let mut si: siginfo_t = unsafe { std::mem::zeroed() };
        p.check("rt_sigtimedwait returns the signum", p.rt_sigtimedwait(&set, Some(&mut si), Some(0), 8) == sig as i64);
        p.check("rt_sigtimedwait preserves SI_QUEUE", si.si_code == SI_QUEUE);
        p.check("rt_sigtimedwait fills siginfo", si.si_signo == sig && si.si_code == SI_QUEUE);
        p.close(sfd);
        p.close(sfd2);
        p.rt_sigprocmask(SIG_UNBLOCK, Some(&set), None, 8);
    }
}

syscall_conformance::probe_main!("signal/wait", scenario::run);
