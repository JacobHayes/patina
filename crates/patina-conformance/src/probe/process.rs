//! Identity, signal, child, wait, and process rows.

use super::*;

impl Probe {
    // ---- identity -----------------------------------------------------------

    pub fn getpid(&self) -> i64 {
        let result = self.call(Syscall::N_getpid, [0; 6]);
        self.event(Syscall::N_getpid, result)
            .norm("ret", Norm::Identity(Id::Process))
            .emit();
        result
    }

    pub fn getuid(&self) -> i64 {
        let result = self.call(Syscall::N_getuid, [0; 6]);
        self.event(Syscall::N_getuid, result)
            .norm("ret", Norm::Identity(Id::User))
            .emit();
        result
    }

    pub fn getgid(&self) -> i64 {
        let result = self.call(Syscall::N_getgid, [0; 6]);
        self.event(Syscall::N_getgid, result)
            .norm("ret", Norm::Identity(Id::Group))
            .emit();
        result
    }

    pub fn gettid(&self) -> i64 {
        let result = self.call(Syscall::N_gettid, [0; 6]);
        self.event(Syscall::N_gettid, result)
            .norm("ret", Norm::Identity(Id::Process))
            .emit();
        result
    }

    pub fn getppid(&self) -> i64 {
        let result = self.call(Syscall::N_getppid, [0; 6]);
        self.event(Syscall::N_getppid, result)
            .norm("ret", Norm::Identity(Id::Process))
            .emit();
        result
    }

    pub fn getpgid(&self, pid: i32) -> i64 {
        let result = self.call(Syscall::N_getpgid, [pid as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_getpgid, if result >= 0 { 0 } else { result })
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity(Id::Process))
            .field("positive", result > 0)
            .emit();
        result
    }

    pub fn getsid(&self, pid: i32) -> i64 {
        let result = self.call(Syscall::N_getsid, [pid as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_getsid, if result >= 0 { 0 } else { result })
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity(Id::Process))
            .field("positive", result > 0)
            .emit();
        result
    }

    pub fn kill(&self, pid: i32, sig: i32) -> i64 {
        let result = self.call(Syscall::N_kill, [pid as i64, sig as i64, 0, 0, 0, 0]);
        self.event(Syscall::N_kill, result)
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity(Id::Process))
            .arg("sig", sig)
            .emit();
        result
    }

    pub fn tkill(&self, tid: i32, sig: i32) -> i64 {
        let result = self.call(Syscall::N_tkill, [tid as i64, sig as i64, 0, 0, 0, 0]);
        self.event(Syscall::N_tkill, result)
            .arg("tid", tid)
            .norm("args.tid", Norm::Identity(Id::Process))
            .arg("sig", sig)
            .emit();
        result
    }

    pub fn tgkill(&self, tgid: i32, tid: i32, sig: i32) -> i64 {
        let result = self.call(
            Syscall::N_tgkill,
            [tgid as i64, tid as i64, sig as i64, 0, 0, 0],
        );
        self.event(Syscall::N_tgkill, result)
            .arg("tgid", tgid)
            .norm("args.tgid", Norm::Identity(Id::Process))
            .arg("tid", tid)
            .norm("args.tid", Norm::Identity(Id::Process))
            .arg("sig", sig)
            .emit();
        result
    }

    pub fn rt_sigprocmask(
        &self,
        how: i32,
        set: Option<&libc::sigset_t>,
        old: Option<&mut libc::sigset_t>,
        sigset_size: usize,
    ) -> i64 {
        let result = self.call(
            Syscall::N_rt_sigprocmask,
            [
                how as i64,
                set.map_or(0, |s| s as *const libc::sigset_t as i64),
                old.map_or(0, |s| s as *mut libc::sigset_t as i64),
                sigset_size as i64,
                0,
                0,
            ],
        );
        self.event(Syscall::N_rt_sigprocmask, result)
            .arg("how", how)
            .arg("sigset_size", sigset_size)
            .emit();
        result
    }

    pub fn rt_sigpending(&self, set: &mut libc::sigset_t, sigset_size: usize) -> i64 {
        let result = self.call(
            Syscall::N_rt_sigpending,
            [
                set as *mut libc::sigset_t as i64,
                sigset_size as i64,
                0,
                0,
                0,
                0,
            ],
        );
        self.event(Syscall::N_rt_sigpending, result)
            .arg("sigset_size", sigset_size)
            .emit();
        result
    }

    pub fn rt_sigtimedwait(
        &self,
        set: &libc::sigset_t,
        info: Option<&mut libc::siginfo_t>,
        timeout_ns: Option<i64>,
        sigset_size: usize,
    ) -> i64 {
        let timeout = timeout_ns.map(|ns| libc::timespec {
            tv_sec: ns / 1_000_000_000,
            tv_nsec: ns % 1_000_000_000,
        });
        let info_ptr = info
            .as_ref()
            .map_or(0, |i| (*i as *const libc::siginfo_t).cast_mut() as i64);
        let result = self.call(
            Syscall::N_rt_sigtimedwait,
            [
                set as *const libc::sigset_t as i64,
                info_ptr,
                timeout
                    .as_ref()
                    .map_or(0, |ts| ts as *const libc::timespec as i64),
                sigset_size as i64,
                0,
                0,
            ],
        );
        // The queued payload is only meaningful (and only kernel-filled) for
        // SI_QUEUE; every other code records 0 so the field is stable.
        let si_int = info
            .as_ref()
            .filter(|i| result > 0 && i.si_code == libc::SI_QUEUE)
            .map_or(0, |i| unsafe { i.si_value().sival_ptr as usize as i32 });
        self.event(Syscall::N_rt_sigtimedwait, result)
            .arg("timeout_ns", timeout_ns.map_or(Value::Null, Value::from))
            .arg("sigset_size", sigset_size)
            .field("si_signo", info.as_ref().map_or(0, |i| i.si_signo))
            .field("si_code", info.as_ref().map_or(0, |i| i.si_code))
            .field("si_int", si_int)
            .emit();
        result
    }

    pub fn rt_sigsuspend(&self, set: &libc::sigset_t, sigset_size: usize) -> i64 {
        let result = self.call(
            Syscall::N_rt_sigsuspend,
            [
                set as *const libc::sigset_t as i64,
                sigset_size as i64,
                0,
                0,
                0,
                0,
            ],
        );
        self.event(Syscall::N_rt_sigsuspend, result)
            .arg("sigset_size", sigset_size)
            .emit();
        result
    }

    pub fn signalfd4(&self, fd: i32, set: &libc::sigset_t, flags: i32) -> i32 {
        let result = self.call(
            Syscall::N_signalfd4,
            [
                fd as i64,
                set as *const libc::sigset_t as i64,
                8,
                flags as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_signalfd4, result).arg("flags", flags);
        self.fd_arg(builder, "fd", fd)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    #[cfg(target_arch = "x86_64")]
    pub fn signalfd(&self, fd: i32, set: &libc::sigset_t) -> i32 {
        let result = self.call(
            Syscall::N_signalfd,
            [fd as i64, set as *const libc::sigset_t as i64, 8, 0, 0, 0],
        );
        let builder = self.event(Syscall::N_signalfd, result);
        self.fd_arg(builder, "fd", fd)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// One `read` of a whole `signalfd_siginfo` from signalfd `fd`, and the
    /// siginfo when it read one: its signal, code, `sival_int` and sender
    /// (by identity relation) are recorded.
    pub fn read_signalfd(&self, fd: i32) -> Option<libc::signalfd_siginfo> {
        let size = std::mem::size_of::<libc::signalfd_siginfo>();
        // SAFETY: all-zero is a valid signalfd_siginfo.
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        let n = self.call(
            Syscall::N_read,
            [
                fd as i64,
                &mut info as *mut libc::signalfd_siginfo as i64,
                size as i64,
                0,
                0,
                0,
            ],
        );
        self.fd_arg(self.rec.event("read", n), "fd", fd)
            .arg("len", size)
            .emit();
        if n != size as i64 {
            return None;
        }
        self.rec
            .event("signalfd_siginfo", 0)
            .field("ssi_signo", info.ssi_signo)
            .field("ssi_code", info.ssi_code)
            .field("ssi_pid", info.ssi_pid)
            .norm("fields.ssi_pid", Norm::Identity(Id::Process))
            .field("ssi_uid", info.ssi_uid)
            .norm("fields.ssi_uid", Norm::Identity(Id::User))
            .field("ssi_int", info.ssi_int)
            .emit();
        Some(info)
    }

    pub fn sigaltstack(&self, new: Option<&libc::stack_t>, old: Option<&mut libc::stack_t>) -> i64 {
        let old_ptr = old
            .as_ref()
            .map_or(0, |s| (*s as *const libc::stack_t).cast_mut() as i64);
        let result = self.call(
            Syscall::N_sigaltstack,
            [
                new.map_or(0, |s| s as *const libc::stack_t as i64),
                old_ptr,
                0,
                0,
                0,
                0,
            ],
        );
        let flags = old.as_ref().map_or(-1, |s| s.ss_flags);
        self.event(Syscall::N_sigaltstack, result)
            .field("old_flags", flags)
            .emit();
        result
    }

    pub fn rt_sigaction_raw(&self, signum: i32, size: usize) -> i64 {
        let result = self.call(
            Syscall::N_rt_sigaction,
            [signum as i64, 0, 0, size as i64, 0, 0],
        );
        self.event(Syscall::N_rt_sigaction, result)
            .arg("signum", signum)
            .arg("sigset_size", size)
            .emit();
        result
    }

    pub fn rt_sigqueueinfo(&self, pid: i32, sig: i32, info: &libc::siginfo_t) -> i64 {
        let result = self.call(
            Syscall::N_rt_sigqueueinfo,
            [
                pid as i64,
                sig as i64,
                info as *const libc::siginfo_t as i64,
                0,
                0,
                0,
            ],
        );
        self.event(Syscall::N_rt_sigqueueinfo, result)
            .arg("pid", pid)
            .norm("args.pid", Norm::Identity(Id::Process))
            .arg("sig", sig)
            .arg("si_code", info.si_code)
            .emit();
        result
    }

    pub fn rt_tgsigqueueinfo(&self, tgid: i32, tid: i32, sig: i32, info: &libc::siginfo_t) -> i64 {
        let result = self.call(
            Syscall::N_rt_tgsigqueueinfo,
            [
                tgid as i64,
                tid as i64,
                sig as i64,
                info as *const libc::siginfo_t as i64,
                0,
                0,
            ],
        );
        self.event(Syscall::N_rt_tgsigqueueinfo, result)
            .arg("tgid", tgid)
            .norm("args.tgid", Norm::Identity(Id::Process))
            .arg("tid", tid)
            .norm("args.tid", Norm::Identity(Id::Process))
            .arg("sig", sig)
            .arg("si_code", info.si_code)
            .emit();
        result
    }

    pub fn set_tid_address(&self, ptr: *mut i32) -> i64 {
        let result = self.call(Syscall::N_set_tid_address, [ptr as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_set_tid_address, result)
            .norm("ret", Norm::Identity(Id::Process))
            .emit();
        result
    }

    pub fn prctl(&self, option: i32, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
        let result = self.call(
            Syscall::N_prctl,
            [option as i64, a2 as i64, a3 as i64, a4 as i64, a5 as i64, 0],
        );
        self.event(Syscall::N_prctl, result)
            .arg("option", option)
            .emit();
        result
    }

    pub fn wait4(&self, pid: i32, options: i32) -> (i64, i32) {
        let mut status = 0;
        let result = self.call(
            Syscall::N_wait4,
            [
                pid as i64,
                &mut status as *mut i32 as i64,
                options as i64,
                0,
                0,
                0,
            ],
        );
        self.event(Syscall::N_wait4, result)
            .arg("pid", pid)
            .arg("options", options)
            .field("status", status)
            .emit();
        (result, status)
    }

    pub fn waitid(&self, idtype: i32, id: u32, options: i32) -> (i64, i32) {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = self.call(
            Syscall::N_waitid,
            [
                idtype as i64,
                id as i64,
                &mut info as *mut libc::siginfo_t as i64,
                options as i64,
                0,
                0,
            ],
        );
        self.event(Syscall::N_waitid, result)
            .arg("idtype", idtype)
            .arg("id", id)
            .arg("options", options)
            .field("si_signo", info.si_signo)
            .field("si_code", info.si_code)
            .emit();
        (result, info.si_code)
    }

    // ---- signals, threads and process rows (the signals family) -------------

    /// Announce that the scenario's next act ends the process on `signal`
    /// (`SIG_DFL` termination). A native signal death is an oracle only when
    /// this is the last recorded event, and the patina run must then end the
    /// same way.
    pub fn dies_by(&self, signal: i32) {
        self.rec
            .event(EXPECT_DEATH_OP, 0)
            .arg("signal", signal)
            .emit();
    }

    /// Announce that the process ends by exiting with `code` (not 0): a
    /// native exit with another status is an oracle only when this is the
    /// last recorded event, and the patina run must then end the same way.
    pub fn exits_with(&self, code: i32) {
        self.rec.event(EXPECT_EXIT_OP, 0).arg("code", code).emit();
    }

    /// `pause`: returns only when a handled signal was delivered (`-EINTR`).
    /// An x86_64 legacy row; the generic table's shape is `ppoll` over no
    /// descriptors.
    pub fn pause(&self) -> i64 {
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_pause, [0; 6]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = self.legacy(
            // SAFETY: no arguments.
            || unsafe { libc::pause() } as i64,
            Syscall::N_ppoll,
            [0, 0, 0, 0, SIGSET_BYTES, 0],
        );
        self.rec.event("pause", result).emit();
        result
    }

    pub fn socketpair(&self, domain: i32, kind: i32, protocol: i32) -> (i64, [i32; 2]) {
        let mut fds = [-1i32; 2];
        let result = self.call(
            Syscall::N_socketpair,
            [
                domain as i64,
                kind as i64,
                protocol as i64,
                fds.as_mut_ptr() as i64,
                0,
                0,
            ],
        );
        let builder = self
            .event(Syscall::N_socketpair, result)
            .arg("domain", domain)
            .arg("type", kind)
            .arg("protocol", protocol);
        let builder = if result >= 0 {
            builder
                .field("first", fds[0])
                .norm("fields.first", Norm::Relative("fd"))
                .field("second", fds[1])
                .norm("fields.second", Norm::Relative("fd"))
        } else {
            builder
        };
        builder.emit();
        (result, fds)
    }

    /// The raw `exit` row (one thread ends; the process lives while others
    /// run). The event is recorded BEFORE the call, which never returns.
    pub fn exit_thread(&self, code: i32) -> ! {
        self.event(Syscall::N_exit, 0).arg("code", code).emit();
        self.call(Syscall::N_exit, [code as i64, 0, 0, 0, 0, 0]);
        unreachable!("exit returned")
    }

    /// `exit_group`: the whole process ends with `code`. Recorded before the
    /// call, which never returns.
    pub fn exit_group(&self, code: i32) -> ! {
        self.event(Syscall::N_exit_group, 0)
            .arg("code", code)
            .emit();
        self.call(Syscall::N_exit_group, [code as i64, 0, 0, 0, 0, 0]);
        unreachable!("exit_group returned")
    }

    /// `nanosleep` recording whether an interrupted sleep reported a remaining
    /// time inside `(0, request]` (the kernel fills `rem` on `EINTR`; a
    /// completed sleep leaves it alone). Returns the result and `rem` in ns.
    pub fn nanosleep_rem(&self, sec: i64, nsec: i64) -> (i64, i64) {
        let req = libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        };
        let mut rem = libc::timespec {
            tv_sec: -1,
            tv_nsec: -1,
        };
        let result = self.call(
            Syscall::N_nanosleep,
            [
                &req as *const libc::timespec as i64,
                &mut rem as *mut libc::timespec as i64,
                0,
                0,
                0,
                0,
            ],
        );
        let request_ns = sec * 1_000_000_000 + nsec;
        let rem_ns = rem.tv_sec * 1_000_000_000 + rem.tv_nsec;
        let builder = self
            .event(Syscall::N_nanosleep, result)
            .arg("sec", sec)
            .arg("nsec", nsec);
        let builder = if result == neg(libc::EINTR) {
            builder.field("remain_in_range", rem_ns > 0 && rem_ns <= request_ns)
        } else {
            builder
        };
        builder.emit();
        (result, rem_ns)
    }

    /// `clock_nanosleep` (relative unless `TIMER_ABSTIME`) with the same
    /// remaining-time observation as [`Self::nanosleep_rem`]; for an absolute
    /// sleep the kernel leaves `rem` untouched, recorded as `remain_untouched`.
    pub fn clock_nanosleep_rem(&self, clock: i32, flags: i32, sec: i64, nsec: i64) -> (i64, i64) {
        self.clock_sleep(clock, flags, (sec, nsec), true)
    }

    /// `clock_nanosleep(clock, flags, &(sec, nsec), rem)`, `rem` NULL
    /// unless `with_rem`.
    pub(super) fn clock_sleep(
        &self,
        clock: i32,
        flags: i32,
        (sec, nsec): (i64, i64),
        with_rem: bool,
    ) -> (i64, i64) {
        let req = libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        };
        let mut rem = libc::timespec {
            tv_sec: -1,
            tv_nsec: -1,
        };
        let rem_ptr = if with_rem {
            &mut rem as *mut libc::timespec as i64
        } else {
            0
        };
        let result = self.call(
            Syscall::N_clock_nanosleep,
            [
                clock as i64,
                flags as i64,
                &req as *const libc::timespec as i64,
                rem_ptr,
                0,
                0,
            ],
        );
        let request_ns = sec * 1_000_000_000 + nsec;
        let rem_ns = rem.tv_sec * 1_000_000_000 + rem.tv_nsec;
        let absolute = flags & libc::TIMER_ABSTIME != 0;
        let builder = self
            .event(Syscall::N_clock_nanosleep, result)
            .arg("clock", clock)
            .arg("flags", flags);
        // An absolute deadline is a clock reading, so it is not a stable arg.
        let builder = if absolute {
            builder.arg("absolute", true)
        } else {
            builder.arg("sec", sec).arg("nsec", nsec)
        };
        let builder = if with_rem && result == neg(libc::EINTR) {
            if absolute {
                builder.field("remain_untouched", rem.tv_sec == -1 && rem.tv_nsec == -1)
            } else {
                builder.field("remain_in_range", rem_ns > 0 && rem_ns <= request_ns)
            }
        } else {
            builder
        };
        builder.emit();
        (result, rem_ns)
    }

    /// Raw `rt_sigaction(signum, act, oldact, 8)` with the KERNEL struct
    /// layout. Records which pointers were passed and, on success with an
    /// `oldact`, the previous action's compared flags and whether it was
    /// `SIG_DFL`/`SIG_IGN`/a handler (`old_kind`), never a code address.
    pub fn rt_sigaction_install(
        &self,
        signum: i32,
        act: Option<&KernelSigaction>,
        old: Option<&mut KernelSigaction>,
    ) -> i64 {
        let old_ptr = old
            .as_ref()
            .map_or(0, |o| (*o as *const KernelSigaction).cast_mut() as i64);
        let result = self.call(
            Syscall::N_rt_sigaction,
            [
                signum as i64,
                act.map_or(0, |a| a as *const KernelSigaction as i64),
                old_ptr,
                8,
                0,
                0,
            ],
        );
        let builder = self
            .event(Syscall::N_rt_sigaction, result)
            .arg("signum", signum)
            .arg("has_act", act.is_some())
            .arg("has_oldact", old.is_some());
        let builder = match (result, old) {
            (0, Some(old)) => builder
                .field(
                    "old_kind",
                    match old.handler {
                        0 => "SIG_DFL",
                        1 => "SIG_IGN",
                        _ => "handler",
                    },
                )
                .field("old_flags", old.flags & SA_FLAGS_COMPARED)
                .field(
                    "old_has_restorer",
                    old.flags & SA_RESTORER != 0 && old.restorer != 0,
                ),
            _ => builder,
        };
        builder.emit();
        result
    }

    /// Query an action raw (`act = NULL`), returning it for the scenario's own
    /// use (the restorer a raw install needs).
    pub fn rt_sigaction_query(&self, signum: i32) -> (i64, KernelSigaction) {
        let mut old = KernelSigaction::default();
        let result = self.rt_sigaction_install(signum, None, Some(&mut old));
        (result, old)
    }

    /// A scenario-side observation with no kernel call behind it: an ordering
    /// mark (`helper_kill` right before a helper thread signals the main
    /// thread) or a fact a handler recorded. `fields` are recorded verbatim.
    pub fn mark(&self, op: &str, fields: &[(&str, Value)]) {
        let mut builder = self.rec.event(op, 0);
        for (key, value) in fields {
            builder = builder.field(key, value.clone());
        }
        builder.emit();
    }

    /// A row whose first argument is a descriptor and whose others are plain
    /// integers the scenario chose, recorded under `names`.
    pub(super) fn fd_ints(&self, row: Syscall, fd: i32, names: &[&str], values: &[i64]) -> i64 {
        let mut args = [fd as i64, 0, 0, 0, 0, 0];
        args[1..=values.len()].copy_from_slice(values);
        let result = self.call(row, args);
        let mut builder = self.fd_arg(self.event(row, result), "fd", fd);
        for (name, value) in names.iter().zip(values) {
            builder = builder.arg(name, *value);
        }
        builder.emit();
        result
    }

    /// `row` issued with `args` the scenario built (pointers to its own
    /// structures among them) and recorded under `named`: descriptive values
    /// the scenario chooses, never an address, so the event compares across
    /// runs.
    pub fn observed(&self, row: Syscall, args: Args, named: &[(&str, Value)]) -> i64 {
        let result = self.call(row, args);
        let mut builder = self.event(row, result);
        for (name, value) in named {
            builder = builder.arg(name, value.clone());
        }
        builder.emit();
        result
    }

    /// A row past the virtual ABI level, issued with plain integer arguments
    /// recorded verbatim (NULL pointers as 0): what is under test is the
    /// number's absence, so nothing is interpreted.
    pub fn absent(&self, row: Syscall, args: &[(&str, i64)]) -> i64 {
        let mut raw = [0i64; 6];
        for (slot, (_, value)) in raw.iter_mut().zip(args) {
            *slot = *value;
        }
        let result = self.call(row, raw);
        let mut builder = self.event(row, result);
        for (name, value) in args {
            builder = builder.arg(name, *value);
        }
        builder.emit();
        result
    }
}
