//! Descriptor readiness and futex rows.

use super::*;

impl Probe {
    // ---- readiness ----------------------------------------------------------

    pub fn epoll_create1(&self, flags: i32) -> i32 {
        let result = self.call(Syscall::N_epoll_create1, [flags as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_epoll_create1, result)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    pub fn epoll_ctl(&self, epfd: i32, op: i32, fd: i32, events: u32, data: u64) -> i64 {
        let mut event = libc::epoll_event { events, u64: data };
        let result = self.call(
            Syscall::N_epoll_ctl,
            [
                epfd as i64,
                op as i64,
                fd as i64,
                &mut event as *mut libc::epoll_event as i64,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_epoll_ctl, result);
        let builder = self.fd_arg(builder, "epfd", epfd).arg("op", op);
        self.fd_arg(builder, "fd", fd)
            .arg("events", events)
            .arg("data", data)
            .emit();
        result
    }

    /// `epoll_wait`; the delivered set is recorded sorted by `data` (arrival
    /// order is the host's business).
    pub fn epoll_wait(&self, epfd: i32, maxevents: i32, timeout_ms: i32) -> (i64, Vec<(u64, u32)>) {
        let mut events: Vec<libc::epoll_event> =
            vec![libc::epoll_event { events: 0, u64: 0 }; maxevents.max(1) as usize];
        let args = [
            epfd as i64,
            events.as_mut_ptr() as i64,
            maxevents as i64,
            timeout_ms as i64,
            0,
            0,
        ];
        // The generic (arm64) table has no `epoll_wait` row: there the kernel
        // shape is `epoll_pwait` with a NULL sigmask, and only the libc vehicle
        // calls glibc's `epoll_wait`.
        #[cfg(target_arch = "x86_64")]
        let result = self.call(Syscall::N_epoll_wait, args);
        #[cfg(not(target_arch = "x86_64"))]
        let result = match self.vehicle {
            // SAFETY: the buffer holds `maxevents` entries.
            Vehicle::Libc => crate::vehicle::fold_errno(unsafe {
                libc::epoll_wait(epfd, events.as_mut_ptr(), maxevents, timeout_ms)
            } as i64),
            Vehicle::Syscall => self.call(Syscall::N_epoll_pwait, args),
        };
        let builder = self
            .fd_arg(self.rec.event("epoll_wait", result), "epfd", epfd)
            .arg("maxevents", maxevents)
            .arg("timeout_ms", timeout_ms);
        let (builder, delivered) = self.record_epoll(builder, result, &events);
        builder.emit();
        (result, delivered)
    }

    pub fn eventfd2(&self, initval: u32, flags: i32) -> i32 {
        let result = self.call(
            Syscall::N_eventfd2,
            [initval as i64, flags as i64, 0, 0, 0, 0],
        );
        self.event(Syscall::N_eventfd2, result)
            .arg("initval", initval)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// `ppoll` over `(fd, events)` pairs with an optional relative timeout;
    /// revents recorded per slot.
    pub fn ppoll(&self, fds: &[(i32, i16)], timeout_ns: Option<i64>) -> (i64, Vec<i16>) {
        let mut pollfds = net::pollfd_array(fds);
        let timeout = timeout_ns.map(|ns| libc::timespec {
            tv_sec: ns / 1_000_000_000,
            tv_nsec: ns % 1_000_000_000,
        });
        let timeout_ptr = timeout
            .as_ref()
            .map_or(0, |ts| ts as *const libc::timespec as i64);
        let result = self.call(
            Syscall::N_ppoll,
            [
                pollfds.as_mut_ptr() as i64,
                pollfds.len() as i64,
                timeout_ptr,
                0,
                std::mem::size_of::<libc::sigset_t>() as i64,
                0,
            ],
        );
        let builder = self
            .event(Syscall::N_ppoll, result)
            .arg("timeout_ns", timeout_ns.map_or(Value::Null, Value::from));
        self.record_pollfds(builder, fds, &pollfds, result, !0)
    }

    // ---- threads ------------------------------------------------------------

    pub fn futex(
        &self,
        word: &std::sync::atomic::AtomicU32,
        op: i32,
        value: u32,
        timeout_ns: Option<i64>,
    ) -> i64 {
        let timeout = timeout_ns.map(|ns| libc::timespec {
            tv_sec: ns / 1_000_000_000,
            tv_nsec: ns % 1_000_000_000,
        });
        let timeout_ptr = timeout
            .as_ref()
            .map_or(0, |ts| ts as *const libc::timespec as i64);
        let result = self.call(
            Syscall::N_futex,
            [
                word.as_ptr() as i64,
                op as i64,
                value as i64,
                timeout_ptr,
                0,
                0,
            ],
        );
        let builder = self
            .event(Syscall::N_futex, result)
            .arg("op", op)
            .arg("value", value);
        match timeout_ns {
            Some(ns) => builder.arg("timeout_ns", ns).emit(),
            None => builder.arg("timeout_ns", Value::Null).emit(),
        }
        result
    }
}
