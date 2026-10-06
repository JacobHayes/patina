//! Socket poll, select, and epoll readiness rows.

use super::*;

impl Probe {
    // ---- readiness ---------------------------------------------------------

    /// `poll(2)` over `(fd, events)` with a millisecond timeout; revents per
    /// slot, kept to `mask`'s bits when recorded. The generic (arm64) table
    /// has no `poll` row: there the syscall vehicle issues `ppoll` with the
    /// timeout as a timespec (glibc's own spelling).
    pub fn poll(&self, fds: &[(i32, i16)], timeout_ms: i32, mask: i16) -> (i64, Vec<i16>) {
        let mut pollfds = pollfd_array(fds);
        let pointer = if pollfds.is_empty() {
            0
        } else {
            pollfds.as_mut_ptr() as i64
        };
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_poll,
            [pointer, pollfds.len() as i64, timeout_ms as i64, 0, 0, 0],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = {
            let ts = libc::timespec {
                tv_sec: i64::from(timeout_ms / 1000),
                tv_nsec: i64::from(timeout_ms % 1000) * 1_000_000,
            };
            let ts_ptr = if timeout_ms < 0 {
                0
            } else {
                &ts as *const libc::timespec as i64
            };
            let count = pollfds.len();
            self.legacy(
                // SAFETY: the array holds `count` entries.
                || unsafe { libc::poll(pollfds.as_mut_ptr(), count as libc::nfds_t, timeout_ms) }
                    as i64,
                Syscall::N_ppoll,
                [pointer, count as i64, ts_ptr, 0, SIGSET_BYTES, 0],
            )
        };
        let builder = self.rec.event("poll", result).arg("timeout_ms", timeout_ms);
        self.record_pollfds(builder, fds, &pollfds, result, mask)
    }

    /// Record a poll-shaped call's slots — each descriptor and the events
    /// asked, and once it answered each slot's revents kept to `mask` — and
    /// answer the result and the revents.
    pub(in crate::probe) fn record_pollfds(
        &self,
        builder: EventBuilder<'_>,
        fds: &[(i32, i16)],
        pollfds: &[libc::pollfd],
        result: i64,
        mask: i16,
    ) -> (i64, Vec<i16>) {
        let revents: Vec<i16> = pollfds.iter().map(|p| p.revents).collect();
        let mut builder = builder.arg("nfds", fds.len());
        for (index, &(fd, events)) in fds.iter().enumerate() {
            builder = self
                .fd_arg(builder, &format!("fd{index}"), fd)
                .arg(&format!("events{index}"), events);
        }
        if result >= 0 {
            for (index, revent) in revents.iter().enumerate() {
                builder = builder.field(&format!("revents{index}"), *revent & mask);
            }
        }
        builder.emit();
        (result, revents)
    }

    /// `poll` with `nfds` entries at an address the kernel cannot read (1),
    /// through the row on every vehicle (a shape glibc's wrapper passes
    /// straight through). The generic (arm64) table has no `poll` row: there
    /// it is `ppoll` with a zero timeout.
    pub fn poll_fault(&self, nfds: usize) -> i64 {
        #[cfg(target_arch = "x86_64")]
        let result = self.call_unwrapped(Syscall::N_poll, [1, nfds as i64, 0, 0, 0, 0]);
        #[cfg(not(target_arch = "x86_64"))]
        let result = {
            let zero = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            self.call_unwrapped(
                Syscall::N_ppoll,
                [1, nfds as i64, &zero as *const _ as i64, 0, SIGSET_BYTES, 0],
            )
        };
        self.rec
            .event("poll", result)
            .arg("fds", "bad pointer")
            .arg("nfds", nfds)
            .emit();
        result
    }

    /// Record a `select`-shaped event (`op`) and answer which descriptors
    /// stayed set.
    #[allow(clippy::too_many_arguments)]
    fn record_select(
        &self,
        op: &str,
        result: i64,
        nfds: i32,
        sets: Sets<'_>,
        read: &libc::fd_set,
        write: &libc::fd_set,
        except: &libc::fd_set,
        timeout: Value,
    ) -> Ready {
        let ready = Ready {
            read: sets
                .read
                .iter()
                .map(|fd| result > 0 && is_set(read, *fd))
                .collect(),
            write: sets
                .write
                .iter()
                .map(|fd| result > 0 && is_set(write, *fd))
                .collect(),
            except: sets
                .except
                .iter()
                .map(|fd| result > 0 && is_set(except, *fd))
                .collect(),
        };
        let mut builder = self
            .rec
            .event(op, result)
            .arg("nfds", nfds)
            .arg("timeout", timeout);
        for (name, fds, flags) in [
            ("r", sets.read, &ready.read),
            ("w", sets.write, &ready.write),
            ("e", sets.except, &ready.except),
        ] {
            for (index, fd) in fds.iter().enumerate() {
                builder = self.fd_arg(builder, &format!("{name}{index}"), *fd);
                if result >= 0 {
                    builder = builder.field(&format!("{name}{index}_ready"), flags[index]);
                }
            }
        }
        builder.emit();
        ready
    }

    /// `select(2)` over `sets` with a `(sec, usec)` timeout (`None` passes
    /// NULL). Answers the ready descriptors and the timeout as the call left
    /// it (Linux writes the unslept time back). The generic (arm64) table
    /// has no `select` row: there the syscall vehicle issues `pselect6` with
    /// a timespec and converts the unslept time back (glibc's own spelling).
    pub fn select(
        &self,
        nfds: i32,
        sets: Sets<'_>,
        timeout: Option<(i64, i64)>,
    ) -> (i64, Ready, Option<(i64, i64)>) {
        let mut read = fd_set(sets.read);
        let mut write = fd_set(sets.write);
        let mut except = fd_set(sets.except);
        let mut tv = timeout.map(|(tv_sec, tv_usec)| libc::timeval { tv_sec, tv_usec });
        let tv_ptr = tv.as_mut().map_or(0, |tv| tv as *mut libc::timeval as i64);
        #[cfg(target_arch = "x86_64")]
        let result = self.call(
            Syscall::N_select,
            [
                nfds as i64,
                &mut read as *mut _ as i64,
                &mut write as *mut _ as i64,
                &mut except as *mut _ as i64,
                tv_ptr,
                0,
            ],
        );
        #[cfg(not(target_arch = "x86_64"))]
        let result = match self.vehicle {
            // SAFETY: local sets and timeval.
            Vehicle::Libc => fold_errno(unsafe {
                libc::select(
                    nfds,
                    &mut read,
                    &mut write,
                    &mut except,
                    tv_ptr as *mut libc::timeval,
                )
            } as i64),
            // glibc's select: a negative timeout is EINVAL without a call;
            // microseconds reaching a second are normalized into seconds.
            _ if tv.is_some_and(|tv| tv.tv_sec < 0 || tv.tv_usec < 0) => neg(libc::EINVAL),
            _ => {
                let mut ts = tv.map(|tv| libc::timespec {
                    tv_sec: tv.tv_sec + tv.tv_usec / 1_000_000,
                    tv_nsec: (tv.tv_usec % 1_000_000) * 1000,
                });
                let result = self.call(
                    Syscall::N_pselect6,
                    [
                        nfds as i64,
                        &mut read as *mut _ as i64,
                        &mut write as *mut _ as i64,
                        &mut except as *mut _ as i64,
                        ts.as_mut().map_or(0, |ts| ts as *mut libc::timespec as i64),
                        0,
                    ],
                );
                if let (Some(tv), Some(ts)) = (tv.as_mut(), ts) {
                    tv.tv_sec = ts.tv_sec;
                    tv.tv_usec = ts.tv_nsec / 1000;
                }
                result
            }
        };
        let left = tv.map(|tv| (tv.tv_sec, tv.tv_usec));
        let ready = self.record_select(
            "select",
            result,
            nfds,
            sets,
            &read,
            &write,
            &except,
            timeout.map_or(Value::Null, |(s, us)| Value::from(format!("{s}s{us}us"))),
        );
        (result, ready, left)
    }

    /// `pselect6` over `sets` with a `(sec, nsec)` timeout and an optional
    /// signal mask of `sigsetsize` bytes. glibc's `pselect` is the libc door
    /// (it copies the timeout, so what the kernel writes back is never
    /// recorded); a `sigsetsize` other than 8 is a shape glibc cannot
    /// express, issued through `syscall(2)` on every vehicle.
    pub fn pselect6(
        &self,
        nfds: i32,
        sets: Sets<'_>,
        timeout: Option<(i64, i64)>,
        mask: Option<&libc::sigset_t>,
        sigsetsize: usize,
    ) -> (i64, Ready) {
        let mut read = fd_set(sets.read);
        let mut write = fd_set(sets.write);
        let mut except = fd_set(sets.except);
        let mut ts = timeout.map(|(tv_sec, tv_nsec)| libc::timespec { tv_sec, tv_nsec });
        let pair: [usize; 2] = [
            mask.map_or(0, |m| m as *const libc::sigset_t as usize),
            sigsetsize,
        ];
        let args = [
            nfds as i64,
            &mut read as *mut _ as i64,
            &mut write as *mut _ as i64,
            &mut except as *mut _ as i64,
            ts.as_mut().map_or(0, |ts| ts as *mut libc::timespec as i64),
            &pair as *const [usize; 2] as i64,
        ];
        let result = if sigsetsize as i64 == SIGSET_BYTES {
            self.call(Syscall::N_pselect6, args)
        } else {
            self.call_unwrapped(Syscall::N_pselect6, args)
        };
        let ready = self.record_select(
            "pselect6",
            result,
            nfds,
            sets,
            &read,
            &write,
            &except,
            timeout.map_or(Value::Null, |(s, ns)| Value::from(format!("{s}s{ns}ns"))),
        );
        (result, ready)
    }

    /// The legacy `epoll_create(size)` row (x86_64 only; glibc's wrapper is
    /// not one the shim defines, so every vehicle issues the row).
    #[cfg(target_arch = "x86_64")]
    pub fn epoll_create(&self, size: i32) -> i32 {
        let result = self.call(Syscall::N_epoll_create, [size as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_epoll_create, result)
            .arg("size", size)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// The legacy `eventfd(initval)` row (x86_64 only: glibc's `eventfd`
    /// issues `eventfd2`, so every vehicle issues the row itself).
    #[cfg(target_arch = "x86_64")]
    pub fn eventfd(&self, initval: u32) -> i32 {
        let result = self.call(Syscall::N_eventfd, [initval as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_eventfd, result)
            .arg("initval", initval)
            .norm("ret", Norm::Relative("fd"))
            .emit();
        result as i32
    }

    /// Record an epoll wait's delivered events, sorted by data.
    pub(in crate::probe) fn record_epoll<'a>(
        &self,
        builder: EventBuilder<'a>,
        result: i64,
        events: &[libc::epoll_event],
    ) -> (EventBuilder<'a>, Vec<(u64, u32)>) {
        let mut delivered: Vec<(u64, u32)> = if result > 0 {
            events[..result as usize]
                .iter()
                .map(|event| (event.u64, event.events))
                .collect()
        } else {
            Vec::new()
        };
        delivered.sort();
        let rendered: Vec<Value> = delivered
            .iter()
            .map(|(data, mask)| Value::from(format!("{data}:{mask:#x}")))
            .collect();
        let builder = if result >= 0 {
            builder.field("events", Value::Array(rendered))
        } else {
            builder
        };
        (builder, delivered)
    }

    /// `epoll_pwait` with an optional mask of `sigsetsize` bytes. glibc's
    /// `epoll_pwait` is the libc door for the kernel's size (8); another size
    /// is issued through `syscall(2)` on every vehicle.
    pub fn epoll_pwait(
        &self,
        epfd: i32,
        maxevents: i32,
        timeout_ms: i32,
        mask: Option<&libc::sigset_t>,
        sigsetsize: usize,
    ) -> (i64, Vec<(u64, u32)>) {
        let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; maxevents.max(1) as usize];
        let args = [
            epfd as i64,
            events.as_mut_ptr() as i64,
            maxevents as i64,
            timeout_ms as i64,
            mask.map_or(0, |m| m as *const libc::sigset_t as i64),
            sigsetsize as i64,
        ];
        let result = if sigsetsize as i64 == SIGSET_BYTES {
            self.call(Syscall::N_epoll_pwait, args)
        } else {
            self.call_unwrapped(Syscall::N_epoll_pwait, args)
        };
        let builder = self
            .fd_arg(self.event(Syscall::N_epoll_pwait, result), "epfd", epfd)
            .arg("maxevents", maxevents)
            .arg("timeout_ms", timeout_ms)
            .arg("mask", mask.is_some())
            .arg("sigsetsize", sigsetsize);
        let (builder, delivered) = self.record_epoll(builder, result, &events);
        builder.emit();
        (result, delivered)
    }

    /// `epoll_pwait2` with a `(sec, nsec)` timeout (`None` passes NULL: wait
    /// without bound) and no mask.
    pub fn epoll_pwait2(
        &self,
        epfd: i32,
        maxevents: i32,
        timeout: Option<(i64, i64)>,
    ) -> (i64, Vec<(u64, u32)>) {
        let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; maxevents.max(1) as usize];
        let ts = timeout.map(|(tv_sec, tv_nsec)| libc::timespec { tv_sec, tv_nsec });
        let result = self.call(
            Syscall::N_epoll_pwait2,
            [
                epfd as i64,
                events.as_mut_ptr() as i64,
                maxevents as i64,
                ts.as_ref()
                    .map_or(0, |ts| ts as *const libc::timespec as i64),
                0,
                SIGSET_BYTES,
            ],
        );
        let builder = self
            .fd_arg(self.event(Syscall::N_epoll_pwait2, result), "epfd", epfd)
            .arg("maxevents", maxevents)
            .arg(
                "timeout",
                timeout.map_or(Value::Null, |(s, ns)| Value::from(format!("{s}s{ns}ns"))),
            );
        let (builder, delivered) = self.record_epoll(builder, result, &events);
        builder.emit();
        (result, delivered)
    }
}
