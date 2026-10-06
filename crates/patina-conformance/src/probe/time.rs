//! Basic clock, sleep, and entropy rows.

use super::*;

impl Probe {
    // ---- time ---------------------------------------------------------------

    pub fn clock_gettime(&self, clock: i32) -> (i64, i128) {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let result = self.call(
            Syscall::N_clock_gettime,
            [
                clock as i64,
                &mut ts as *mut libc::timespec as i64,
                0,
                0,
                0,
                0,
            ],
        );
        let ns = ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128;
        let builder = self
            .event(Syscall::N_clock_gettime, result)
            .arg("clock", clock);
        let builder = if result >= 0 {
            builder
                .field("ns", ns as i64)
                .norm("fields.ns", Norm::Monotonic)
        } else {
            builder
        };
        builder.emit();
        (result, ns)
    }

    pub fn gettimeofday(&self) -> (i64, i128) {
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let result = self.call(
            Syscall::N_gettimeofday,
            [&mut tv as *mut libc::timeval as i64, 0, 0, 0, 0, 0],
        );
        let us = tv.tv_sec as i128 * 1_000_000 + tv.tv_usec as i128;
        let builder = self.event(Syscall::N_gettimeofday, result);
        let builder = if result >= 0 {
            builder
                .field("us", us as i64)
                .norm("fields.us", Norm::Monotonic)
                .field("usec_in_range", (0..1_000_000).contains(&tv.tv_usec))
        } else {
            builder
        };
        builder.emit();
        (result, us)
    }

    pub fn nanosleep(&self, sec: i64, nsec: i64) -> i64 {
        self.nanosleep_rem(sec, nsec).0
    }

    /// `clock_nanosleep` with a NULL `rem` (relative unless `TIMER_ABSTIME`).
    pub fn clock_nanosleep(&self, clock: i32, flags: i32, sec: i64, nsec: i64) -> i64 {
        self.clock_sleep(clock, flags, (sec, nsec), false).0
    }

    // ---- entropy ------------------------------------------------------------

    pub fn getrandom(&self, len: usize, flags: u32) -> (i64, Vec<u8>) {
        let mut buf = vec![0u8; len];
        let result = self.call(
            Syscall::N_getrandom,
            [buf.as_mut_ptr() as i64, len as i64, flags as i64, 0, 0, 0],
        );
        if result >= 0 {
            buf.truncate(result as usize);
        } else {
            buf.clear();
        }
        let builder = self
            .event(Syscall::N_getrandom, result)
            .arg("len", len)
            .arg("flags", flags);
        let builder = if result >= 0 {
            builder.field("nonzero", buf.iter().any(|&b| b != 0))
        } else {
            builder
        };
        builder.emit();
        (result, buf)
    }

    // ---- entropy edge ----------------------------------------------------------

    /// `getrandom(NULL, len, flags)`.
    pub fn getrandom_null(&self, len: usize, flags: u32) -> i64 {
        let result = self.call(Syscall::N_getrandom, [0, len as i64, flags as i64, 0, 0, 0]);
        self.event(Syscall::N_getrandom, result)
            .arg("buf", "NULL")
            .arg("len", len)
            .arg("flags", flags)
            .emit();
        result
    }
}
