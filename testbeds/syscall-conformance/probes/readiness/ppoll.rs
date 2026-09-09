//! readiness/ppoll — ppoll over pipes and an eventfd: readiness bits, POLLHUP,
//! POLLNVAL, ignored negative descriptors, and a timed wait on the clock. Its
//! own probe because the libc symbol `ppoll` is not interposed today, which
//! makes the whole binary an audit refusal under patina; keeping it apart
//! leaves readiness/epoll runnable.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use syscall_conformance::calls::Probe;
    use syscall_conformance::vehicle::{fold_errno, Args, Sys};

    // `ppoll` is linked only from this probe binary (the symbol is not
    // interposed today, so naming it in the shared table would make every probe
    // an audit refusal).
    fn libc_ppoll(a: Args) -> i64 {
        fold_errno(unsafe {
            ppoll(
                a[0] as *mut pollfd,
                a[1] as nfds_t,
                a[2] as *const timespec,
                a[3] as *const sigset_t,
            )
        } as i64)
    }

    pub fn run(p: &Probe) {
        p.register_libc(Sys::Ppoll, libc_ppoll);
        let (r, fds) = p.pipe2(O_CLOEXEC);
        p.require("pipe2", r == 0);
        let [rd, wr] = fds;
        let (n, revents) = p.ppoll(&[(rd, POLLIN)], Some(0));
        p.check(
            "an empty pipe is not readable",
            n == 0 && revents == vec![0],
        );
        p.write(wr, b"x");
        let (n, revents) = p.ppoll(&[(rd, POLLIN)], Some(0));
        p.check(
            "after a write it is readable",
            n == 1 && revents == vec![POLLIN],
        );
        let (n, revents) = p.ppoll(&[(rd, POLLIN), (wr, POLLOUT)], Some(0));
        p.check(
            "both ends report",
            n == 2 && revents == vec![POLLIN, POLLOUT],
        );
        p.read(rd, 8);
        let (_, before) = p.clock_gettime(CLOCK_MONOTONIC);
        let (n, _) = p.ppoll(&[(rd, POLLIN)], Some(2_000_000));
        p.check("a timed wait with nothing ready returns 0", n == 0);
        let (_, after) = p.clock_gettime(CLOCK_MONOTONIC);
        p.check(
            "the timed wait advanced the clock by at least the timeout",
            after - before >= 2_000_000,
        );
        let (n, revents) = p.ppoll(&[(4000, POLLIN)], Some(0));
        p.check(
            "a closed descriptor reports POLLNVAL",
            n == 1 && revents == vec![POLLNVAL],
        );
        let (n, revents) = p.ppoll(&[(-1, POLLIN)], Some(0));
        p.check(
            "a negative descriptor is ignored",
            n == 0 && revents == vec![0],
        );
        let (n, _) = p.ppoll(&[], Some(1_000_000));
        p.check("ppoll with no descriptors is a sleep", n == 0);
        p.check("close the writer", p.close(wr) == 0);
        let (n, revents) = p.ppoll(&[(rd, POLLIN)], Some(0));
        p.check(
            "a pipe with no writer reports POLLHUP",
            n == 1 && revents == vec![POLLHUP],
        );

        let ef = p.eventfd2(0, EFD_NONBLOCK);
        p.require("eventfd2", ef >= 0);
        let (n, revents) = p.ppoll(&[(ef, POLLIN | POLLOUT)], Some(0));
        p.check(
            "a fresh eventfd is writable only",
            n == 1 && revents == vec![POLLOUT],
        );
        p.write(ef, &1u64.to_ne_bytes());
        let (n, revents) = p.ppoll(&[(ef, POLLIN | POLLOUT)], Some(0));
        p.check(
            "a written eventfd is readable and writable",
            n == 1 && revents == vec![POLLIN | POLLOUT],
        );
        p.close(ef);
        p.close(rd);
    }
}

syscall_conformance::probe_main!("readiness/ppoll", scenario::run);
