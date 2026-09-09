//! fd/pipes — pipe2 / dup / fcntl / flock: descriptor flags versus description
//! flags, sharing through dup, EOF/EPIPE/EAGAIN on pipes, and advisory locks.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use syscall_conformance::calls::{neg, Probe, AT_FDCWD};

    pub fn run(p: &Probe) {
        let root = p.scratch();

        let (r, fds) = p.pipe2(O_CLOEXEC);
        p.require("pipe2", r == 0);
        let [rd, wr] = fds;
        p.check("write into the pipe", p.write(wr, b"hello") == 5);
        let (n, data) = p.read(rd, 16);
        p.check("read what was written", n == 5 && data == b"hello");
        let getfl = p.fcntl(rd, F_GETFL, 0);
        p.check(
            "the read end is O_RDONLY",
            getfl >= 0 && getfl as i32 & O_ACCMODE == O_RDONLY,
        );
        let getfl = p.fcntl(wr, F_GETFL, 0);
        p.check(
            "the write end is O_WRONLY",
            getfl >= 0 && getfl as i32 & O_ACCMODE == O_WRONLY,
        );
        p.check(
            "O_CLOEXEC shows as FD_CLOEXEC",
            p.fcntl(rd, F_GETFD, 0) == i64::from(FD_CLOEXEC),
        );
        p.check(
            "F_SETFD clears it",
            p.fcntl(rd, F_SETFD, 0) == 0 && p.fcntl(rd, F_GETFD, 0) == 0,
        );
        p.check(
            "F_SETFL O_NONBLOCK",
            p.fcntl(rd, F_SETFL, i64::from(O_NONBLOCK)) == 0,
        );
        p.check(
            "an empty non-blocking read is EAGAIN",
            p.read(rd, 4).0 == neg(EAGAIN),
        );
        let getfl = p.fcntl(rd, F_GETFL, 0);
        p.check(
            "F_GETFL reports O_NONBLOCK",
            getfl >= 0 && getfl as i32 & O_NONBLOCK != 0,
        );

        let d = p.dup(rd) as i32;
        p.check("dup returns a new descriptor", d >= 0 && d != rd);
        p.write(wr, b"ab");
        let (n, data) = p.read(d, 8);
        p.check("the dup reads the same pipe", n == 2 && data == b"ab");
        let getfl = p.fcntl(d, F_GETFL, 0);
        p.check(
            "O_NONBLOCK is shared through the dup (description flag)",
            getfl >= 0 && getfl as i32 & O_NONBLOCK != 0,
        );
        p.check(
            "F_SETFD FD_CLOEXEC on the original",
            p.fcntl(rd, F_SETFD, i64::from(FD_CLOEXEC)) == 0,
        );
        let d2 = p.dup(rd) as i32;
        p.check(
            "dup does not copy FD_CLOEXEC (descriptor flag)",
            d2 >= 0 && p.fcntl(d2, F_GETFD, 0) == 0,
        );
        let high = p.fcntl(rd, F_DUPFD, 20);
        p.check("F_DUPFD honors the minimum", high >= 20);
        let high_cloexec = p.fcntl(rd, F_DUPFD_CLOEXEC, 30);
        p.check(
            "F_DUPFD_CLOEXEC sets FD_CLOEXEC on the new descriptor only",
            high_cloexec >= 30
                && p.fcntl(high_cloexec as i32, F_GETFD, 0) == i64::from(FD_CLOEXEC)
                && p.fcntl(high as i32, F_GETFD, 0) == 0,
        );
        let size = p.fcntl(rd, F_GETPIPE_SZ, 0);
        p.check(
            "F_GETPIPE_SZ is a page multiple",
            size > 0 && size % 4096 == 0,
        );
        p.check(
            "F_SETPIPE_SZ to one page",
            p.fcntl(rd, F_SETPIPE_SZ, 4096) >= 4096,
        );
        p.check(
            "dup of a closed descriptor is EBADF",
            p.dup(4000) == neg(EBADF),
        );
        p.check(
            "fcntl on a closed descriptor is EBADF",
            p.fcntl(4000, F_GETFL, 0) == neg(EBADF),
        );
        p.check(
            "an unknown fcntl command is EINVAL",
            p.fcntl(rd, 9999, 0) == neg(EINVAL),
        );

        p.check("close the write end", p.close(wr) == 0);
        p.check(
            "read after the last writer closed is EOF",
            p.read(rd, 8).0 == 0,
        );
        for f in [rd, d, d2, high as i32, high_cloexec as i32] {
            p.close(f);
        }

        let (r, fds) = p.pipe2(O_NONBLOCK);
        p.require("pipe2 O_NONBLOCK", r == 0);
        let [rd, wr] = fds;
        let big = vec![b'x'; 70_000];
        let partial = p.write(wr, &big);
        p.check(
            "a non-blocking write into a full pipe is partial",
            partial > 0 && partial < 70_000,
        );
        p.check(
            "the next non-blocking write is EAGAIN",
            p.write(wr, b"y") == neg(EAGAIN),
        );
        p.check("close the read end", p.close(rd) == 0);
        p.check(
            "write with no reader is EPIPE",
            p.write(wr, b"z") == neg(EPIPE),
        );
        p.close(wr);
        let (r, unexpected) = p.pipe2(0x1);
        p.check("pipe2 with an unknown flag is EINVAL", r == neg(EINVAL));
        if r == 0 {
            // An unexpected success is closed unobserved (see fs/open_rw).
            p.rec.quiet(|| {
                p.close(unexpected[0]);
                p.close(unexpected[1]);
            });
        }

        let file = format!("{root}/lock");
        let fa = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o640);
        let fb = p.openat(AT_FDCWD, &file, O_RDWR, 0);
        p.require("two opens of the lock file", fa >= 0 && fb >= 0);
        p.check("flock LOCK_SH", p.flock(fa, LOCK_SH) == 0);
        p.check("a second shared lock", p.flock(fb, LOCK_SH | LOCK_NB) == 0);
        p.check(
            "an exclusive lock over a shared one is EWOULDBLOCK",
            p.flock(fb, LOCK_EX | LOCK_NB) == neg(EWOULDBLOCK),
        );
        p.check("LOCK_UN", p.flock(fa, LOCK_UN) == 0);
        p.check(
            "upgrade to exclusive once alone",
            p.flock(fb, LOCK_EX | LOCK_NB) == 0,
        );
        p.check(
            "a shared lock against an exclusive one is EWOULDBLOCK",
            p.flock(fa, LOCK_SH | LOCK_NB) == neg(EWOULDBLOCK),
        );
        let fc = p.dup(fb) as i32;
        p.check(
            "unlock through a dup of the holder",
            fc >= 0 && p.flock(fc, LOCK_UN) == 0,
        );
        p.check("the lock is released", p.flock(fa, LOCK_SH | LOCK_NB) == 0);
        // Linux 6.8 answers 0 to an operation outside LOCK_SH|LOCK_EX|LOCK_UN:
        // observed, not asserted (the blessing pins the host answer).
        p.flock(fa, 99);
        p.check(
            "flock on a closed descriptor is EBADF",
            p.flock(4000, LOCK_SH) == neg(EBADF),
        );
        for f in [fa, fb, fc] {
            p.close(f);
        }
    }
}

syscall_conformance::probe_main!("fd/pipes", scenario::run);
