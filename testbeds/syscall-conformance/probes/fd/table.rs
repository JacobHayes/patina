//! fd/table — the descriptor table: lowest-free allocation with holes, dup /
//! dup2 / dup3 / F_DUPFD binding numbers to one open file description, the
//! per-number FD_CLOEXEC bit versus per-description status flags, close_range,
//! EMFILE at RLIMIT_NOFILE (pinned to 1024 by run.sh), redirecting a standard
//! stream with dup2 and reopening a closed standard number, standard input at
//! EOF (run.sh feeds /dev/null), and the non-file kinds' answers to lseek.
//!
//! Standard ERROR is the redirected stream, never stdout: the event stream is
//! written to fd 1 as each call returns, so redirecting fd 1 would divert the
//! events themselves into the file under test.

#[cfg(target_os = "linux")]
mod scenario {
    use libc::*;
    use syscall_conformance::calls::{neg, Probe, AT_FDCWD};

    pub fn run(p: &Probe) {
        let root = p.scratch();
        let open = |name: &str| {
            p.openat(
                AT_FDCWD,
                &format!("{root}/{name}"),
                O_RDWR | O_CREAT | O_CLOEXEC,
                0o640,
            )
        };

        // ---- allocation: lowest free, holes reused ----
        let a = open("a");
        let b = open("b");
        let c = open("c");
        p.require("three opens", a >= 0 && b >= 0 && c >= 0);
        p.check(
            "numbers are allocated lowest-free, consecutively",
            b == a + 1 && c == b + 1,
        );
        p.check("close the middle one", p.close(b) == 0);
        let d = open("d");
        p.check("the closed number is reused (lowest free)", d == b);
        p.check("standard input is at EOF", p.read(0, 8).0 == 0);

        // ---- dup: one description, two numbers ----
        let e = p.dup(a) as i32;
        p.check("dup takes the lowest free number", e == c + 1);
        p.check("write through the original", p.write(a, b"hello") == 5);
        p.check(
            "a dup shares the file offset (one open file description)",
            p.lseek(e, 0, SEEK_CUR) == 5,
        );
        p.check(
            "O_CLOEXEC shows on the original's number only",
            p.fcntl(a, F_GETFD, 0) == i64::from(FD_CLOEXEC) && p.fcntl(e, F_GETFD, 0) == 0,
        );
        let getfl = p.fcntl(a, F_GETFL, 0);
        p.check(
            "F_GETFL on a file reports its access mode",
            getfl >= 0 && getfl as i32 & O_ACCMODE == O_RDWR,
        );
        p.check(
            "F_SETFL O_APPEND is shared through the dup (description flag)",
            p.fcntl(e, F_SETFL, i64::from(O_APPEND)) == 0
                && p.fcntl(a, F_GETFL, 0) as i32 & O_APPEND == O_APPEND,
        );
        p.check(
            "F_SETFL cannot change the access mode",
            p.fcntl(a, F_SETFL, 0) == 0 && p.fcntl(a, F_GETFL, 0) as i32 & O_ACCMODE == O_RDWR,
        );

        // ---- dup2 / dup3: a chosen number ----
        p.check(
            "dup2 onto an open number closes it and binds the description",
            p.dup2(a, c) == i64::from(c) && p.lseek(c, 0, SEEK_CUR) == 5,
        );
        p.check(
            "dup2 of equal numbers validates and returns it",
            p.dup2(a, a) == i64::from(a),
        );
        p.check(
            "dup2 from a closed number is EBADF",
            p.dup2(4000, c) == neg(EBADF),
        );
        p.check("dup3 of equal numbers is EINVAL", p.dup3(a, a, 0) == neg(EINVAL));
        p.check(
            "dup3 with a flag other than O_CLOEXEC is EINVAL",
            p.dup3(a, 50, 0x1) == neg(EINVAL),
        );
        p.check(
            "dup3 O_CLOEXEC lands on the new number only",
            p.dup3(a, 50, O_CLOEXEC) == 50
                && p.fcntl(50, F_GETFD, 0) == i64::from(FD_CLOEXEC)
                && p.fcntl(e, F_GETFD, 0) == 0,
        );
        p.check(
            "dup2 to a number past RLIMIT_NOFILE is EBADF",
            p.dup2(a, 1024) == neg(EBADF),
        );
        p.check(
            "a closed number gets a fresh description, not the old one",
            p.close(50) == 0 && p.fcntl(50, F_GETFD, 0) == neg(EBADF),
        );

        // ---- F_DUPFD at the limit ----
        p.check(
            "F_DUPFD with a minimum at RLIMIT_NOFILE is EINVAL",
            p.fcntl(a, F_DUPFD, 1024) == neg(EINVAL),
        );
        let top = p.fcntl(a, F_DUPFD, 1023);
        p.check("F_DUPFD binds the last number of the table", top == 1023);
        p.check(
            "with the last number taken, F_DUPFD above it is EMFILE",
            p.fcntl(a, F_DUPFD, 1023) == neg(EMFILE),
        );
        p.close(1023);

        // ---- close_range ----
        let x = open("x");
        let y = open("y");
        let z = open("z");
        p.require("three more opens", x >= 0 && y >= 0 && z >= 0);
        p.check(
            "close_range with first > last is EINVAL",
            p.close_range(z as u32, x as u32, 0) == neg(EINVAL),
        );
        p.check(
            "close_range with an unknown flag is EINVAL",
            p.close_range(x as u32, z as u32, 0x8) == neg(EINVAL),
        );
        p.check(
            "close_range closes every number in the range",
            p.close_range(x as u32, z as u32, 0) == 0
                && p.fcntl(x, F_GETFD, 0) == neg(EBADF)
                && p.fcntl(y, F_GETFD, 0) == neg(EBADF)
                && p.fcntl(z, F_GETFD, 0) == neg(EBADF),
        );
        p.check(
            "close_range over an empty range succeeds",
            p.close_range(x as u32, z as u32, 0) == 0,
        );
        let x2 = open("x2");
        let y2 = open("y2");
        p.check("the range's numbers are free again", x2 == x && y2 == y);
        p.check("clear FD_CLOEXEC first", p.fcntl(x2, F_SETFD, 0) == 0);
        p.check(
            "CLOSE_RANGE_CLOEXEC marks the range close-on-exec instead of closing it",
            p.close_range(x2 as u32, y2 as u32, CLOSE_RANGE_CLOEXEC) == 0
                && p.fcntl(x2, F_GETFD, 0) == i64::from(FD_CLOEXEC)
                && p.fcntl(y2, F_GETFD, 0) == i64::from(FD_CLOEXEC),
        );
        p.check("close x2", p.close(x2) == 0);
        p.check("close y2", p.close(y2) == 0);

        // ---- non-file kinds ----
        let (r, fds) = p.pipe2(O_CLOEXEC);
        p.require("pipe2", r == 0);
        let [rd, wr] = fds;
        p.check(
            "lseek on a pipe is ESPIPE",
            p.lseek(rd, 0, SEEK_CUR) == neg(ESPIPE),
        );
        let wr2 = p.dup2(wr, 60);
        p.check("dup2 of a pipe end to a chosen number", wr2 == 60);
        p.check("write through the chosen number", p.write(60, b"ab") == 2);
        p.check("close the original write end", p.close(wr) == 0);
        p.check(
            "the dup keeps the write side open: the reader sees the bytes, not EOF",
            p.read(rd, 8).0 == 2,
        );
        p.check("close the dup", p.close(60) == 0);
        p.check(
            "with the last write end closed, the reader sees EOF",
            p.read(rd, 8).0 == 0,
        );
        p.close(rd);
        let ef = p.eventfd2(1, EFD_CLOEXEC);
        p.require("eventfd2", ef >= 0);
        let ef2 = p.dup(ef) as i32;
        let (n, data) = p.read(ef2, 8);
        p.check(
            "a dup of an eventfd reads the same counter",
            ef2 >= 0 && n == 8 && data == 1u64.to_ne_bytes(),
        );
        p.close(ef2);
        p.close(ef);

        // ---- redirecting a standard stream ----
        let saved = p.dup(2) as i32;
        p.check("dup of standard error", saved >= 0);
        let out = open("stderr");
        p.check("dup2 a file over standard error", p.dup2(out, 2) == 2);
        p.check("a write to number 2 lands in the file", p.write(2, b"redirected") == 10);
        p.check("restore standard error", p.dup2(saved, 2) == 2);
        p.check("rewind the file", p.lseek(out, 0, SEEK_SET) == 0);
        let (n, data) = p.read(out, 16);
        p.check("the file holds the redirected bytes", n == 10 && data == b"redirected");
        p.check("close the file", p.close(out) == 0);
        p.check("close standard error", p.close(2) == 0);
        let two = open("two");
        p.check("the next open takes number 2", two == 2);
        p.check("number 2 is now an ordinary file", p.write(2, b"x") == 1);
        p.check("close it", p.close(2) == 0);
        p.check("put standard error back", p.dup2(saved, 2) == 2);
        p.check("close the saved copy", p.close(saved) == 0);

        // ---- EBADF ----
        p.check("close of a closed number is EBADF", p.close(4000) == neg(EBADF));
        p.check("close of a negative number is EBADF", p.close(-1) == neg(EBADF));
        p.check(
            "F_GETFL on a closed number is EBADF",
            p.fcntl(4000, F_GETFL, 0) == neg(EBADF),
        );
        for f in [a, c, d, e] {
            p.close(f);
        }
    }
}

syscall_conformance::probe_main!("fd/table", scenario::run);
