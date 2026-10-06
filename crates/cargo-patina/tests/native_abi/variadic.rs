//! Real libc-door coverage for Rust variadic boundary ownership.
use crate::common;

use common::native::assert_success;

#[path = "variadic/matrix.rs"]
mod matrix;

#[test]
fn fcntl_promoted_int_pointer_and_absent_arguments_reach_the_model() {
    // Class pairing: compiled C calls exercise the platform variadic ABI;
    // registry uniqueness prevents this from silently binding a second wrapper.
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("variadic.c");
    std::fs::write(&source, r#"
#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#ifdef __linux__
extern void *patina_dlsym_route(const char *);
#endif
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    int fd = open("/variadic", O_CREAT | O_RDWR, 0600);
    if (fd < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) || fcntl(fd, F_GETFD) != FD_CLOEXEC) return 1;
    if ((fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDWR) return 2;
    int copy = fcntl(fd, F_DUPFD, 64);
    if (copy < 64 || fcntl(copy, F_GETFD) != 0) return 3;
    struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
    if (fcntl(fd, F_SETLK, &lock)) return 4;
#ifdef __linux__
    if (fcntl64(fd, F_GETFD) != FD_CLOEXEC || fcntl64(fd, F_SETFD, 0) || fcntl(fd, F_GETFD)) return 5;
    if (patina_dlsym_route("fcntl") != (void *)fcntl || patina_dlsym_route("fcntl64") != (void *)fcntl64) return 6;
#endif
    errno = 0;
    if (fcntl(-1, F_GETFD) != -1 || errno != EBADF) return 7;
#ifdef __linux__
    if (argc > 1) {
        if (pthread_cancel(pthread_self())) return 8;
        if (argv[1][0] == '6') fcntl64(fd, F_SETLKW, &lock);
        else fcntl(fd, F_SETLKW, &lock);
        return 9; /* must be a named refusal, never a forced unwind or success */
    }
#endif
    return 0;
}
"#).unwrap();
    let guest = common::native::assert_build_c_guest(
        source.to_str().unwrap(),
        common::native::CLink::PosixShim,
    );
    let (output, trace) = guest.record_standalone(&[]);
    assert_success(output);
    patina_dst_trace::TraceBundle::load(&trace)
        .unwrap()
        .validate()
        .unwrap();
    #[cfg(target_os = "linux")]
    for (mode, name) in [("cancel", "fcntl"), ("64", "fcntl64")] {
        guest.assert_internal_fatal(&[mode], &[&format!("pending cancellation reaches {name},")]);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn mremap_optional_address_is_read_only_for_fixed_placement() {
    // Class pairing: the variadic export inventory and PanicScope boundary lint;
    // these real C calls also cover the absent optional operand on each ABI.
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("mremap.c");
    std::fs::write(
        &source,
        r#"
#define _GNU_SOURCE
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif
int main(void) {
    const size_t page = 4096;
    unsigned char *source = mmap(0, page, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (source == MAP_FAILED) return 1;
    source[0] = 0x59;
    /* No optional argument, including DONTUNMAP without FIXED. */
    unsigned char *same = mremap(source, page, page, 0);
    if (same != source || same[0] != 0x59) return 2;
    unsigned char *moved = mremap(same, page, page,
                                 MREMAP_MAYMOVE | MREMAP_DONTUNMAP);
    if (moved == MAP_FAILED || moved == same || moved[0] != 0x59) return 3;
    if (munmap(same, page)) return 4;
    unsigned char *target = mmap(0, page, PROT_NONE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (target == MAP_FAILED) return 5;
    unsigned char *fixed = mremap(moved, page, page,
                                 MREMAP_MAYMOVE | MREMAP_FIXED, target);
    if (fixed != target || fixed[0] != 0x59) return 6;
    return munmap(fixed, page) ? 7 : 0;
}
"#,
    )
    .unwrap();
    let guest = common::native::assert_build_c_guest(
        source.to_str().unwrap(),
        common::native::CLink::PosixShim,
    );
    let (output, trace) = guest.record_standalone(&[]);
    assert_success(output);
    patina_dst_trace::TraceBundle::load(&trace)
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn open_family_promoted_mode_and_absent_mode_reach_the_model() {
    // Class pairing: the guarded variadic inventory and the shared wrong-slot matrix.
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("open.c");
    std::fs::write(
        &source,
        r#"
#define _GNU_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#ifdef __linux__
extern int __open(const char *, int, ...);
extern int __open64(const char *, int, ...);
#endif
static int check(int fd, unsigned mode) {
    struct stat value;
    if (fd < 0 || fstat(fd, &value) || (value.st_mode & 0777) != mode) return 1;
    return close(fd);
}
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    umask(0);
    if (check(open("/mode-open", O_CREAT | O_RDWR, 0641), 0641)) return 1;
    if (check(open("/mode-open", O_RDONLY), 0641)) return 2;
    if (check(openat(AT_FDCWD, "/mode-openat", O_CREAT | O_RDWR, 0623), 0623)) return 3;
    if (check(openat(AT_FDCWD, "/mode-openat", O_RDONLY), 0623)) return 4;
#ifdef __linux__
    if (check(open64("/mode-open64", O_CREAT | O_RDWR, 0642), 0642)) return 5;
    if (check(open64("/mode-open64", O_RDONLY), 0642)) return 6;
    if (check(openat64(AT_FDCWD, "/mode-openat64", O_CREAT | O_RDWR, 0624), 0624)) return 7;
    if (check(openat64(AT_FDCWD, "/mode-openat64", O_RDONLY), 0624)) return 8;
    if (check(__open("/mode-__open", O_CREAT | O_RDWR, 0643), 0643)) return 9;
    if (check(__open("/mode-__open", O_RDONLY), 0643)) return 10;
    if (check(__open64("/mode-__open64", O_CREAT | O_RDWR, 0644), 0644)) return 11;
    if (check(__open64("/mode-__open64", O_RDONLY), 0644)) return 12;
#endif
    errno = 0;
    if (open("/missing", O_RDONLY) != -1 || errno != ENOENT) return 13;
#ifdef __linux__
    if (argc > 1) {
        if (pthread_cancel(pthread_self())) return 14;
        if (argv[1][0] == '6') __open64("/mode-open", O_RDONLY);
        else __open("/mode-open", O_RDONLY);
        return 15;
    }
#endif
    return 0;
}
"#,
    )
    .unwrap();
    let guest = common::native::assert_build_c_guest(
        source.to_str().unwrap(),
        common::native::CLink::PosixShim,
    );
    let (output, trace) = guest.record_standalone(&[]);
    assert_success(output);
    patina_dst_trace::TraceBundle::load(&trace)
        .unwrap()
        .validate()
        .unwrap();
    #[cfg(target_os = "linux")]
    for (mode, symbol) in [("cancel", "__open"), ("64", "__open64")] {
        guest.assert_internal_fatal(
            &[mode],
            &[&format!("pending cancellation reaches {symbol},")],
        );
    }
}
#[test]
fn ioctl_absent_pointer_and_scalar_arguments_reach_the_model() {
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("ioctl.c");
    std::fs::write(
        &source,
        r#"
#define _GNU_SOURCE
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <termios.h>
int main(void) {
    int fd = open("/ioctl", O_CREAT | O_RDWR, 0600);
    if (fd < 0 || write(fd, "abcd", 4) != 4 || lseek(fd, 0, SEEK_SET)) return 1;
    if (ioctl(fd, FIOCLEX) || fcntl(fd, F_GETFD) != FD_CLOEXEC) return 2;
    if (ioctl(fd, FIONCLEX) || fcntl(fd, F_GETFD)) return 3;
    int on = 1, available = -1;
    if (ioctl(fd, FIONBIO, &on) || !(fcntl(fd, F_GETFL) & O_NONBLOCK)) return 4;
    if (ioctl(fd, FIONREAD, &available) || available != 4) return 5;
    errno = 0;
    if (ioctl(fd, FIONBIO, (int *)0) != -1 || errno != EFAULT) return 6;
#ifdef __linux__
    /* The kernel truncates request to unsigned int before decoding its operand. */
    available = -1;
    if (ioctl(fd, 0x100000000UL | FIONREAD, &available) || available != 4) return 7;
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) || unlockpt(master)) return 8;
    int slave = ioctl(master, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0 || fcntl(slave, F_GETFD) != FD_CLOEXEC ||
        (fcntl(slave, F_GETFL) & O_ACCMODE) != O_RDWR) return 9;
    if (ioctl(slave, TCFLSH, TCIOFLUSH) || ioctl(slave, TCSBRK, 1)) return 10;
    if (close(slave) || close(master)) return 11;
#endif
    return close(fd) ? 12 : 0;
}
"#,
    )
    .unwrap();
    let guest = common::native::assert_build_c_guest(
        source.to_str().unwrap(),
        common::native::CLink::PosixShim,
    );
    let (output, trace) = guest.record_standalone(&[]);
    assert_success(output);
    patina_dst_trace::TraceBundle::load(&trace)
        .unwrap()
        .validate()
        .unwrap();
}
#[cfg(target_os = "linux")]
#[test]
fn ptrace_request_specific_pid_pointer_and_absent_arguments_reach_the_model() {
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("ptrace.c");
    std::fs::write(&source, r#"
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <unistd.h>
#include <errno.h>
int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1) { ptrace(PTRACE_TRACEME); return 10; }
    errno = 0;
    if (ptrace(PTRACE_ATTACH, getpid()) != -1 || errno != EPERM) return 1;
    errno = 0;
    if (ptrace(PTRACE_DETACH, getpid(), (void *)0, (void *)0) != -1 || errno != ESRCH) return 2;
    errno = 0;
    if (ptrace(PTRACE_SEIZE, getpid(), (void *)1, (void *)0) != -1 || errno != EIO) return 3;
    errno = 0;
    if (ptrace(PTRACE_SEIZE, getpid(), (void *)0, (void *)PTRACE_O_TRACESYSGOOD) != -1 || errno != EPERM) return 4;
    long word = 0;
    errno = 0;
    if (ptrace(PTRACE_PEEKDATA, getpid(), &word) != -1 || errno != ESRCH) return 5;
    return 0;
}
"#).unwrap();
    let guest = common::native::assert_build_c_guest(
        source.to_str().unwrap(),
        common::native::CLink::PosixShim,
    );
    let (output, trace) = guest.record_standalone(&[]);
    assert_success(output);
    patina_dst_trace::TraceBundle::load(&trace)
        .unwrap()
        .validate()
        .unwrap();
    guest.assert_internal_fatal(&["traceme"], &["PTRACE_TRACEME"]);
}
