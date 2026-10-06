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
#ifdef __linux__
#include <sys/inotify.h>
#include <sys/syscall.h>
#endif
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
    /* Class pairing: command-directed payload widths and the operand matrix.
     * SETNEXTWD validates a full unsigned word, unlike the terminal int args. */
    int watches = (int)syscall(SYS_inotify_init1, IN_NONBLOCK);
    unsigned long nextwd = _IOW('I', 0, int);
    if (watches < 0) return 13;
    errno = 0;
    if (ioctl(watches, nextwd, 0x100000001UL) != -1 || errno != EINVAL) return 14;
    if (ioctl(watches, nextwd, 37UL)) return 15;
    if (syscall(SYS_inotify_add_watch, watches, "/ioctl", IN_MODIFY) != 37) return 16;
    if (close(watches)) return 17;
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
#[cfg(target_os = "linux")]
#[test]
fn prctl_option_specific_absent_word_pointer_and_reserved_arguments_reach_the_model() {
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("prctl.c");
    std::fs::write(&source, r#"
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <linux/filter.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#ifndef PR_GET_AUXV
#define PR_GET_AUXV 0x41555856
#endif
int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1) { prctl(PR_SET_SECCOMP, 1UL); return 20; }
    if (prctl(PR_GET_DUMPABLE) != 1) return 1;
    if (prctl(PR_SET_DUMPABLE, 0UL) || prctl(PR_GET_DUMPABLE) != 0) return 2;
    if (prctl(PR_SET_DUMPABLE, 1UL) || prctl(PR_GET_DUMPABLE) != 1) return 3;
    char name[16] = {0};
    if (prctl(PR_SET_NAME, "variadic-name") || prctl(PR_GET_NAME, name)) return 4;
    if (strcmp(name, "variadic-name")) return 5;
    int signal = 0;
    if (prctl(PR_SET_PDEATHSIG, (unsigned long)SIGUSR1) || prctl(PR_GET_PDEATHSIG, &signal) || signal != SIGUSR1) return 6;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) || prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL) != 1) return 7;
    errno = 0;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 1UL, 0UL, 0UL) != -1 || errno != EINVAL) return 8;
    unsigned long auxv[128] = {0};
    if (prctl(PR_GET_AUXV, auxv, (unsigned long)sizeof(auxv), 0UL, 0UL) <= 0) return 9;
    errno = 0;
    if (prctl(-1) != -1 || errno != EINVAL) return 10;
    errno = 0;
    if (prctl(PR_SET_SECCOMP, 0UL) != -1 || errno != EINVAL) return 11;
    errno = 0;
    if (prctl(PR_SET_SECCOMP, 2UL, (void *)0) != -1 || errno != EFAULT) return 12;
    struct sock_fprog empty = {0};
    errno = 0;
    if (prctl(PR_SET_SECCOMP, 2UL, &empty) != -1 || errno != EINVAL) return 13;
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
    guest.assert_internal_fatal(&["strict"], &["entering strict mode"]);
}
#[test]
fn printf_doors_preserve_promotions_pointers_and_long_formatting() {
    // Class pairing: the guarded variadic inventory and shared wrong-slot matrix.
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("stdio.c");
    std::fs::write(&source, r#"
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
extern int patina_stream_printf(FILE *, const char *, ...);
int main(void) {
    /* FILE handles remain the modeled sentinels; their descriptors can name a
     * virtual file, so pread observes the bytes each formatted door produced. */
    int fd = open("/formatted", O_CREAT | O_RDWR, 0600);
    if (fd < 0 || dup2(fd, STDOUT_FILENO) != STDOUT_FILENO) return 1;
    const char *format = "mix:%hhd:%hu:%.2f:%s:%p%n\n";
    int count = -1;
    char expected[256];
    int expected_count = -1;
    int length = snprintf(expected, sizeof(expected), format, (signed char)-7,
                          (unsigned short)513, (float)1.25, "words", (void *)&count,
                          &expected_count);
    if (length <= 0 || expected_count != length - 1) return 2;
    if (printf(format, (signed char)-7, (unsigned short)513, (float)1.25,
               "words", (void *)&count, &count) != length || count != expected_count) return 3;
    count = -1;
    if (fprintf(stdout, format, (signed char)-7, (unsigned short)513, (float)1.25,
                "words", (void *)&count, &count) != length || count != expected_count) return 4;
    count = -1;
    if (patina_stream_printf(stdout, format, (signed char)-7, (unsigned short)513, (float)1.25,
                             "words", (void *)&count, &count) != length || count != expected_count) return 5;
    if (fflush(stdout)) return 6;
    char actual[256] = {0};
    for (int door = 0; door < 3; door++) {
        if (pread(fd, actual, (size_t)length, (off_t)door * length) != length ||
            memcmp(actual, expected, (size_t)length)) return 7;
    }
    char *long_text = malloc(8193);
    char *long_actual = malloc(8192);
    if (!long_text || !long_actual) return 8;
    memset(long_text, 'x', 8192); long_text[8192] = 0;
    if (printf("%s", long_text) != 8192 || fprintf(stdout, "%s", long_text) != 8192 ||
        patina_stream_printf(stdout, "%s", long_text) != 8192 || fflush(stdout)) return 9;
    for (int door = 0; door < 3; door++) {
        off_t offset = (off_t)3 * length + (off_t)door * 8192;
        if (pread(fd, long_actual, 8192, offset) != 8192 || memcmp(long_actual, long_text, 8192)) return 10;
    }
    free(long_actual);
    free(long_text);
    if (printf("%s", "") != 0 || printf("plain") != 5 || fprintf(stdout, "plain") != 5 ||
        patina_stream_printf(stdout, "fixed") != 5 || fflush(stdout)) return 11;
    if (pread(fd, actual, 15, (off_t)3 * length + 3 * 8192) != 15 ||
        memcmp(actual, "plainplainfixed", 15)) return 12;
    return close(fd) ? 13 : 0;
}
"#).unwrap();
    let guest = common::native::assert_build_c_guest_with_flags(
        source.to_str().unwrap(),
        common::native::CLink::PosixShim,
        &["-fno-builtin"],
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
fn syscall_raw_capture_preserves_zero_through_six_machine_arguments() {
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("syscall.c");
    std::fs::write(&source, r#"
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
int main(void) {
    if (syscall(SYS_getpid) != getpid()) return 1;
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/raw-args", O_CREAT | O_RDWR, 0600);
    if (fd < 0) return 2;
    if (syscall(SYS_write, fd, "six-args", (size_t)8) != 8) return 3;
    if (syscall(SYS_lseek, fd, (off_t)0, SEEK_SET) != 0) return 4;
    char bytes[8] = {0};
    if (syscall(SYS_read, fd, bytes, sizeof(bytes)) != 8 || memcmp(bytes, "six-args", 8)) return 5;
    if (syscall(SYS_ftruncate, fd, (off_t)8192)) return 6;
    /* mmap's fd and offset occupy the fifth and sixth captured positions. */
    char *mapping = (char *)syscall(SYS_mmap, (void *)0, (size_t)4096,
                     PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)4096);
    if (mapping == MAP_FAILED) return 7;
    memcpy(mapping, "offset", 6);
    if (syscall(SYS_msync, mapping, (size_t)4096, MS_SYNC)) return 8;
    memset(bytes, 0, sizeof(bytes));
    if (syscall(SYS_pread64, fd, bytes, (size_t)6, (off_t)4096) != 6 || memcmp(bytes, "offset", 6)) return 9;
    char *target = mmap(0, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (target == MAP_FAILED) return 10;
    void *moved = (void *)syscall(SYS_mremap, mapping, (size_t)4096, (size_t)4096,
                                MREMAP_MAYMOVE | MREMAP_FIXED, target);
    if (moved != target || memcmp(moved, "offset", 6)) return 11;
    if (syscall(SYS_munmap, moved, (size_t)4096) || syscall(SYS_close, fd)) return 12;
    errno = 0;
    if (syscall(SYS_close, -1) != -1 || errno != EBADF) return 13;
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
}
