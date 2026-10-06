//! Real libc-door coverage for Rust variadic boundary ownership.
use crate::common;

use common::native::{Guest, assert_success, text};
use std::process::Command;

#[test]
fn fcntl_panic_is_internal_with_either_panic_strategy_and_hook() {
    // Class pairing: the exported-boundary ownership lint and the shared
    // internal-fatal detector. Injection is compiled into planted-faults;
    // no test edits a copy of production source.
    for strategy in ["unwind", "abort"] {
        let dir = tempfile::tempdir().unwrap();
        let output = assert_success(
            Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
                .current_dir(common::native_workspace())
                .args([
                    "rustc",
                    "--lib",
                    "--locked",
                    "--message-format=json",
                    "-p",
                    "patina-dst-native-shim",
                    "--features",
                    "planted-faults",
                    "--target-dir",
                ])
                .arg(dir.path().join("build"))
                .arg("--")
                .args(patina_dst_native_shim::POSIX_RUST_FLAGS)
                .arg("-C")
                .arg(format!("panic={strategy}"))
                .output()
                .unwrap(),
        );
        let archives: Vec<_> = text(&output.stdout)
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|message| message["reason"] == "compiler-artifact")
            .flat_map(|message| message["filenames"].as_array().unwrap().clone())
            .filter_map(|name| name.as_str().map(str::to_owned))
            .filter(|name| name.ends_with("/libpatina_dst_native_shim.a"))
            .collect();
        assert_eq!(archives.len(), 1, "one built guest archive");
        let object = common::compile_posix_object(dir.path());
        let source = dir.path().join("variadic_panic.rs");
        std::fs::write(
            &source,
            r#"
unsafe extern "C" { fn fcntl(fd: i32, cmd: i32, ...) -> i32; }
fn main() {
    if std::env::args().any(|arg| arg == "replace") {
        std::panic::set_hook(Box::new(|_| {}));
    }
    unsafe { fcntl(i32::MIN, 3); }
    panic!("the planted boundary returned");
}
"#,
        )
        .unwrap();
        let binary = dir.path().join("variadic-panic");
        let mut rustc = Command::new("rustc");
        rustc
            .arg("--edition=2024")
            .arg(&source)
            .args(["-C", &format!("panic={strategy}"), "-C"])
            .arg(format!("link-arg={}", object.display()))
            .arg("-C")
            .arg(format!("link-arg={}", archives[0]))
            .arg("-o")
            .arg(&binary);
        if cfg!(target_os = "linux") {
            rustc.args(["-C", "link-arg=-Wl,--wrap=dlsym", "-C", "link-arg=-lc"]);
        }
        assert_success(rustc.output().unwrap());
        let guest = Guest { dir, binary };
        guest.assert_internal_fatal(&[], &["planted variadic boundary panic"]);
        let diagnostics: &[&str] = match (strategy, cfg!(target_os = "linux")) {
            ("unwind", _) => &["patina native shim panic: unwinding an owned boundary"],
            ("abort", true) => &["patina native shim panic: aborting an owned boundary"],
            _ => &[], // Darwin libc abort: signal + incomplete trace still required.
        };
        guest.assert_internal_fatal(&["replace"], diagnostics);
    }
}

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
