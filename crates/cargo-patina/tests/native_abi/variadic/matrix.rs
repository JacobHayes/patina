//! Compiled failpoints exercise boundary ownership and operand corruption.
use crate::common;
use common::native::{Guest, assert_success, text};
use std::path::Path;
use std::process::Command;

#[test]
fn every_variadic_family_contains_panics_and_detects_wrong_arguments() {
    // Class pairing: exported-boundary ownership is enforced by ast-grep;
    // real C calls detect operand-decoding errors through model behavior.
    // Failpoints are explicitly armed after startup, never source patches.
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
                    "test-panic",
                    "--target-dir",
                ])
                .arg(dir.path().join("build"))
                .arg("--")
                .args(patina_dst_native_shim::POSIX_RUST_FLAGS)
                .arg("-C")
                .arg(format!("panic={strategy}"))
                .arg("-C")
                .arg(if strategy == "abort" {
                    "opt-level=3"
                } else {
                    "opt-level=0"
                })
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
        let mut cases = vec![
            (4, 0, "ioctl"),
            (1, 0, "fcntl"),
            (3, 0, "open"),
            (3, 1, "openat"),
        ];
        if cfg!(target_os = "linux") {
            cases.extend([
                (4, 2, "ioctl"),
                (6, 0, "prctl"),
                (5, 0, "ptrace"),
                (1, 1, "fcntl64"),
                (2, 0, "mremap"),
                (3, 2, "open64"),
                (3, 3, "openat64"),
                (3, 4, "__open"),
                (3, 5, "__open64"),
            ]);
        }
        assert_symbol_ownership(Path::new(&archives[0]), &object, &cases, strategy);
        let c_source = dir.path().join("variadic-call.c");
        let c_object = dir.path().join("variadic-call.o");
        std::fs::write(&c_source, C_CALLS).unwrap();
        assert_success(
            common::c_compiler()
                .args([
                    "-std=c11",
                    "-fno-builtin",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-c",
                ])
                .arg(&c_source)
                .arg("-o")
                .arg(&c_object)
                .output()
                .unwrap(),
        );
        let source = dir.path().join("variadic_panic.rs");
        std::fs::write(
            &source,
            r#"
unsafe extern "C" { fn variadic_call(family: u32, fault: u32, variant: u32) -> i32; }
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let family = args[1].parse().unwrap();
    let fault = args[2].parse().unwrap();
    let variant = args[3].parse().unwrap();
    if args.get(4).is_some() { std::panic::set_hook(Box::new(|_| {})); }
    std::process::exit(unsafe { variadic_call(family, fault, variant) });
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
            .arg(format!("link-arg={}", c_object.display()))
            .arg("-C")
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
        for (family, variant, name) in cases {
            let family = family.to_string();
            let variant = variant.to_string();
            let (normal, trace) = guest.record_standalone(&[&family, "0", &variant]);
            assert_success(normal);
            patina_dst_trace::TraceBundle::load(&trace)
                .unwrap()
                .validate()
                .unwrap();
            let (mutated, _) = guest.record_standalone(&[&family, "2", &variant]);
            assert_eq!(
                mutated.status.code(),
                Some(family.parse::<i32>().unwrap() * 10),
                "{name} operand mutation must fail the semantic assertion: {mutated:?}"
            );
            guest.assert_internal_fatal(
                &[&family, "1", &variant],
                &["planted variadic boundary panic"],
            );
            let diagnostics: &[&str] = match (strategy, cfg!(target_os = "linux")) {
                ("unwind", _) => &["patina native shim panic: unwinding an owned boundary"],
                ("abort", true) => &["patina native shim panic: aborting an owned boundary"],
                _ => &[],
            };
            guest.assert_internal_fatal(&[&family, "1", &variant, "replace"], diagnostics);
            eprintln!(
                "matrix {strategy}: {name}[{variant}]: control=0, planted operand failure={}, original hook and replaced hook passed",
                mutated.status.code().unwrap()
            );
        }
    }
}

fn assert_symbol_ownership(
    archive: &Path,
    object: &Path,
    cases: &[(u32, u32, &str)],
    strategy: &str,
) {
    // Apple nm cannot read the newer LLVM bitcode bundled from Rust std.
    // Extract the shim's native object members and require every nm invocation
    // to succeed; the final guest link separately checks the complete archive.
    let bytes = std::fs::read(archive).unwrap();
    let archive_file = object::read::archive::ArchiveFile::parse(bytes.as_slice()).unwrap();
    let members_dir = object.parent().unwrap().join("nm-members");
    std::fs::create_dir(&members_dir).unwrap();
    let mut members = Vec::new();
    for member in archive_file.members() {
        let member = member.unwrap();
        if !member.name().starts_with(b"patina_dst_native_shim-") {
            continue;
        }
        let path = members_dir.join(format!("member-{}.o", members.len()));
        std::fs::write(&path, member.data(bytes.as_slice()).unwrap()).unwrap();
        members.push(path);
    }
    assert!(!members.is_empty(), "shim object members must be present");
    #[cfg(target_os = "linux")]
    assert_hidden_routes(&members, cases);
    let archive_nm = assert_success(
        Command::new("nm")
            .args(["-g", "-A"])
            .args(&members)
            .output()
            .unwrap(),
    );
    let c_nm = assert_success(Command::new("nm").arg("-A").arg(object).output().unwrap());
    let definitions = |output: &[u8], symbol: &str| -> Vec<(String, String)> {
        let spelling = if cfg!(target_os = "macos") {
            format!("_{symbol}")
        } else {
            symbol.to_owned()
        };
        text(output)
            .lines()
            .filter_map(|line| {
                let words: Vec<_> = line.split_whitespace().collect();
                if words.len() >= 3
                    && words[words.len() - 1] == spelling
                    && matches!(words[words.len() - 2], "T" | "t" | "W" | "w")
                {
                    Some((
                        words[..words.len() - 2].join(" "),
                        words[words.len() - 2].to_owned(),
                    ))
                } else {
                    None
                }
            })
            .collect()
    };
    for (_, _, symbol) in cases {
        let rust = definitions(&archive_nm.stdout, symbol);
        assert_eq!(
            rust.len(),
            1,
            "exactly one strong Rust definition of {symbol}: {rust:?}"
        );
        assert_eq!(rust[0].1, "T", "{symbol} must be strong");
        assert!(
            definitions(&c_nm.stdout, symbol).is_empty(),
            "C still defines {symbol}"
        );
        if cfg!(target_os = "linux") && *symbol != "patina_stream_printf" {
            let route = definitions(&archive_nm.stdout, &format!("patina_route_{symbol}"));
            assert_eq!(
                route, rust,
                "hidden route shares {symbol}'s object and address"
            );
        }
        eprintln!("nm {strategy}: {symbol}: one strong Rust definition, zero C definitions");
    }
}

#[cfg(target_os = "linux")]
fn assert_hidden_routes(members: &[std::path::PathBuf], cases: &[(u32, u32, &str)]) {
    use object::{Object, ObjectSymbol};
    let mut routes = std::collections::BTreeMap::<String, Vec<u8>>::new();
    for path in members {
        let bytes = std::fs::read(path).unwrap();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        for symbol in file.symbols().filter(|symbol| symbol.is_definition()) {
            let name = symbol.name().unwrap();
            if !name.starts_with("patina_route_") {
                continue;
            }
            let object::SymbolFlags::Elf { st_other, .. } = symbol.flags() else {
                panic!("Linux route {name} must be an ELF symbol");
            };
            routes
                .entry(name.to_owned())
                .or_default()
                .push(st_other & 3);
        }
    }
    for (_, _, symbol) in cases {
        if *symbol == "patina_stream_printf" {
            continue;
        }
        let name = format!("patina_route_{symbol}");
        assert_eq!(
            routes.get(&name).map(Vec::as_slice),
            Some([2].as_slice()),
            "{name} must have exactly one ELF STV_HIDDEN definition"
        );
    }
}

const C_CALLS: &str = r#"
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#ifdef __linux__
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
extern int __open(const char *, int, ...);
extern int __open64(const char *, int, ...);
#endif
extern void patina_variadic_test_arm(unsigned family, unsigned fault);
/* Each representative supplies a valid extra operand so fault=2 can read the
 * wrong variadic position without invoking undefined behavior in the probe. */
int variadic_call(unsigned family, unsigned fault, unsigned variant) {
    int fd = open("/variadic-fault", O_CREAT | O_RDWR, 0600);
    if (fd < 0) return 90;
    switch (family) {
    case 1:
        patina_variadic_test_arm(family, fault);
#ifdef __linux__
        if (variant) { if (fcntl64(fd, F_SETFD, FD_CLOEXEC, 0)) return 10; }
        else
#endif
        if (fcntl(fd, F_SETFD, FD_CLOEXEC, 0)) return 10;
        return fcntl(fd, F_GETFD) == FD_CLOEXEC ? 0 : 10;
#ifdef __linux__
    case 2: {
        void *source = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        void *target = mmap(0, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (source == MAP_FAILED || target == MAP_FAILED) return 90;
        ((char *)source)[0] = 73;
        patina_variadic_test_arm(family, fault);
        void *result = mremap(source, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, target, (void *)0);
        return result == target && ((char *)result)[0] == 73 ? 0 : 20;
    }
#endif
    case 3: {
        umask(0);
        patina_variadic_test_arm(family, fault);
        int created;
        switch (variant) {
        case 0: created = open("/fault-mode", O_CREAT | O_RDWR, 0623, 0); break;
        case 1: created = openat(AT_FDCWD, "/fault-mode", O_CREAT | O_RDWR, 0623, 0); break;
#ifdef __linux__
        case 2: created = open64("/fault-mode", O_CREAT | O_RDWR, 0623, 0); break;
        case 3: created = openat64(AT_FDCWD, "/fault-mode", O_CREAT | O_RDWR, 0623, 0); break;
        case 4: created = __open("/fault-mode", O_CREAT | O_RDWR, 0623, 0); break;
        case 5: created = __open64("/fault-mode", O_CREAT | O_RDWR, 0623, 0); break;
#endif
        default: return 90;
        }
        struct stat value;
        return created >= 0 && !fstat(created, &value) && (value.st_mode & 0777) == 0623 ? 0 : 30;
    }
    case 4: {
#ifdef __linux__
        if (variant == 2) {
            int master = posix_openpt(O_RDWR | O_NOCTTY);
            if (master < 0 || grantpt(master) || unlockpt(master)) return 90;
            patina_variadic_test_arm(family, fault);
            int peer = ioctl(master, TIOCGPTPEER, O_RDWR, O_RDONLY);
            return peer >= 0 && (fcntl(peer, F_GETFL) & O_ACCMODE) == O_RDWR ? 0 : 40;
        }
#endif
        int enabled = 1;
        patina_variadic_test_arm(family, fault);
        return !ioctl(fd, FIONBIO, &enabled, (void *)0) && (fcntl(fd, F_GETFL) & O_NONBLOCK) ? 0 : 40;
    }
#ifdef __linux__
    case 5: {
        pid_t pid = getpid();
        errno = 0;
        patina_variadic_test_arm(family, fault);
        return ptrace(PTRACE_ATTACH, pid, (pid_t)0) == -1 && errno == EPERM ? 0 : 50;
    }
    case 6: {
        patina_variadic_test_arm(family, fault);
        return !prctl(PR_SET_DUMPABLE, 1UL, 0UL) && prctl(PR_GET_DUMPABLE) == 1 ? 0 : 60;
    }
#endif
    case 7: {
        patina_variadic_test_arm(family, fault);
        /* A second integer makes the planted va_arg shift deterministic. */
        const char *format = "%d";
        if (variant == 0) return printf(format, 123, 7) == 3 ? 0 : 70;
        if (variant == 1) return fprintf(stderr, format, 123, 7) == 3 ? 0 : 70;
        return 90;
    }
#ifdef __linux__
    case 8: {
        char byte = 0;
        if (write(fd, "q", 1) != 1 || lseek(fd, 0, SEEK_SET)) return 90;
        patina_variadic_test_arm(family, fault);
        return syscall(SYS_read, fd, &byte, (size_t)1) == 1 && byte == 'q' ? 0 : 80;
    }
#endif
    default: return 90;
    }
}
"#;
