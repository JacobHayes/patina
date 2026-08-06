#!/usr/bin/env bash
set -euo pipefail

help() {
  cat <<'EOF'
validate-native-shim.sh — validate the native (macOS/Linux) linked-shim path.

Builds and drives many C and Rust probes through the packaged native shim to
prove std::fs, filesystem metadata, SystemTime/Instant/thread::sleep, captured
stdio, std entropy, and real thread spawn/join + mutex/condvar contention all run
deterministically under DetScheduler — with seeded determinism and record/replay
identity — and that host-effect symbols stay correctly interposed/denied. Fails
loudly on any divergence.

Usage: validate-native-shim.sh [-h|--help]

Takes no positional arguments. Requires a C compiler.

Environment:
  CC                       C compiler to use (default cc).
  CARGO_TARGET_DIR         override the Cargo target directory (default <repo>/target).
  KEEP_PATINA_TMP=1        preserve the scratch temp dir instead of deleting it on exit.
  PATINA_REQUIRE_STRACE=1  require strace-based syscall checks (Linux; fail if unavailable).
  PATINA_REQUIRE_KTRACE=1  require ktrace-based syscall checks (macOS; fail if unavailable).

Exit status: 0 = validated; 1 = a determinism/interposition check failed;
2 = usage error or a missing prerequisite (C compiler).
EOF
}
case "${1:-}" in
  -h|--help) help; exit 0 ;;
  "") ;;
  *) echo "validate-native-shim.sh: unexpected argument '$1' (takes no positional arguments; see --help)" >&2; exit 2 ;;
esac

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target_dir=${CARGO_TARGET_DIR:-$root/target}
tmp=$(mktemp -d)
if [[ ${KEEP_PATINA_TMP:-0} == 1 ]]; then
  echo "validate-native-shim: preserving $tmp" >&2
else
  trap 'rm -rf "$tmp"' EXIT
fi

cc=${CC:-cc}
if ! command -v "$cc" >/dev/null 2>&1; then
  echo "validate-native-shim: C compiler not found: $cc" >&2
  exit 2
fi

# Stock macOS has no `timeout` binary (coreutils is optional; GitHub's macOS
# runners lack it too). The contention probes rely on it purely as a deadlock
# guard, so an alarm+exec wrapper preserves that semantic: a hung probe is
# killed and exits non-zero, which the seed-stability check then reports.
if ! command -v timeout >/dev/null 2>&1; then
  timeout() { perl -e 'alarm shift @ARGV; exec @ARGV or die "exec: $!"' "$@"; }
fi

# A direct staticlib link that drives any host vehicle (the packaged startup
# constructor's host I/O, managed threads, trace-fd I/O) must reach the shim's
# host-alias table. On Linux that table resolves through `__real_dlsym`, the real
# glibc resolver provided by `-Wl,--wrap=dlsym`; without the flag `__real_dlsym`
# is a null weak symbol and the first host vehicle call segfaults. `cargo patina
# native-build` always passes this flag; the direct-`cc` probes below pass it
# explicitly. macOS resolves `dlsym` directly and needs no flag.
if [[ "$(uname -s)" == Linux ]]; then
  native_wrap=(-Wl,--wrap=dlsym)
else
  native_wrap=()
fi

cat >"$tmp/probe.c" <<'C'
#include "patina_native.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check(int condition, const char *operation) {
    if (!condition) {
        fprintf(stderr, "%s failed (patina errno %d)\n", operation, patina_errno());
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    int use_env = argc == 2 && strcmp(argv[1], "env") == 0;
    uint64_t seed = use_env ? 123 : (argc == 2 ? (uint64_t)strtoull(argv[1], NULL, 10) : 123);
    unsigned char random[16];
    uint64_t before = UINT64_MAX;
    uint64_t after = 0;
    char contents[16] = {0};

    if (!check((use_env ? patina_init_from_env() : patina_init_crash(seed)) == 0, "init") ||
        !check(patina_entropy(random, sizeof random) == 0, "entropy") ||
        !check(patina_clock_now(PATINA_CLOCK_MONOTONIC, &before) == 0, "clock before") ||
        !check(patina_sleep_until(PATINA_CLOCK_MONOTONIC, 5000000) == 0, "sleep") ||
        !check(patina_clock_now(PATINA_CLOCK_MONOTONIC, &after) == 0, "clock after") ||
        !check(patina_mkdir("/state") == 0, "mkdir")) return 1;

    int fd = patina_open("/state/value", PATINA_O_READ | PATINA_O_WRITE |
        PATINA_O_CREATE | PATINA_O_TRUNCATE);
    if (!check(fd >= 0, "open") ||
        !check(patina_write(fd, "stable", 6) == 6, "stable write") ||
        !check(patina_fsync(fd) == 0, "fsync") ||
        !check(patina_write(fd, "-volatile", 9) == 9, "volatile write") ||
        !check(patina_crash() == 0, "crash") ||
        !check(patina_close(fd) == -1, "stale descriptor rejection")) return 1;

    fd = patina_open("/state/value", PATINA_O_READ);
    if (!check(fd >= 0, "reopen") ||
        !check(patina_read(fd, contents, sizeof contents) == 6, "read checkpoint") ||
        !check(patina_close(fd) == 0, "close") ||
        !check(patina_rename("/state/value", "/state/renamed") == 0, "rename") ||
        !check(patina_unlink("/state/renamed") == 0, "unlink") ||
        !check(patina_rmdir("/state") == 0, "rmdir") ||
        !check(patina_shutdown() == 0, "shutdown")) return 1;

    printf("NATIVE_SHIM_RESULT seed=%" PRIu64 " random=", seed);
    for (size_t i = 0; i < sizeof random; ++i) printf("%02x", random[i]);
    printf(" before=%" PRIu64 " after=%" PRIu64 " contents=%s\n", before, after, contents);
    return 0;
}
C

cat >"$tmp/posix_probe.c" <<'C'
#include "patina_native.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char contents[8] = {0};
    if (patina_init_crash(7) != 0) return 10;
    if (patina_mkdir("/state") != 0) return 11;
    int fd = open("/state/value", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) return 12;
    if (write(fd, "posix", 5) != 5) return 13;
    if (fsync(fd) != 0) return 14;
    if (lseek(fd, 0, SEEK_SET) != 0) return 15;
    if (read(fd, contents, sizeof contents) != 5) return 16;
    if (memcmp(contents, "posix", 5) != 0) return 17;
    if (ftruncate(fd, 3) != 0) return 18;
    if (close(fd) != 0) return 19;

    int base = open("/state/dup", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (base < 0) return 30;
    int duplicate = dup(base);
    if (duplicate != base + 1) return 32;
    if (write(base, "posix", 5) != 5) return 33;
    if (lseek(duplicate, 0, SEEK_CUR) != 5) return 34;
    errno = 0;
    if (dup2(base, 99) != -1 || errno != ENOSYS) return 35;
    if (dup2(base, base) != base) return 36;
    errno = 0;
    if (fcntl(base, F_DUPFD, 1000000) != -1 || errno != ENOSYS) return 37;
    errno = 0;
    if (dup(1) != -1 || errno != ENOSYS) return 38;
    if (close(duplicate) != 0) return 39;
    if (write(base, "-more", 5) != 5) return 40;
    if (close(base) != 0) return 41;
    if (unlink("/state/dup") != 0) return 42;

    extern char **environ;
    if (environ != NULL && environ[0] != NULL) return 50;
    errno = 0;
    if (setenv("HOSTILE", "1", 1) != -1 || errno != ENOSYS) return 51;
    errno = 0;
    if (unsetenv("HOSTILE") != -1 || errno != ENOSYS) return 52;

    if (rename("/state/value", "/state/renamed") != 0) return 20;
    if (unlink("/state/renamed") != 0) return 21;
    if (rmdir("/state") != 0) return 22;
    errno = 0;
    if (close(999) != -1 || errno != EBADF) return 23;
    if (patina_shutdown() != 0) return 24;
    return 0;
}
C

cat >"$tmp/openat_probe.c" <<'C'
#include "patina_native.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * openat/renameat/unlinkat over the path-based deterministic filesystem. rustix
 * lowers its `fs` calls onto these; the shim models AT_FDCWD (a plain path) and
 * fails closed on a real dirfd. Deterministic by construction: a fixed seed and
 * a crash-free round-trip, so two same-seed runs are byte-identical.
 */
int main(int argc, char **argv) {
    uint64_t seed = argc == 2 ? (uint64_t)strtoull(argv[1], NULL, 10) : 1;
    if (patina_init_crash(seed) != 0) return 10;
    if (patina_mkdir("/state") != 0) return 11;

    int fd = openat(AT_FDCWD, "/state/at", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) return 12;
    if (write(fd, "openat", 6) != 6) return 13;
    if (lseek(fd, 0, SEEK_SET) != 0) return 14;
    char contents[8] = {0};
    if (read(fd, contents, sizeof contents) != 6) return 15;
    if (memcmp(contents, "openat", 6) != 0) return 16;
    if (close(fd) != 0) return 17;

    /* A real dirfd is not modeled and fails closed. */
    errno = 0;
    if (openat(99, "/state/at", O_RDONLY) != -1 || errno != ENOSYS) return 18;

    /* renameat(AT_FDCWD, AT_FDCWD) routes to the deterministic rename. */
    if (renameat(AT_FDCWD, "/state/at", AT_FDCWD, "/state/at-renamed") != 0) return 19;
    errno = 0;
    if (renameat(99, "/state/at-renamed", AT_FDCWD, "/x") != -1 || errno != ENOSYS) return 20;

    /* unlinkat with AT_REMOVEDIR removes a directory; without it, a file. */
    if (patina_mkdir("/state/at-dir") != 0) return 21;
    if (unlinkat(AT_FDCWD, "/state/at-dir", AT_REMOVEDIR) != 0) return 22;
    if (unlinkat(AT_FDCWD, "/state/at-renamed", 0) != 0) return 23;
    if (patina_rmdir("/state") != 0) return 24;

    /* printf is the shim's captured stdio now, not host stdio: print while the
     * context is live, then drain the capture to the real descriptors so the
     * harness can read it. */
    printf("NATIVE_OPENAT_RESULT seed=%" PRIu64 " contents=%s\n", seed, contents);
    if (patina_flush_captured_stdio() != 0) return 26;
    if (patina_shutdown() != 0) return 25;
    return 0;
}
C

cat >"$tmp/realpath_probe.c" <<'C'
/*
 * Mirror patina_posix.c's feature-test macros: on macOS `realpath` is asm-renamed
 * to `realpath$DARWIN_EXTSN` (the malloc-on-NULL variant Rust std/libc reference),
 * so the shim defines and the probe must call that same symbol -- without
 * _DARWIN_C_SOURCE the probe would bind the plain host `_realpath` and never
 * exercise the shim.
 */
#ifdef __linux__
#define _GNU_SOURCE 1
#elif defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "patina_native.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * realpath over the deterministic filesystem: std::fs::canonicalize reaches
 * realpath(path, NULL) on macOS (the allocating convention) and realpath(path,
 * buf) on Linux. Both must resolve an existing guest path -- including a
 * `..`/`.`/`//`-laden spelling of the same directory -- to the same canonical
 * absolute path, and the result must be byte-identical across two same-seed
 * runs. Before patina_canonicalize the NULL convention returned ENOSYS.
 */
int main(int argc, char **argv) {
    uint64_t seed = argc == 2 ? (uint64_t)strtoull(argv[1], NULL, 10) : 1;
    if (patina_init_crash(seed) != 0) return 10;
    if (patina_mkdir("/root") != 0) return 11;
    if (patina_mkdir("/root/fragments") != 0) return 12;

    char *allocated = realpath("/root/fragments", NULL);
    if (allocated == NULL) return 13;

    char buffer[PATH_MAX];
    char *filled = realpath("/root/../root/./fragments//", buffer);
    if (filled != buffer) return 14;

    if (strcmp(allocated, "/root/fragments") != 0) return 15;
    if (strcmp(allocated, filled) != 0) return 16;

    free(allocated);
    if (patina_rmdir("/root/fragments") != 0) return 17;
    if (patina_rmdir("/root") != 0) return 18;

    /* printf is the shim's captured stdio now, not host stdio: print while the
     * context is live, then drain the capture to the real descriptors so the
     * harness can read it. */
    printf("NATIVE_REALPATH_RESULT seed=%" PRIu64 " canonical=%s\n", seed, filled);
    if (patina_flush_captured_stdio() != 0) return 20;
    if (patina_shutdown() != 0) return 19;
    return 0;
}
C

cat >"$tmp/std_probe.rs" <<'RS'
// An ordinary Rust program: no Patina-specific init/shutdown calls. The
// packaged `cargo patina build`/`run` startup path installs and
// finalizes the deterministic runtime around it.
fn main() {
    use std::hash::{BuildHasher, Hasher};

    println!("PATINA_STRACE_MARKER");

    let Ok(system) = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH) else { std::process::exit(21); };
    if system.as_nanos() != 0 { std::process::exit(30); }
    let mut first_hash = std::collections::hash_map::RandomState::new().build_hasher();
    first_hash.write(b"patina");
    let mut second_hash = std::collections::hash_map::RandomState::new().build_hasher();
    second_hash.write(b"patina");
    let (first_hash, second_hash) = (first_hash.finish(), second_hash.finish());
    if first_hash == second_hash { std::process::exit(32); }
    let started = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(2));
    if started.elapsed() != std::time::Duration::from_millis(2) {
        std::process::exit(31);
    }
    if std::fs::create_dir("/state").is_err() { std::process::exit(40); }
    if std::fs::create_dir("/state/nested").is_err() { std::process::exit(41); }
    if std::fs::write("/state/value", b"ordinary-std").is_err() { std::process::exit(42); }
    if std::os::unix::fs::symlink("value", "/state/link").is_err() { std::process::exit(43); }
    if !matches!(std::fs::metadata("/state/value"), Ok(value) if value.len() == 12) {
        std::process::exit(44);
    }
    if !matches!(std::fs::read("/state/value"), Ok(value) if value == b"ordinary-std") {
        std::process::exit(45);
    }

    let mut entries = Vec::new();
    let Ok(read_dir) = std::fs::read_dir("/state") else { std::process::exit(46); };
    for entry in read_dir {
        let Ok(entry) = entry else { std::process::exit(47); };
        let Ok(file_type) = entry.file_type() else { std::process::exit(48); };
        let kind = if file_type.is_symlink() {
            "symlink"
        } else if file_type.is_dir() {
            "dir"
        } else if file_type.is_file() {
            "file"
        } else {
            std::process::exit(49);
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            std::process::exit(50);
        };
        entries.push(format!("{name}:{kind}"));
    }
    let fs_summary = entries.join(",");
    if fs_summary != "link:symlink,nested:dir,value:file" { std::process::exit(51); }
    if !matches!(std::fs::read_link("/state/link"), Ok(target) if target == std::path::Path::new("value")) {
        std::process::exit(52);
    }
    if !matches!(std::fs::symlink_metadata("/state/link"), Ok(metadata) if metadata.file_type().is_symlink()) {
        std::process::exit(53);
    }
    if !matches!(std::fs::metadata("/state/link"), Ok(metadata) if metadata.len() == 12 && metadata.is_file()) {
        std::process::exit(54);
    }

    if std::fs::rename("/state/value", "/state/renamed").is_err() { std::process::exit(55); }
    if std::fs::remove_file("/state/link").is_err() { std::process::exit(56); }
    if std::fs::remove_file("/state/renamed").is_err() { std::process::exit(57); }
    if std::fs::remove_dir("/state/nested").is_err() { std::process::exit(58); }
    if std::fs::remove_dir("/state").is_err() { std::process::exit(59); }
    println!(
        "NATIVE_STD_RESULT epoch_ns={} first_hash={first_hash:016x} second_hash={second_hash:016x} fs={fs_summary}",
        system.as_nanos(),
    );
}
RS

cat >"$tmp/thread_probe.rs" <<'RS'
// Ordinary Rust threads, Mutex, and Condvar executed under Patina's
// deterministic scheduler through the interposed pthread layer. Three workers
// each increment a shared counter under the mutex and append their id to a
// shared log; the final count is schedule-invariant but the acquisition order
// is interleaving-sensitive, so it is stable per seed and varies across seeds.
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

struct Shared {
    counter: u64,
    order: Vec<u8>,
    done: u32,
}

fn main() {
    let workers: u8 = 3;
    let iterations: u64 = 4;
    let shared = Arc::new((
        Mutex::new(Shared {
            counter: 0,
            order: Vec::new(),
            done: 0,
        }),
        Condvar::new(),
    ));
    let mut handles = Vec::new();
    for id in 0..workers {
        let shared = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            let (lock, cond) = &*shared;
            for _ in 0..iterations {
                let mut guard = lock.lock().unwrap();
                guard.counter += 1;
                guard.order.push(id);
            }
            let mut guard = lock.lock().unwrap();
            guard.done += 1;
            cond.notify_all();
        }));
    }
    {
        let (lock, cond) = &*shared;
        let mut guard = lock.lock().unwrap();
        while guard.done < u32::from(workers) {
            guard = cond.wait(guard).unwrap();
        }
    }
    for handle in handles {
        handle.join().unwrap();
    }
    let (lock, _cond) = &*shared;
    let guard = lock.lock().unwrap();
    let counter = guard.counter;
    let order: String = guard.order.iter().map(|id| char::from(b'0' + id)).collect();
    drop(guard);
    println!("NATIVE_THREAD_RESULT counter={counter} order={order}");
}
RS

cat >"$tmp/contend_probe.rs" <<'RS'
// The main thread holds a std::sync::Mutex ACROSS a boundary op (a virtual-clock
// sleep) while a worker contends for the same lock. If the mutex were a real
// kernel lock, the worker would block in the kernel while parked with the baton
// and deadlock. Because the mutex is virtual (routed through the deterministic
// scheduler), it completes deterministically and no update is lost: final is
// always 111 (10 + 100 + 1). No explicit Patina init/shutdown: the packaged
// startup path installs and finalizes the runtime.
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

fn main() {
    let state = Arc::new((Mutex::new(0u64), Condvar::new()));
    let worker_state = Arc::clone(&state);
    let worker = thread::spawn(move || {
        let (lock, condvar) = &*worker_state;
        let mut guard = lock.lock().unwrap();
        *guard += 1;
        condvar.notify_all();
        *guard
    });

    {
        let (lock, _) = &*state;
        let mut guard = lock.lock().unwrap();
        *guard += 10;
        thread::sleep(Duration::from_millis(5));
        *guard += 100;
    }

    let worker_result = worker.join().unwrap();
    let (lock, _) = &*state;
    let final_value = *lock.lock().unwrap();
    println!("NATIVE_CONTEND_RESULT worker={worker_result} final={final_value}");
}
RS

cat >"$tmp/udp_probe.rs" <<'RS'
// Ordinary std::net::UdpSocket datagrams routed through Patina's SimNet. Three
// worker threads each send their id to a collector; the collector logs the
// arrival order, which is decided by the deterministic scheduler — stable per
// seed and varying across seeds. A blocking recv on the empty collector parks
// the task through the baton and is woken when a worker sends. No host network
// symbol is called: the sockets are fully virtual. No explicit Patina init.
use std::net::UdpSocket;
use std::thread;

fn main() {
    let collector = UdpSocket::bind("127.0.0.1:9000").unwrap();
    let mut workers = Vec::new();
    for id in 0..3u8 {
        let port = 9001 + u16::from(id);
        let sock = UdpSocket::bind(format!("127.0.0.1:{port}")).unwrap();
        workers.push(thread::spawn(move || {
            sock.send_to(&[b'0' + id], "127.0.0.1:9000").unwrap();
        }));
    }
    let mut order = String::new();
    let mut buf = [0u8; 4];
    for _ in 0..3 {
        let (_n, _from) = collector.recv_from(&mut buf).unwrap();
        order.push(char::from(buf[0]));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    println!("NATIVE_UDP_RESULT order={order}");
}
RS

cat >"$tmp/dup_probe.rs" <<'RS'
// std::fs::File::try_clone routes through the interposed fcntl(F_DUPFD_CLOEXEC)
// into the recorded FsDup operation; the clone shares the open-file cursor.
use std::io::{Read, Seek, SeekFrom};

fn main() {
    std::fs::create_dir("/state").unwrap();
    std::fs::write("/state/value", b"abcdef").unwrap();
    let mut first = std::fs::File::open("/state/value").unwrap();
    let mut second = first.try_clone().unwrap();
    let mut head = [0u8; 3];
    first.read_exact(&mut head).unwrap();
    let mut rest = String::new();
    second.read_to_string(&mut rest).unwrap();
    second.seek(SeekFrom::Start(1)).unwrap();
    let mut mid = [0u8; 2];
    first.read_exact(&mut mid).unwrap();
    drop(first);
    drop(second);
    std::fs::remove_file("/state/value").unwrap();
    std::fs::remove_dir("/state").unwrap();
    println!(
        "NATIVE_DUP_RESULT head={} rest={rest} mid={}",
        String::from_utf8_lossy(&head),
        String::from_utf8_lossy(&mid),
    );
}
RS

cat >"$tmp/env_probe.rs" <<'RS'
// The deterministic environment is empty: std::env::vars (the direct environ
// path) sees nothing, and interposed getenv hides every host/control variable.
fn main() {
    let leaked: Vec<String> = std::env::vars_os()
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect();
    if !leaked.is_empty() {
        eprintln!("environ leaked: {}", leaked.join(","));
        std::process::exit(60);
    }
    if std::env::var_os("HOME").is_some()
        || std::env::var_os("PATH").is_some()
        || std::env::var_os("PATINA_MODE").is_some()
    {
        std::process::exit(61);
    }
    println!("NATIVE_ENV_RESULT vars=0");
}
RS

cat >"$tmp/escape_probe.c" <<'C'
#include <pthread.h>

__attribute__((noinline, used)) static void direct_syscall(void) {
#if defined(__aarch64__)
    __asm__ volatile("svc #0");
#elif defined(__x86_64__)
    __asm__ volatile("syscall");
#endif
}

static void *thread(void *value) { return value; }
int main(void) {
    pthread_t value;
    return pthread_create(&value, NULL, thread, NULL);
}
C

cat >"$tmp/unknown_import_probe.c" <<'C'
#include <stdio.h>

int main(void) { return puts("unknown-import-probe") < 0; }
C

cargo build --locked --manifest-path "$root/Cargo.toml" -p patina-dst-native-shim -p cargo-patina >/dev/null
runner="$target_dir/debug/cargo-patina"

# -----------------------------------------------------------------------------
# Host-alias doctrine: static enforcement over the shim's own objects.
#
# The doctrine (see the shim's `hostapi` module and ARCHITECTURE.md "Host-alias
# doctrine") requires that shim-internal code never name a public, interposable
# host symbol as an undefined external — such a name lands in the guest binary's
# import table and forces a name-based `--allow` that guest code can ride past
# the audit (the class the macOS dispatch-semaphore Parker escape belonged to).
# Every host vehicle is instead resolved at runtime through the single `dlsym`
# primitive. This gate scans the shim's OWN compiled object members and fails on
# any undefined external the audit would deny as a classified escape, holding the
# shim to the exact standard it enforces on guests. The `object` scan and its
# planted-leak self-test (a fixture naming `open`/`semaphore_wait` that the scan
# must catch, so it can never go vacuous) live in the cargo test below; running
# it here makes the containment gate cover the doctrine. Red→green: the
# pre-doctrine shim (which named `semaphore_wait`, `read$NOCANCEL`, ... directly)
# fails this; the swept shim passes with `dlsym` as the only escape-surface
# residue.
echo 'validate-native-shim: enforcing the host-alias doctrine over the shim objects' >&2
cargo test --locked --manifest-path "$root/Cargo.toml" -p cargo-patina \
  --test shim_host_alias >/dev/null
# The C-ABI-only probe links the shim staticlib WITHOUT the packaged POSIX layer
# (no `patina_posix.c`), so it defines no `__wrap_dlsym` and must NOT be built
# with `-Wl,--wrap=dlsym` (that would rewrite std's own bundled `dlsym` probe to
# the missing wrapper). It also drives no host vehicle — no threads, no trace fd,
# an empty stdio flush — so it never reaches the host-alias table and needs no
# wrap. The POSIX probe below links `patina_posix.c` (which provides
# `__wrap_dlsym`) and exercises the startup constructor, so it takes the wrap.
"$cc" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
  -I"$root/crates/patina-native-shim/include" \
  "$tmp/probe.c" "$target_dir/debug/libpatina_dst_native_shim.a" \
  -o "$tmp/probe"
"$cc" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
  -I"$root/crates/patina-native-shim/include" \
  "$tmp/posix_probe.c" "$root/crates/patina-native-shim/c/patina_posix.c" \
  "$target_dir/debug/libpatina_dst_native_shim.a" ${native_wrap[@]+"${native_wrap[@]}"} -o "$tmp/posix-probe"
"$tmp/posix-probe"
# openat/renameat/unlinkat over the deterministic filesystem, linked against the
# shim exactly like the posix probe. Two same-seed runs must be byte-identical
# and the write/read round-trip must read back through the deterministic FS.
"$cc" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
  -I"$root/crates/patina-native-shim/include" \
  "$tmp/openat_probe.c" "$root/crates/patina-native-shim/c/patina_posix.c" \
  "$target_dir/debug/libpatina_dst_native_shim.a" ${native_wrap[@]+"${native_wrap[@]}"} -o "$tmp/openat-probe"
"$tmp/openat-probe" 5 >"$tmp/openat-seed-5-1"
"$tmp/openat-probe" 5 >"$tmp/openat-seed-5-2"
cmp "$tmp/openat-seed-5-1" "$tmp/openat-seed-5-2"
grep -qx 'NATIVE_OPENAT_RESULT seed=5 contents=openat' "$tmp/openat-seed-5-1"
# realpath over the deterministic filesystem, linked against the shim exactly
# like the openat probe. Both realpath conventions -- allocating (destination
# NULL) and caller-buffer -- must agree on the canonical path, and two same-seed
# runs must be byte-identical.
"$cc" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
  -I"$root/crates/patina-native-shim/include" \
  "$tmp/realpath_probe.c" "$root/crates/patina-native-shim/c/patina_posix.c" \
  "$target_dir/debug/libpatina_dst_native_shim.a" ${native_wrap[@]+"${native_wrap[@]}"} -o "$tmp/realpath-probe"
"$tmp/realpath-probe" 5 >"$tmp/realpath-seed-5-1"
"$tmp/realpath-probe" 5 >"$tmp/realpath-seed-5-2"
cmp "$tmp/realpath-seed-5-1" "$tmp/realpath-seed-5-2"
grep -qx 'NATIVE_REALPATH_RESULT seed=5 canonical=/root/fragments' "$tmp/realpath-seed-5-1"
# The interposed ordinary-std probe is built and driven through the packaged
# `cargo patina` native target: native-build compiles the shim layer, injects
# cfg(patina)/cfg(dst), and links the shim below the program; native-run wires
# the PATINA_TRACE_FD supervisor channel for record/replay. The probe carries no
# Patina-specific init/shutdown calls: the packaged startup path installs and
# finalizes the deterministic runtime around ordinary application code.
"$runner" build "$tmp/std_probe.rs" --output "$tmp/std-probe" >/dev/null

# Fail-closed startup: running the same binary directly, outside the supervisor,
# must abort with a clear message rather than silently run undeterministically.
if "$tmp/std-probe" >/dev/null 2>"$tmp/standalone-error"; then
  echo 'validate-native-shim: native binary ran standalone without the supervisor' >&2
  exit 1
fi
grep -q 'must run under' "$tmp/standalone-error"

"$runner" run "$tmp/std-probe" --seed 9 >"$tmp/std-seed-1"
"$runner" run "$tmp/std-probe" --seed 9 >"$tmp/std-seed-2"
"$runner" run "$tmp/std-probe" --seed 10 >"$tmp/std-seed-other"
cmp "$tmp/std-seed-1" "$tmp/std-seed-2"
if cmp -s "$tmp/std-seed-1" "$tmp/std-seed-other"; then
  echo 'validate-native-shim: distinct std-probe seeds produced identical output' >&2
  exit 1
fi
"$runner" run "$tmp/std-probe" --seed 9 --record "$tmp/std.patina" \
  --fingerprint native-std-v1 >"$tmp/std-record"
"$runner" run "$tmp/std-probe" --seed 9 --record "$tmp/std-repeat.patina" \
  --fingerprint native-std-v1 >/dev/null
cmp "$tmp/std.patina" "$tmp/std-repeat.patina"
"$runner" replay "$tmp/std-probe" "$tmp/std.patina" \
  --fingerprint native-std-v1 >"$tmp/std-replay"
cmp "$tmp/std-record" "$tmp/std-replay"
cmp "$tmp/std-seed-1" "$tmp/std-replay"
grep -qx 'PATINA_STRACE_MARKER' "$tmp/std-replay"
grep -Eq '^NATIVE_STD_RESULT epoch_ns=0 first_hash=[0-9a-f]{16} second_hash=[0-9a-f]{16} fs=link:symlink,nested:dir,value:file$' "$tmp/std-replay"
if "$runner" replay "$tmp/std-probe" "$tmp/std.patina" \
  --fingerprint native-std-other >/dev/null 2>&1; then
  echo 'validate-native-shim: std-probe replay accepted a changed fingerprint' >&2
  exit 1
fi

# The audit's static allowlist covers only effect-free host-deferred symbols.
# Everything the SHIM itself uses as its host control plane is `--allow`ed per
# audited binary here instead, so an unmanaged binary importing the same symbols
# still fails the audit.
#
# Under the host-alias doctrine (see the shim's `hostapi` modules and the
# host-alias static section above) the shim resolves every host vehicle — the
# trace-fd read/write aliases and the execution-baton semaphore — at runtime
# through `dlsym(RTLD_NEXT, ...)`, so those vehicle names never appear in the
# guest import table. On macOS `dlsym` itself is the sanctioned primitive and the
# whole control plane is just `dlsym`. On Linux the shim interposes `dlsym`, so
# the primitive is `__real_dlsym` reached through `-Wl,--wrap=dlsym`, which leaves
# `dlsym` as the single resolution residue; `pthread_create` is swept off the
# table too (a plain strong def interposes it and the real creator is resolved
# through the same `dlsym(RTLD_NEXT, ...)` table, so no `--wrap=pthread_create`
# and no named residue). Either way a guest importing
# semaphore_wait/sem_wait/read$NOCANCEL/__read/pthread_create/... is now DENIED
# rather than riding a name-based allowance.
control_plane=(
  --allow dlsym
)
shim_allow=("${control_plane[@]}")
"$runner" audit "$tmp/std-probe" \
  "${shim_allow[@]}" >"$tmp/native-imports"

# Syscall containment pass. Linux uses a whole-run strace default-deny over
# file/network/clock/descriptor/entropy classes (below). macOS has no equivalent
# runtime gate: a sound whole-run syscall check would have to separate the
# pre-main dyld/libSystem loader prelude from post-init guest syscalls, and
# ktrace — the only root-capable, SIP-compatible whole-run tracer here — cannot
# provide that separation (see the Darwin branch). Rather than ship a check that
# cannot fail, the macOS path skips loudly and PATINA_REQUIRE_KTRACE=1 turns the
# unmet demand into a hard failure.
if [[ "$(uname -s)" == Darwin ]]; then
  # macOS runtime syscall containment is NOT verified here. ktrace decodes BSD
  # syscalls (BSC_*, class 4 subclass 0x0C) whole-run under root with SIP on, but
  # cannot found a sound default-deny gate for three independent reasons, each
  # reproduced on this host during calibration:
  #   1. BSC_* events carry only raw register values, not decoded paths, so a
  #      guest's raw open()/openat()/stat() is indistinguishable by argument from
  #      the loader's prelude open()/stat() on libSystem/dylib paths.
  #   2. There is no in-band boundary marker separating the loader prelude from
  #      guest code: the deterministic runtime buffers ALL guest output (stdout
  #      AND stderr) into a single flush at process exit, so a "first write to the
  #      probe's stdout" boundary does not exist — an early unbuffered stderr
  #      marker is observed emitted only at the very end of the trace, after the
  #      end-of-main stdout flush.
  #   3. The loader/runtime legitimately issues the same syscall NAMES a guest
  #      escape would (open, openat, stat64, fcntl, getpid, ...) and its init
  #      interleaves with early guest execution, so a name-scoped default-deny is
  #      either vacuous (allowlist the names and escapes pass) or false-positives
  #      on every clean run. A planted post-init raw getpid (inline `svc`) reaches
  #      the kernel and lands among the runtime's own getpid events, name-identical
  #      and not temporally separable from them.
  # A future ktrace/OS exposing path context or a userspace boundary marker — or a
  # permitted dtrace pid-provider main:entry boundary — could found a real gate.
  # Until then the static instruction scan + import audit below are the macOS
  # containment evidence, and an operator demanding ktrace enforcement is told the
  # guarantee cannot be provided rather than handed a check that cannot fail.
  if [[ "${PATINA_REQUIRE_KTRACE:-0}" == 1 ]]; then
    echo 'validate-native-shim: PATINA_REQUIRE_KTRACE=1 but macOS runtime syscall containment is not verifiable via ktrace (BSC_* events lack path context; the runtime defers all output so there is no pre-main/post-init boundary; loader and guest share syscall names). Refusing to report a containment gate that cannot fail.' >&2
    exit 1
  fi
  echo 'validate-native-shim: skipping macOS ktrace containment pass (not verifiable via ktrace: BSC_* syscall events carry no path context and the runtime defers all output, so the loader prelude cannot be separated from post-init guest syscalls; static instruction scan + import audit remain the macOS containment evidence)' >&2
elif ! command -v strace >/dev/null 2>&1; then
  # Mirror the PATINA_REQUIRE_KTRACE idiom above: the strace pass is the Linux
  # syscall-containment class detector, and a soft-skip when strace is absent
  # means CI could run WITHOUT that gate and never notice. PATINA_REQUIRE_STRACE=1
  # turns the missing-tool skip into a hard failure so CI cannot silently drop
  # the containment evidence (the Linux jobs install strace and set this).
  if [[ "${PATINA_REQUIRE_STRACE:-0}" == 1 ]]; then
    echo 'validate-native-shim: PATINA_REQUIRE_STRACE=1 but strace is not on PATH; the Linux whole-run syscall-containment default-deny gate cannot run. Refusing to pass without it. Install strace (e.g. apt-get install -y strace) or unset PATINA_REQUIRE_STRACE.' >&2
    exit 1
  fi
  echo 'validate-native-shim: skipping strace containment pass (strace not found)' >&2
else
  # Linux whole-run syscall containment: a default-deny strace filter over the
  # file/network/descriptor/memory/clock/entropy classes below.
  #
  # Soundness argument. The shim services ALL application file and network I/O
  # in-process (in-memory FS, simulated net, virtual clock), so a correct run
  # reaches the kernel with ZERO application syscalls -- nothing the guest does
  # is a real syscall. The only genuine syscalls in a clean trace are therefore
  # (1) the dynamic loader's prelude, reading the trusted DT_NEEDED objects it is
  # required to map (libc.so, libgcc_s.so, and their ld.so.cache/ld.so.preload
  # lookups), and (2) Rust's pre-main runtime init (the std stack-overflow guard
  # reads /proc/self/maps once). Both are keyed to TRUSTED PATHS. We exempt:
  #   - the memory/signal/futex/exit prelude syscall names (no path/fd context);
  #   - getrandom(GRND_NONBLOCK) (libc/rng entropy probe);
  #   - openat/open/newfstatat/readlink on a trusted path (*.so*, /etc/ld.so.cache,
  #     /etc/ld.so.preload, /proc/self/maps);
  #   - faccessat/access on exactly /etc/ld.so.preload (the ld.so preload probe);
  #   - read/pread64/fstat/fcntl/lseek on stdio fds 0-3, OR on a fd that WE saw
  #     opened on a trusted path (tracked in `trusted`, cleared on close so a later
  #     application reuse of that fd number is not auto-trusted);
  #   - write to stdio fds 0-3 (the runtime flushes the guest's buffered stdout,
  #     including PATINA_STRACE_MARKER, in a single write at exit).
  # Exemptions are keyed to trusted paths and the fds opened for them. An
  # application open()/openat() on ANY non-trusted path is still denied, and a
  # read/fstat/etc. on any non-trusted fd is still denied. There is no blanket
  # fd or blanket syscall-name allow that a real escape could hide behind. The
  # planted-escape self-test below proves a raw openat on a non-trusted path is
  # still flagged; if it were ever missed, the gate fails loudly.
  #
  # The `-e trace=` set and the awk filter are captured in variables so the
  # planted-escape self-test exercises the EXACT same invocation and filter as
  # the real std-probe check -- an over-broadening of the filter fails the
  # self-test before the real check can pass.
  strace_events='trace=%file,%network,%desc,%memory,%clock,nanosleep,gettimeofday,futex,rt_sigaction,rt_sigprocmask,rt_sigreturn,sigaltstack,sched_yield,exit_group,exit,getrandom'
  strace_filter='
    function trusted_path(a) {
      return (a ~ /\.so(\.|"|$)/) || (a ~ /"\/etc\/ld\.so\.cache"/) || (a ~ /"\/etc\/ld\.so\.preload"/) || (a ~ /"\/proc\/self\/maps"/)
    }
    {
      line = $0
      sub(/^[0-9]+ +/, "", line)
      if (line ~ /^--- / || line ~ /^\+\+\+ /) next
      syscall = line
      sub(/\(.*/, "", syscall)
      args = line
      sub(/^[^(]*\(/, "", args)
      # Track fds opened on a trusted prelude path; release them on close so a
      # reused fd number is not carried over to application code.
      if (syscall ~ /^(openat|openat2|open)$/ && trusted_path(args) && line ~ /= *[0-9]+$/) {
        ret = line; sub(/^.*= */, "", ret); sub(/[^0-9].*/, "", ret); if (ret != "") trusted[ret] = 1
      }
      if (syscall == "close") { cfd = args; sub(/[^0-9].*/, "", cfd); if (cfd != "") delete trusted[cfd] }
      if (syscall ~ /^(execve|brk|arch_prctl|mmap|mmap2|munmap|mprotect|madvise|futex|sched_yield|sigaltstack|rt_sigaction|rt_sigprocmask|rt_sigreturn|exit|exit_group|close)$/) next
      if (syscall == "getrandom" && args ~ /GRND_NONBLOCK/) next
      if (syscall ~ /^(openat|openat2|open|newfstatat|readlink|readlinkat)$/ && trusted_path(args)) next
      if (syscall ~ /^(faccessat|faccessat2|access)$/ && args ~ /"\/etc\/ld\.so\.preload"/) next
      if (syscall ~ /^(read|pread64|fstat|fcntl|lseek)$/) {
        fd = args; sub(/[^0-9].*/, "", fd)
        if (fd ~ /^[0-3]$/ || (fd != "" && (fd in trusted))) next
      }
      if (syscall == "write" && args ~ /^[0-3][,)]/) next
      print line
    }
  '

  # Planted-escape self-test: a tiny program that makes a RAW openat syscall on a
  # non-trusted path (/etc/hostname), bypassing the shim so the openat actually
  # reaches the kernel. Run under the SAME strace invocation and the SAME awk
  # filter as the real check; the filter MUST flag it. This proves the broadened
  # prelude exemptions did not open a hole -- if a future edit lets this pass,
  # the gate fails loudly here, before the real containment check can succeed.
  cat >"$tmp/escape_syscall_probe.c" <<'C'
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void) {
#ifdef SYS_openat
    long fd = syscall(SYS_openat, AT_FDCWD, "/etc/hostname", O_RDONLY);
#else
    long fd = syscall(SYS_open, "/etc/hostname", O_RDONLY);
#endif
    if (fd >= 0) syscall(SYS_close, fd);
    return 0;
}
C
  "$cc" -std=c11 -Wall -Wextra -Werror "$tmp/escape_syscall_probe.c" -o "$tmp/escape-syscall-probe"
  strace -f -s 4096 -e "$strace_events" \
    -o "$tmp/escape-strace" "$tmp/escape-syscall-probe" >/dev/null 2>&1 || true
  awk "$strace_filter" "$tmp/escape-strace" >"$tmp/escape-strace-denied"
  if [[ ! -s "$tmp/escape-strace-denied" ]]; then
    echo 'validate-native-shim: strace filter self-test FAILED: planted raw openat("/etc/hostname") escape was not flagged; the containment filter cannot catch a real escape' >&2
    exit 1
  fi
  if ! grep -Eq 'openat.*"/etc/hostname"' "$tmp/escape-strace-denied"; then
    echo 'validate-native-shim: strace filter self-test FAILED: denied set is non-empty but does not contain the planted openat("/etc/hostname") escape' >&2
    cat "$tmp/escape-strace-denied" >&2
    exit 1
  fi

  PATINA_MODE=seeded PATINA_SEED=9 \
    strace -f -s 4096 -e "$strace_events" \
      -o "$tmp/std-strace" "$tmp/std-probe" >"$tmp/std-strace-stdout"
  grep -qx 'PATINA_STRACE_MARKER' "$tmp/std-strace-stdout"
  awk "$strace_filter" "$tmp/std-strace" >"$tmp/std-strace-denied"
  if [[ -s "$tmp/std-strace-denied" ]]; then
    echo 'validate-native-shim: syscalls escaped the deterministic boundary:' >&2
    cat "$tmp/std-strace-denied" >&2
    exit 1
  fi
fi

# Audit/run parity (native audit/run blockers, issue 2a): standalone `audit` now
# tolerates the shim's own control-plane vehicle (`dlsym`) exactly as the pre-run
# `run` gate does — both build the effective allow set through the single
# `effective_native_allow` constructor — so `audit` reports the surface `run`
# enforces rather than flagging the control-plane `dlsym` that `run` silently
# permits (the reported disparity). A shim-linked std probe therefore audits CLEAN
# with NO `--allow`. Default-deny is unweakened: the only auto-tolerated symbol is
# the fixed control-plane residue (`dlsym`), and every REAL escape symbol is still
# denied — the non-shim escape/unknown-import probes below prove it.
if ! "$runner" audit "$tmp/std-probe" >/dev/null 2>"$tmp/audit-error"; then
  echo 'validate-native-shim: audit/run parity FAILED: a shim-linked std probe was refused by `audit` without --allow, but the pre-run `run` gate would run it — the control-plane dlsym must be tolerated identically by audit and run' >&2
  cat "$tmp/audit-error" >&2
  exit 1
fi
"$cc" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror "$tmp/escape_probe.c" -o "$tmp/escape-probe"
# The cc-built probes are deliberately NOT shim-linked, so a bare audit is
# refused by the shim-link gate before classification; the planted-escape legs
# use --raw, which runs the real audit (instruction scan and escape categories
# included) under the PATINA_RAW_AUDIT banner.
if "$runner" audit "$tmp/escape-probe" >/dev/null 2>"$tmp/shim-gate-error"; then
  echo 'validate-native-shim: audit of a non-shim-linked binary unexpectedly passed' >&2
  exit 1
fi
grep -q 'not built with `cargo patina build`' "$tmp/shim-gate-error"
if "$runner" audit "$tmp/escape-probe" --raw \
  >"$tmp/escape-out" 2>"$tmp/escape-error"; then
  echo 'validate-native-shim: native escape probe unexpectedly passed audit' >&2
  exit 1
fi
grep -q 'PATINA_RAW_AUDIT' "$tmp/escape-error"
grep -Eq 'direct-syscall|unmanaged-thread' "$tmp/escape-error"
"$cc" -std=c11 -Wall -Wextra -Werror "$tmp/unknown_import_probe.c" -o "$tmp/unknown-import-probe"
if "$runner" audit "$tmp/unknown-import-probe" --raw \
  >"$tmp/unknown-import-out" 2>"$tmp/unknown-import-error"; then
  echo 'validate-native-shim: unknown import probe unexpectedly passed audit' >&2
  exit 1
fi
grep -q 'unknown-import' "$tmp/unknown-import-error"

# Managed threads: an ordinary Rust std::thread + Mutex + Condvar program built
# through the native target. The schedule-invariant total is stable while the
# interleaving-sensitive acquisition order is seed-deterministic and varies
# across seeds; record/replay reproduces the exact schedule.
#
# Runs on both platforms: Rust std lowers Mutex/Condvar/parking to the
# interposed pthread symbols on macOS and to raw SYS_futex (through the
# interposed libc `syscall` wrapper) on Linux, and both route those waits and
# wakes through the deterministic scheduler.
"$runner" build "$tmp/thread_probe.rs" --output "$tmp/thread-probe" >/dev/null
"$runner" run "$tmp/thread-probe" --seed 7 >"$tmp/thread-seed-1"
"$runner" run "$tmp/thread-probe" --seed 7 >"$tmp/thread-seed-2"
cmp "$tmp/thread-seed-1" "$tmp/thread-seed-2"
grep -q 'counter=12' "$tmp/thread-seed-1"
# The acquisition order must actually vary across seeds. Interleaving
# granularity differs by platform — macOS takes a scheduling point at every
# interposed lock, while on Linux uncontended locks are pure userspace atomics
# and only futex contention points interleave — so assert variation over a
# range of seeds rather than between two fixed ones.
thread_distinct=$(for s in 1 2 3 4 5 6; do
  "$runner" run "$tmp/thread-probe" --seed "$s"
done | sort -u | wc -l)
if [[ "$thread_distinct" -lt 2 ]]; then
  echo 'validate-native-shim: thread-probe order did not vary across seeds' >&2
  exit 1
fi
"$runner" run "$tmp/thread-probe" --seed 7 --record "$tmp/thread.patina" \
  --fingerprint native-thread-v1 >"$tmp/thread-record"
"$runner" run "$tmp/thread-probe" --seed 7 --record "$tmp/thread-repeat.patina" \
  --fingerprint native-thread-v1 >/dev/null
cmp "$tmp/thread.patina" "$tmp/thread-repeat.patina"
"$runner" replay "$tmp/thread-probe" "$tmp/thread.patina" \
  --fingerprint native-thread-v1 >"$tmp/thread-replay"
cmp "$tmp/thread-record" "$tmp/thread-replay"
cmp "$tmp/thread-seed-1" "$tmp/thread-replay"
if "$runner" replay "$tmp/thread-probe" "$tmp/thread.patina" \
  --fingerprint native-thread-other >/dev/null 2>&1; then
  echo 'validate-native-shim: thread-probe replay accepted a changed fingerprint' >&2
  exit 1
fi
# The pthread symbols are shim-provided (managed), so the thread probe audits
# clean under the same allowlist as the single-threaded probe, while a bare
# host pthread_create (the escape probe) is still denied as an unmanaged thread.
"$runner" audit "$tmp/thread-probe" "${shim_allow[@]}" >"$tmp/thread-imports"

# A std::sync::Mutex held across a boundary op while another thread contends:
# proves lock contention is routed through the scheduler (virtual mutex) and not
# a host kernel lock. `timeout` guards against a regression that reintroduces a
# real host lock (which would deadlock); seeded mode uses no trace descriptor,
# so timeout does not disturb the control plane.
"$runner" build "$tmp/contend_probe.rs" --output "$tmp/contend-probe" >/dev/null
contend_1=$(timeout 60 "$runner" run "$tmp/contend-probe" --seed 2)
contend_2=$(timeout 60 "$runner" run "$tmp/contend-probe" --seed 2)
if [[ "$contend_1" != "$contend_2" ]]; then
  echo 'validate-native-shim: contention probe was not seed-stable' >&2
  exit 1
fi
# Mutual exclusion held across the boundary: no update is lost, so the total is
# always 111 regardless of interleaving.
if ! grep -Eq 'NATIVE_CONTEND_RESULT worker=(1|111) final=111$' <<<"$contend_1"; then
  echo "validate-native-shim: contention probe lost an update across a boundary-held lock: $contend_1" >&2
  exit 1
fi
"$runner" audit "$tmp/contend-probe" "${shim_allow[@]}" >/dev/null

# Ordinary std::net::UdpSocket datagrams over SimNet: workers send to a
# collector whose arrival order is scheduler-decided, so it is seed-stable and
# varies across seeds, and record/replay reproduces the exact ordering. The
# sockets are fully virtual, so the probe audits clean with no new allowance.
"$runner" build "$tmp/udp_probe.rs" --output "$tmp/udp-probe" >/dev/null
"$runner" run "$tmp/udp-probe" --seed 1 >"$tmp/udp-seed-1"
"$runner" run "$tmp/udp-probe" --seed 1 >"$tmp/udp-seed-2"
cmp "$tmp/udp-seed-1" "$tmp/udp-seed-2"
grep -Eq 'NATIVE_UDP_RESULT order=[012]{3}$' "$tmp/udp-seed-1"
# Delivery order is scheduler-decided; assert it varies across a seed range.
udp_distinct=$(for s in 1 2 3 4 5 6; do
  "$runner" run "$tmp/udp-probe" --seed "$s"
done | sort -u | wc -l)
if [[ "$udp_distinct" -lt 2 ]]; then
  echo 'validate-native-shim: udp-probe delivery order did not vary across seeds' >&2
  exit 1
fi
"$runner" run "$tmp/udp-probe" --seed 1 --record "$tmp/udp.patina" \
  --fingerprint native-udp-v1 >"$tmp/udp-record"
"$runner" replay "$tmp/udp-probe" "$tmp/udp.patina" \
  --fingerprint native-udp-v1 >"$tmp/udp-replay"
cmp "$tmp/udp-record" "$tmp/udp-replay"
cmp "$tmp/udp-seed-1" "$tmp/udp-replay"
"$runner" audit "$tmp/udp-probe" "${shim_allow[@]}" >/dev/null

# Deterministic descriptor duplication: File::try_clone routes through
# fcntl(F_DUPFD_CLOEXEC) to the recorded FsDup operation, and the duplicate
# shares the open-file cursor.
"$runner" build "$tmp/dup_probe.rs" --output "$tmp/dup-probe" >/dev/null
"$runner" audit "$tmp/dup-probe" "${shim_allow[@]}" >/dev/null
"$runner" run "$tmp/dup-probe" --seed 3 >"$tmp/dup-seed-1"
"$runner" run "$tmp/dup-probe" --seed 3 >"$tmp/dup-seed-2"
cmp "$tmp/dup-seed-1" "$tmp/dup-seed-2"
grep -qx 'NATIVE_DUP_RESULT head=abc rest=def mid=bc' "$tmp/dup-seed-1"
"$runner" run "$tmp/dup-probe" --seed 3 --record "$tmp/dup.patina" \
  --fingerprint native-dup-v1 >"$tmp/dup-record"
"$runner" replay "$tmp/dup-probe" "$tmp/dup.patina" \
  --fingerprint native-dup-v1 >"$tmp/dup-replay"
cmp "$tmp/dup-record" "$tmp/dup-replay"
cmp "$tmp/dup-seed-1" "$tmp/dup-replay"

# The deterministic environment is empty, including direct environ iteration.
# Host canaries (even PATINA_-prefixed ones) must not affect output or traces.
"$runner" build "$tmp/env_probe.rs" --output "$tmp/env-probe" >/dev/null
"$runner" audit "$tmp/env-probe" "${shim_allow[@]}" >/dev/null
PATINA_ENV_CANARY_HOST=one "$runner" run "$tmp/env-probe" --seed 3 >"$tmp/env-seed-1"
CANARY_HOST=two "$runner" run "$tmp/env-probe" --seed 3 >"$tmp/env-seed-2"
cmp "$tmp/env-seed-1" "$tmp/env-seed-2"
grep -qx 'NATIVE_ENV_RESULT vars=0' "$tmp/env-seed-1"
CANARY_HOST=one "$runner" run "$tmp/env-probe" --seed 3 --record "$tmp/env.patina" \
  --fingerprint native-env-v1 >"$tmp/env-record"
CANARY_HOST=two "$runner" replay "$tmp/env-probe" "$tmp/env.patina" \
  --fingerprint native-env-v1 >"$tmp/env-replay"
cmp "$tmp/env-record" "$tmp/env-replay"
cmp "$tmp/env-seed-1" "$tmp/env-replay"

# R20 std HashMap seeding: std's `RandomState` draws its hashing keys from the
# process entropy source, which the shim seeds deterministically. So a HashMap's
# iteration order must be a pure function of the Patina seed — NOT ambient OS
# randomness (which would make it differ every run) and NOT a fixed constant
# (which would mean the order is not seed-derived at all). This gate proves both
# on the native target: the SAME seed yields byte-identical order across separate
# processes (and reproduces on replay), while a DIFFERENT seed reorders it.
cat >"$tmp/hashmap_probe.rs" <<'RS'
// No explicit Patina init/shutdown: the packaged startup path installs and
// finalizes the runtime around ordinary application code. HashMap iteration
// order is observed by collecting the keys in iteration order; std's RandomState
// seeds its hasher from the (Patina-seeded) entropy source.
use std::collections::HashMap;

fn main() {
    let mut map = HashMap::new();
    for i in 0..16u32 {
        map.insert(format!("key-{i}"), i);
    }
    let order: Vec<String> = map.keys().cloned().collect();
    println!("NATIVE_HASHMAP_ORDER {}", order.join(","));
}
RS
"$runner" build "$tmp/hashmap_probe.rs" --output "$tmp/hashmap-probe" >/dev/null
"$runner" audit "$tmp/hashmap-probe" "${shim_allow[@]}" >/dev/null
"$runner" run "$tmp/hashmap-probe" --seed 1 >"$tmp/hashmap-seed-1"
"$runner" run "$tmp/hashmap-probe" --seed 1 >"$tmp/hashmap-seed-1-again"
"$runner" run "$tmp/hashmap-probe" --seed 2 >"$tmp/hashmap-seed-2"
cmp "$tmp/hashmap-seed-1" "$tmp/hashmap-seed-1-again"
grep -Eq 'NATIVE_HASHMAP_ORDER ([a-z0-9-]+,){15}[a-z0-9-]+$' "$tmp/hashmap-seed-1"
if cmp -s "$tmp/hashmap-seed-1" "$tmp/hashmap-seed-2"; then
  echo 'validate-native-shim: HashMap iteration order did not vary across seeds (not seed-derived: it is a fixed constant, so std hashing is not drawing from Patina entropy)' >&2
  exit 1
fi
"$runner" run "$tmp/hashmap-probe" --seed 1 --record "$tmp/hashmap.patina" \
  --fingerprint native-hashmap-v1 >"$tmp/hashmap-record"
"$runner" replay "$tmp/hashmap-probe" "$tmp/hashmap.patina" \
  --fingerprint native-hashmap-v1 >"$tmp/hashmap-replay"
cmp "$tmp/hashmap-record" "$tmp/hashmap-replay"
cmp "$tmp/hashmap-seed-1" "$tmp/hashmap-replay"

# SlateDB feedback #6: dependency RNG initialization through rand::rng() must
# reach Patina's deterministic entropy, not the host or an unmodeled
# /dev/urandom fallback. This package uses rand's current API directly (stronger
# coverage than HashMap's std RandomState wrapper): same seed is byte-identical,
# another seed changes the bytes, and record->replay reproduces exactly.
rand_pkg="$tmp/rand-rng-pkg"
mkdir -p "$rand_pkg/src"
cat >"$rand_pkg/Cargo.toml" <<'TOML'
[workspace]

[package]
name = "rand_rng_probe"
version = "0.0.0"
edition = "2024"

[dependencies]
rand = "=0.9.5"
TOML
cat >"$rand_pkg/src/main.rs" <<'RS'
use rand::RngCore;

fn main() {
    let mut rng = rand::rng();
    let first = rng.next_u64();
    let mut bytes = [0u8; 24];
    rng.fill_bytes(&mut bytes);
    print!("NATIVE_RAND_RNG first={first:016x} bytes=");
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
}
RS
"$runner" build "$rand_pkg" --output "$tmp/rand-rng-probe" >/dev/null
"$runner" audit "$tmp/rand-rng-probe" "${shim_allow[@]}" >/dev/null
"$runner" run "$tmp/rand-rng-probe" --seed 1 >"$tmp/rand-rng-seed-1"
"$runner" run "$tmp/rand-rng-probe" --seed 1 >"$tmp/rand-rng-seed-1-again"
"$runner" run "$tmp/rand-rng-probe" --seed 2 >"$tmp/rand-rng-seed-2"
cmp "$tmp/rand-rng-seed-1" "$tmp/rand-rng-seed-1-again"
grep -Eq '^NATIVE_RAND_RNG first=[0-9a-f]{16} bytes=[0-9a-f]{48}$' "$tmp/rand-rng-seed-1"
if cmp -s "$tmp/rand-rng-seed-1" "$tmp/rand-rng-seed-2"; then
  echo 'validate-native-shim: rand::rng() output did not vary across seeds' >&2
  exit 1
fi
"$runner" run "$tmp/rand-rng-probe" --seed 1 --record "$tmp/rand-rng.patina" \
  --fingerprint native-rand-rng-v1 >"$tmp/rand-rng-record"
"$runner" replay "$tmp/rand-rng-probe" "$tmp/rand-rng.patina" \
  --fingerprint native-rand-rng-v1 >"$tmp/rand-rng-replay"
cmp "$tmp/rand-rng-record" "$tmp/rand-rng-replay"
cmp "$tmp/rand-rng-seed-1" "$tmp/rand-rng-replay"

# Direct /dev/urandom fallback path: some entropy libraries fall back to opening
# and reading the device if their first getrandom-class probe is unavailable.
# The shim models /dev/urandom as a read-only deterministic entropy device wired
# to the same domain-separated entropy stream.
cat >"$tmp/urandom_probe.rs" <<'RS'
use std::fs::File;
use std::io::Read;

fn main() {
    let mut file = File::open("/dev/urandom").expect("open deterministic urandom");
    let mut bytes = [0u8; 24];
    file.read_exact(&mut bytes).expect("read deterministic urandom");
    print!("NATIVE_URANDOM bytes=");
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
}
RS
"$runner" build "$tmp/urandom_probe.rs" --output "$tmp/urandom-probe" >/dev/null
"$runner" audit "$tmp/urandom-probe" "${shim_allow[@]}" >/dev/null
"$runner" run "$tmp/urandom-probe" --seed 1 >"$tmp/urandom-seed-1"
"$runner" run "$tmp/urandom-probe" --seed 1 >"$tmp/urandom-seed-1-again"
"$runner" run "$tmp/urandom-probe" --seed 2 >"$tmp/urandom-seed-2"
cmp "$tmp/urandom-seed-1" "$tmp/urandom-seed-1-again"
grep -Eq '^NATIVE_URANDOM bytes=[0-9a-f]{48}$' "$tmp/urandom-seed-1"
if cmp -s "$tmp/urandom-seed-1" "$tmp/urandom-seed-2"; then
  echo 'validate-native-shim: /dev/urandom output did not vary across seeds' >&2
  exit 1
fi
"$runner" run "$tmp/urandom-probe" --seed 1 --record "$tmp/urandom.patina" \
  --fingerprint native-urandom-v1 >"$tmp/urandom-record"
"$runner" replay "$tmp/urandom-probe" "$tmp/urandom.patina" \
  --fingerprint native-urandom-v1 >"$tmp/urandom-replay"
cmp "$tmp/urandom-record" "$tmp/urandom-replay"
cmp "$tmp/urandom-seed-1" "$tmp/urandom-replay"

# R20 config-differential double-run: the SAME single-threaded source built plain
# and with `--yield-points` must produce a byte-identical RESULT at the same seed.
# The instrumentation adds scheduling points, but with only one task there is
# never another task to switch to, so every seeded entropy/clock draw happens in
# the same program order and the observable output is schedule-invariant. (The
# recorded traces still DIFFER — the yield-points binary carries extra TaskYield
# operations — which is exactly why cross-replay between the two fails closed on
# the +yieldpoints fingerprint; see the end_to_end yield-points test.) This
# pins that a config change which must NOT alter output indeed does not.
"$runner" build "$tmp/hashmap_probe.rs" --output "$tmp/hashmap-probe-yp" \
  --yield-points >/dev/null
"$runner" run "$tmp/hashmap-probe-yp" --seed 1 >"$tmp/hashmap-yp-seed-1"
if ! cmp -s "$tmp/hashmap-seed-1" "$tmp/hashmap-yp-seed-1"; then
  echo 'validate-native-shim: yield-points on/off changed a single-threaded guest RESULT (config-differential identity broken)' >&2
  diff "$tmp/hashmap-seed-1" "$tmp/hashmap-yp-seed-1" >&2 || true
  exit 1
fi

# Whole-Cargo-package native-build: an ordinary-std package with a path
# dependency (`greeter`) and a build script, driven through its own `cargo
# build` under Patina control. The shim cfg and link args reach the final binary
# through CARGO_ENCODED_RUSTFLAGS while an explicit host --target keeps them off
# build scripts and proc macros (the build script's host-side file read would
# abort into an uninitialized runtime if they leaked). The produced binary
# audits, runs, and record/replays exactly like a single-source binary; the
# build-script env and the dependency's output appear in the deterministic
# result. Multi-bin ambiguity without --bin and an off-allowlist binary both
# fail closed.
pkg="$tmp/pkg"
mkdir -p "$pkg/greeter/src" "$pkg/app/src/bin"
cat >"$pkg/greeter/Cargo.toml" <<'TOML'
[package]
name = "greeter"
version = "0.0.0"
edition = "2024"
TOML
cat >"$pkg/greeter/src/lib.rs" <<'RS'
pub fn greeting() -> String { format!("hello from {}", "greeter") }
RS
cat >"$pkg/app/Cargo.toml" <<'TOML'
[package]
name = "patina-native-pkg"
version = "0.0.0"
edition = "2024"

[dependencies]
greeter = { path = "../greeter" }
TOML
cat >"$pkg/app/build.rs" <<'RS'
fn main() {
    // Runs on the host. Its file I/O would route into an uninitialized Patina
    // runtime and abort if the shim link args leaked onto host build artifacts.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    std::fs::read(std::path::Path::new(&manifest).join("Cargo.toml")).unwrap();
    println!("cargo:rustc-env=PKG_BUILT=1");
    println!("cargo:rerun-if-changed=build.rs");
}
RS
cat >"$pkg/app/src/main.rs" <<'RS'
use std::hash::{BuildHasher, Hasher};
fn main() {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write(greeter::greeting().as_bytes());
    let hash = hasher.finish();
    std::fs::create_dir("/state").unwrap();
    std::fs::write("/state/value", greeter::greeting().as_bytes()).unwrap();
    let stored = std::fs::read_to_string("/state/value").unwrap();
    std::fs::remove_file("/state/value").unwrap();
    std::fs::remove_dir("/state").unwrap();
    println!(
        "NATIVE_PKG_RESULT built={} hash={hash:016x} stored={stored}",
        env!("PKG_BUILT")
    );
}
RS
cat >"$pkg/app/src/bin/leaky.rs" <<'RS'
// Imports an uninterposed process-class libc symbol (`killpg`) the audit denies
// as "process". The spawn family (fork/posix_spawn*/waitpid/kill/...) is now
// shim-defined (deny-traps), so a Command::spawn — or a kill — leaves no process
// *import* to flag; this reaches for a still-uninterposed member of the class.
// Taking its address forces the undefined import; building succeeds, the audit
// must reject the product.
unsafe extern "C" {
    fn killpg(pgrp: i32, sig: i32) -> i32;
}
fn main() {
    let reached = killpg as *const ();
    std::process::exit((reached as usize & 1) as i32);
}
RS

"$runner" build "$pkg/app" --bin patina-native-pkg --output "$tmp/pkg-probe" >/dev/null
"$runner" audit "$tmp/pkg-probe" "${shim_allow[@]}" >/dev/null
"$runner" run "$tmp/pkg-probe" --seed 5 >"$tmp/pkg-seed-1"
"$runner" run "$tmp/pkg-probe" --seed 5 >"$tmp/pkg-seed-2"
"$runner" run "$tmp/pkg-probe" --seed 6 >"$tmp/pkg-seed-other"
cmp "$tmp/pkg-seed-1" "$tmp/pkg-seed-2"
if cmp -s "$tmp/pkg-seed-1" "$tmp/pkg-seed-other"; then
  echo 'validate-native-shim: distinct pkg-probe seeds produced identical output' >&2
  exit 1
fi
grep -q 'built=1' "$tmp/pkg-seed-1"
grep -q 'stored=hello from greeter' "$tmp/pkg-seed-1"
"$runner" run "$tmp/pkg-probe" --seed 5 --record "$tmp/pkg.patina" \
  --fingerprint native-pkg-v1 >"$tmp/pkg-record"
"$runner" replay "$tmp/pkg-probe" "$tmp/pkg.patina" \
  --fingerprint native-pkg-v1 >"$tmp/pkg-replay"
cmp "$tmp/pkg-record" "$tmp/pkg-replay"
cmp "$tmp/pkg-seed-1" "$tmp/pkg-replay"

# Multiple binary targets with no --bin selection fails closed rather than
# guessing which binary to build.
if "$runner" build "$pkg/app" --output "$tmp/pkg-ambiguous" \
  >/dev/null 2>"$tmp/pkg-ambiguous-error"; then
  echo 'validate-native-shim: multi-bin package built without --bin selection' >&2
  exit 1
fi
grep -q 'multiple binary targets' "$tmp/pkg-ambiguous-error"

# A package binary whose build product imports an off-allowlist symbol builds
# but fails the audit with the existing category diagnostic.
"$runner" build "$pkg/app" --bin leaky --output "$tmp/pkg-leaky" >/dev/null
if "$runner" audit "$tmp/pkg-leaky" >/dev/null 2>"$tmp/pkg-leaky-error"; then
  echo 'validate-native-shim: off-allowlist package binary passed the audit' >&2
  exit 1
fi
grep -q 'process' "$tmp/pkg-leaky-error"

"$tmp/probe" 123 >"$tmp/seed-1"
"$tmp/probe" 123 >"$tmp/seed-2"
"$tmp/probe" 124 >"$tmp/seed-other"
cmp "$tmp/seed-1" "$tmp/seed-2"
if cmp -s "$tmp/seed-1" "$tmp/seed-other"; then
  echo 'validate-native-shim: distinct seeds produced identical output' >&2
  exit 1
fi
PATINA_MODE=record PATINA_SEED=123 PATINA_TRACE="$tmp/native.patina" \
  PATINA_FINGERPRINT=native-shim-v1 "$tmp/probe" env >"$tmp/record"
PATINA_MODE=replay PATINA_TRACE="$tmp/native.patina" \
  PATINA_FINGERPRINT=native-shim-v1 "$tmp/probe" env >"$tmp/replay"
cmp "$tmp/record" "$tmp/replay"

# -----------------------------------------------------------------------------
# Virtual-clock timer queue validation probes: timed waits, sleep ordering, and
# SimNet UDP latency all run as ordinary std Rust programs under native-run.
# -----------------------------------------------------------------------------
cat >"$tmp/timed_wait_probe.rs" <<'RS'
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let signal_delay = Duration::from_millis(25);
    let signal_deadline = Duration::from_millis(100);
    let signalled = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_signalled = Arc::clone(&signalled);
    let signal_started = Instant::now();
    let worker = thread::spawn(move || {
        thread::sleep(signal_delay);
        let (lock, condvar) = &*worker_signalled;
        let mut guard = lock.lock().unwrap();
        *guard = true;
        condvar.notify_one();
    });

    let (lock, condvar) = &*signalled;
    let mut guard = lock.lock().unwrap();
    let mut timed_out = false;
    while !*guard {
        let (next_guard, result) = condvar.wait_timeout(guard, signal_deadline).unwrap();
        guard = next_guard;
        if result.timed_out() {
            timed_out = true;
            break;
        }
    }
    let signal_elapsed = signal_started.elapsed();
    if timed_out || !*guard {
        eprintln!("signalled condvar wait timed out unexpectedly");
        std::process::exit(10);
    }
    if signal_elapsed != signal_delay {
        eprintln!(
            "signalled condvar elapsed {:?}, expected {:?}",
            signal_elapsed, signal_delay
        );
        std::process::exit(11);
    }
    drop(guard);
    worker.join().unwrap();

    let timeout = Duration::from_millis(100);
    let timeout_pair = (Mutex::new(false), Condvar::new());
    let (lock, condvar) = &timeout_pair;
    let guard = lock.lock().unwrap();
    let timeout_started = Instant::now();
    let (_guard, result) = condvar.wait_timeout(guard, timeout).unwrap();
    let timeout_elapsed = timeout_started.elapsed();
    if !result.timed_out() {
        eprintln!("unsignalled condvar wait did not time out");
        std::process::exit(12);
    }
    if timeout_elapsed != timeout {
        eprintln!(
            "timeout condvar elapsed {:?}, expected {:?}",
            timeout_elapsed, timeout
        );
        std::process::exit(13);
    }

    println!(
        "NATIVE_TIMED_WAIT_RESULT signalled_elapsed_ns={} timeout_elapsed_ns={}",
        signal_elapsed.as_nanos(),
        timeout_elapsed.as_nanos()
    );
}
RS

cat >"$tmp/recv_timeout_probe.rs" <<'RS'
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

// Two threads over mpsc with recv_timeout. On macOS this drives std's Darwin
// thread Parker (park/park_timeout on a libdispatch semaphore); the shim
// interposes those semaphores and routes the wait through the deterministic
// scheduler + virtual clock, so the delivery/timeout interleaving and the
// timeout count are a function of the seed alone.
fn main() {
    let (tx, rx) = mpsc::channel::<u64>();
    let producer = thread::spawn(move || {
        for i in 0..5 {
            thread::sleep(Duration::from_millis(10));
            tx.send(i).unwrap();
        }
    });
    let mut delivered = Vec::new();
    let mut timeouts = 0u32;
    loop {
        match rx.recv_timeout(Duration::from_millis(7)) {
            Ok(v) => delivered.push(v),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                timeouts += 1;
                if delivered.len() == 5 {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    producer.join().unwrap();
    println!("NATIVE_RECV_TIMEOUT_RESULT delivered={delivered:?} timeouts={timeouts}");
}
RS

cat >"$tmp/rwlock_ffi_probe.rs" <<'RS'
use std::cell::UnsafeCell;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// std's own RwLock never lowers to pthread_rwlock_* on the supported
// toolchains, so exercise the shim's deterministic pthread_rwlock interposers
// directly through FFI. Three writer threads each hold the write lock across a
// scheduling point, so the others park on it; the acquisition order is chosen by
// DetScheduler (writer-preferring, FIFO), byte-identical per seed.
#[repr(C, align(16))]
struct RawRwLock(UnsafeCell<[u8; 200]>);
unsafe impl Sync for RawRwLock {}

unsafe extern "C" {
    fn pthread_rwlock_init(lock: *mut u8, attr: *const u8) -> i32;
    fn pthread_rwlock_wrlock(lock: *mut u8) -> i32;
    fn pthread_rwlock_unlock(lock: *mut u8) -> i32;
}

static LOCK: RawRwLock = RawRwLock(UnsafeCell::new([0u8; 200]));

fn main() {
    unsafe {
        assert_eq!(pthread_rwlock_init(LOCK.0.get() as *mut u8, std::ptr::null()), 0);
    }
    let log = Arc::new(Mutex::new(Vec::<u32>::new()));
    let mut handles = Vec::new();
    for id in 0..3u32 {
        let log = Arc::clone(&log);
        handles.push(thread::spawn(move || {
            for _ in 0..3 {
                unsafe {
                    assert_eq!(pthread_rwlock_wrlock(LOCK.0.get() as *mut u8), 0);
                }
                log.lock().unwrap().push(id);
                thread::sleep(Duration::from_nanos(1));
                unsafe {
                    assert_eq!(pthread_rwlock_unlock(LOCK.0.get() as *mut u8), 0);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    println!("NATIVE_RWLOCK_FFI_RESULT order={:?}", *log.lock().unwrap());
}
RS

cat >"$tmp/os_unfair_lock_probe.rs" <<'RS'
// os_unfair_lock (parking_lot_core's Darwin word lock) is interposed: the bare
// u32 word — with NO init call — routes through the deterministic scheduler and
// the shared mutex table, which lazily registers it on first use. Three threads
// contend on ONE os_unfair_lock guarding a shared vector across a scheduling
// point, so the others park on it; the acquisition order is chosen by
// DetScheduler and is byte-identical per seed. trylock acquires an unheld lock
// and reports contention on a held one.
use std::cell::UnsafeCell;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[repr(C)]
struct Shared {
    word: UnsafeCell<u32>,
    order: UnsafeCell<Vec<u32>>,
}
unsafe impl Sync for Shared {}

unsafe extern "C" {
    fn os_unfair_lock_lock(lock: *mut u32);
    fn os_unfair_lock_trylock(lock: *mut u32) -> bool;
    fn os_unfair_lock_unlock(lock: *mut u32);
}

fn main() {
    let shared = Arc::new(Shared {
        word: UnsafeCell::new(0),
        order: UnsafeCell::new(Vec::new()),
    });
    unsafe {
        let word = shared.word.get();
        assert!(os_unfair_lock_trylock(word), "trylock of an unheld lock must acquire");
        assert!(!os_unfair_lock_trylock(word), "trylock of a held lock must fail");
        os_unfair_lock_unlock(word);
    }
    let mut handles = Vec::new();
    for id in 0..3u32 {
        let shared = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            for _ in 0..3 {
                unsafe {
                    let word = shared.word.get();
                    os_unfair_lock_lock(word);
                    // Guarded by the lock, so serialized under the scheduler.
                    (*shared.order.get()).push(id);
                    thread::sleep(Duration::from_nanos(1));
                    os_unfair_lock_unlock(word);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    unsafe {
        println!("OS_UNFAIR_LOCK_RESULT order={:?}", *shared.order.get());
    }
}
RS

cat >"$tmp/os_unfair_lock_misuse_probe.rs" <<'RS'
// Unlocking a never-locked os_unfair_lock is a programmer error the real
// primitive traps on (an unlock by a non-owner). The interposer must abort
// LOUDLY and deterministically rather than silently succeed — these functions
// have no error channel, so a soft failure would be an invisible escape.
#[repr(C)]
struct OsUnfairLock(u32);
unsafe extern "C" {
    fn os_unfair_lock_unlock(lock: *mut OsUnfairLock);
}
fn main() {
    let mut lock = OsUnfairLock(0);
    unsafe {
        os_unfair_lock_unlock(&mut lock);
    }
    println!("OS_UNFAIR_LOCK_MISUSE_SURVIVED");
}
RS

cat >"$tmp/gate_refusal_probe.rs" <<'RS'
// A genuinely-uninterposed escape: `shm_open` (shared-memory-ipc class) is a
// truly cross-process primitive the shim never interposes, so the pre-run gate
// must REFUSE to run this binary — keeping the refusal path covered now that
// os_unfair_lock is interposed and accepted. The call must be unconditional (a
// dead branch is stripped and would drop the import), so it uses harmless args:
// O_RDONLY on a nonexistent name returns ENOENT with no host effect, so even the
// --allow-unsupported-symbols hatch run stays clean.
use std::ffi::c_char;
unsafe extern "C" {
    fn shm_open(name: *const c_char, oflag: i32, mode: u32) -> i32;
}
fn main() {
    let name = c"/patina-nonexistent-probe";
    let r = unsafe { shm_open(name.as_ptr(), 0, 0) };
    std::hint::black_box(r);
    println!("GATE_REFUSAL_RAN");
}
RS

cat >"$tmp/clock_nsec_probe.rs" <<'RS'
// clock_gettime_nsec_np returns the virtual clock value directly in nanoseconds
// (rustix's time module). It must map onto the same virtual clock as
// clock_gettime — CLOCK_UPTIME_RAW/CLOCK_MONOTONIC both read PATINA monotonic —
// so with no intervening sleep the two reads agree, and two same-seed runs are
// byte-identical.
const CLOCK_REALTIME: u32 = 0;
const CLOCK_MONOTONIC: u32 = 6;
const CLOCK_UPTIME_RAW: u32 = 8;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

unsafe extern "C" {
    fn clock_gettime_nsec_np(clock_id: u32) -> u64;
    fn clock_gettime(clock_id: u32, tp: *mut Timespec) -> i32;
}

fn main() {
    unsafe {
        let mono_ns = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
        let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
        assert_eq!(clock_gettime(CLOCK_MONOTONIC, &mut ts), 0);
        let mono_gt = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
        assert_eq!(
            mono_ns, mono_gt,
            "clock_gettime_nsec_np disagreed with clock_gettime on the virtual monotonic clock"
        );
        let real_ns = clock_gettime_nsec_np(CLOCK_REALTIME);
        println!("CLOCK_NSEC_RESULT mono_ns={mono_ns} real_ns={real_ns}");
    }
}
RS

cat >"$tmp/sleep_order_probe.rs" <<'RS'
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

struct State {
    order: Vec<char>,
    a_elapsed_ns: Option<u128>,
    work: u64,
}

fn main() {
    let state = Arc::new(Mutex::new(State {
        order: Vec::new(),
        a_elapsed_ns: None,
        work: 0,
    }));

    let a_state = Arc::clone(&state);
    let thread_a = thread::spawn(move || {
        let started = Instant::now();
        thread::sleep(Duration::from_millis(100));
        let elapsed = started.elapsed();
        if elapsed != Duration::from_millis(100) {
            eprintln!("thread A elapsed {:?}, expected 100ms", elapsed);
            std::process::exit(20);
        }
        println!("NATIVE_SLEEP_ORDER_A elapsed_ns={}", elapsed.as_nanos());
        let mut guard = a_state.lock().unwrap();
        guard.a_elapsed_ns = Some(elapsed.as_nanos());
        guard.order.push('A');
    });

    let b_state = Arc::clone(&state);
    let thread_b = thread::spawn(move || {
        for value in 0..100u64 {
            let mut guard = b_state.lock().unwrap();
            guard.work += value;
        }
        let work = b_state.lock().unwrap().work;
        println!("NATIVE_SLEEP_ORDER_B done work={work}");
        let mut guard = b_state.lock().unwrap();
        guard.order.push('B');
    });

    thread_a.join().unwrap();
    thread_b.join().unwrap();

    let guard = state.lock().unwrap();
    let order: String = guard.order.iter().collect();
    let a_elapsed_ns = guard.a_elapsed_ns.unwrap();
    println!(
        "NATIVE_SLEEP_ORDER_RESULT order={order} a_elapsed_ns={a_elapsed_ns} work={}",
        guard.work
    );
}
RS

cat >"$tmp/udp_latency_probe.rs" <<'RS'
use std::net::UdpSocket;
use std::thread;
use std::time::Instant;

fn main() {
    let receiver = UdpSocket::bind("127.0.0.1:9100").unwrap();
    let receiver_thread = thread::spawn(move || {
        let started = Instant::now();
        let mut buf = [0u8; 16];
        let (n, _from) = receiver.recv_from(&mut buf).unwrap();
        let elapsed = started.elapsed();
        println!(
            "NATIVE_UDP_LATENCY_RECV elapsed_ns={} bytes={n}",
            elapsed.as_nanos()
        );
        let payload = String::from_utf8(buf[..n].to_vec()).unwrap();
        (elapsed.as_nanos(), payload)
    });

    let sender = UdpSocket::bind("127.0.0.1:9101").unwrap();
    sender.send_to(b"ping", "127.0.0.1:9100").unwrap();
    let (elapsed_ns, payload) = receiver_thread.join().unwrap();
    println!("NATIVE_UDP_LATENCY_RESULT elapsed_ns={elapsed_ns} payload={payload}");
}
RS

cat >"$tmp/tcp_probe.rs" <<'RS'
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;

fn main() {
    let ipv6 = TcpListener::bind("[::1]:9300").is_err();
    let dns = TcpStream::connect("localhost:9300").is_err();

    let listener = TcpListener::bind("127.0.0.1:9300").unwrap();
    let server = thread::spawn(move || {
        let (mut stream, peer) = listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        let reply = String::from_utf8(request).unwrap().to_uppercase();
        stream.write_all(reply.as_bytes()).unwrap();
        peer.to_string()
    });

    let mut client = TcpStream::connect("127.0.0.1:9300").unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    let peer = server.join().unwrap();
    println!("NATIVE_TCP_RESULT reply={reply} peer={peer} ipv6_closed={ipv6} dns_closed={dns}");
}
RS

"$runner" build "$tmp/timed_wait_probe.rs" --output "$tmp/timed-wait-probe" >/dev/null
"$runner" audit "$tmp/timed-wait-probe" "${shim_allow[@]}" >/dev/null
for seed in 5 6; do
  "$runner" run "$tmp/timed-wait-probe" --seed "$seed" >"$tmp/timed-wait-seed-$seed-1"
  "$runner" run "$tmp/timed-wait-probe" --seed "$seed" >"$tmp/timed-wait-seed-$seed-2"
  cmp "$tmp/timed-wait-seed-$seed-1" "$tmp/timed-wait-seed-$seed-2"
  grep -qx 'NATIVE_TIMED_WAIT_RESULT signalled_elapsed_ns=25000000 timeout_elapsed_ns=100000000' \
    "$tmp/timed-wait-seed-$seed-1"
done
"$runner" run "$tmp/timed-wait-probe" --seed 5 --record "$tmp/timed-wait.patina" \
  --fingerprint native-timed-wait-v1 >"$tmp/timed-wait-record"
"$runner" run "$tmp/timed-wait-probe" --seed 5 --record "$tmp/timed-wait-repeat.patina" \
  --fingerprint native-timed-wait-v1 >/dev/null
cmp "$tmp/timed-wait.patina" "$tmp/timed-wait-repeat.patina"
"$runner" replay "$tmp/timed-wait-probe" "$tmp/timed-wait.patina" \
  --fingerprint native-timed-wait-v1 >"$tmp/timed-wait-replay"
cmp "$tmp/timed-wait-record" "$tmp/timed-wait-replay"
cmp "$tmp/timed-wait-seed-5-1" "$tmp/timed-wait-replay"

# std::thread Parker via mpsc recv_timeout. On macOS the Parker blocks on a
# libdispatch semaphore, so this exercises the interposed dispatch-semaphore
# path (park/park_timeout/unpark); on Linux the futex Parker. The interposed
# semaphores must NOT leak as imports (the shim now DEFINES them — before the
# fix they shared the baton's `--allow`ed dispatch-semaphore audit entry, which
# was the escape). The delivery/timeout schedule is byte-identical across three
# runs at multiple seeds and record/replay-exact.
"$runner" build "$tmp/recv_timeout_probe.rs" --output "$tmp/recv-timeout-probe" >/dev/null
"$runner" audit "$tmp/recv-timeout-probe" "${shim_allow[@]}" >/dev/null
if nm -u "$tmp/recv-timeout-probe" 2>/dev/null | grep -q dispatch_semaphore; then
  echo 'validate-native-shim: dispatch_semaphore_* leaked as an import; the Parker escape is not closed' >&2
  exit 1
fi
for seed in 5 6 7; do
  "$runner" run "$tmp/recv-timeout-probe" --seed "$seed" >"$tmp/recv-timeout-$seed-1"
  "$runner" run "$tmp/recv-timeout-probe" --seed "$seed" >"$tmp/recv-timeout-$seed-2"
  "$runner" run "$tmp/recv-timeout-probe" --seed "$seed" >"$tmp/recv-timeout-$seed-3"
  cmp "$tmp/recv-timeout-$seed-1" "$tmp/recv-timeout-$seed-2"
  cmp "$tmp/recv-timeout-$seed-1" "$tmp/recv-timeout-$seed-3"
  grep -Fqx 'NATIVE_RECV_TIMEOUT_RESULT delivered=[0, 1, 2, 3, 4] timeouts=5' \
    "$tmp/recv-timeout-$seed-1"
done
"$runner" run "$tmp/recv-timeout-probe" --seed 5 --record "$tmp/recv-timeout.patina" \
  --fingerprint native-recv-timeout-v1 >"$tmp/recv-timeout-record"
"$runner" run "$tmp/recv-timeout-probe" --seed 5 --record "$tmp/recv-timeout-repeat.patina" \
  --fingerprint native-recv-timeout-v1 >/dev/null
cmp "$tmp/recv-timeout.patina" "$tmp/recv-timeout-repeat.patina"
"$runner" replay "$tmp/recv-timeout-probe" "$tmp/recv-timeout.patina" \
  --fingerprint native-recv-timeout-v1 >"$tmp/recv-timeout-replay"
cmp "$tmp/recv-timeout-record" "$tmp/recv-timeout-replay"

# Deterministic pthread_rwlock_* via FFI (std's RwLock does not lower to these,
# so drive them directly). Writer contention routes through the scheduler:
# byte-identical acquisition order per seed, and the interposers are DEFINED so
# pthread_rwlock never appears as an import.
"$runner" build "$tmp/rwlock_ffi_probe.rs" --output "$tmp/rwlock-ffi-probe" >/dev/null
"$runner" audit "$tmp/rwlock-ffi-probe" "${shim_allow[@]}" >/dev/null
if nm -u "$tmp/rwlock-ffi-probe" 2>/dev/null | grep -q pthread_rwlock; then
  echo 'validate-native-shim: pthread_rwlock leaked as an import; the rwlock interposers are missing' >&2
  exit 1
fi
rwlock_ffi_distinct=0
for seed in 1 3 5; do
  "$runner" run "$tmp/rwlock-ffi-probe" --seed "$seed" >"$tmp/rwlock-ffi-$seed-1"
  "$runner" run "$tmp/rwlock-ffi-probe" --seed "$seed" >"$tmp/rwlock-ffi-$seed-2"
  "$runner" run "$tmp/rwlock-ffi-probe" --seed "$seed" >"$tmp/rwlock-ffi-$seed-3"
  cmp "$tmp/rwlock-ffi-$seed-1" "$tmp/rwlock-ffi-$seed-2"
  cmp "$tmp/rwlock-ffi-$seed-1" "$tmp/rwlock-ffi-$seed-3"
  grep -q '^NATIVE_RWLOCK_FFI_RESULT order=' "$tmp/rwlock-ffi-$seed-1"
done
rwlock_ffi_distinct=$(cat "$tmp"/rwlock-ffi-{1,3,5}-1 | sort -u | wc -l)
if [[ "$rwlock_ffi_distinct" -lt 2 ]]; then
  echo 'validate-native-shim: pthread_rwlock acquisition order did not vary across seeds' >&2
  exit 1
fi

# Pre-run default-deny gate self-test. A binary that reaches a genuinely
# uninterposed escape (`shm_open`, a cross-process architectural non-goal) must
# be REFUSED by native-run, naming and categorizing the symbol, with the guest
# never running; and it must run only under --allow-unsupported-symbols, with a
# loud warning. This keeps the refusal path covered now that os_unfair_lock is
# interposed rather than refused. The gate is demonstrably able to fail: the
# first check depends on the run being rejected.
"$runner" build "$tmp/gate_refusal_probe.rs" \
  --output "$tmp/gate-refusal-probe" >/dev/null
if "$runner" run "$tmp/gate-refusal-probe" --seed 1 \
    >"$tmp/gate-refusal-out" 2>"$tmp/gate-refusal-err"; then
  echo 'validate-native-shim: pre-run gate let a genuinely-uninterposed symbol run' >&2
  exit 1
fi
grep -q 'shm_open' "$tmp/gate-refusal-err"
grep -q 'shared-memory-ipc' "$tmp/gate-refusal-err"
if grep -q 'GATE_REFUSAL_RAN' "$tmp/gate-refusal-out"; then
  echo 'validate-native-shim: guest ran despite the pre-run gate denial' >&2
  exit 1
fi
"$runner" run "$tmp/gate-refusal-probe" --seed 1 --allow-unsupported-symbols all \
  >"$tmp/gate-refusal-hatch-out" 2>"$tmp/gate-refusal-hatch-err"
grep -qx 'GATE_REFUSAL_RAN' "$tmp/gate-refusal-hatch-out"
grep -q 'WARNING' "$tmp/gate-refusal-hatch-err"

# os_unfair_lock acceptance (macOS). Now that the symbol is interposed, the
# contention probe must PASS the pre-run gate with no --allow, audit clean, and
# be byte-identical across two same-seed runs (the flipped former parker-escape
# probe). A misuse — unlocking a never-locked lock — must instead abort loudly
# and deterministically, never printing its survival marker.
if [[ "$(uname -s)" == Darwin ]]; then
  "$runner" build "$tmp/os_unfair_lock_probe.rs" \
    --output "$tmp/os-unfair-lock-probe" >/dev/null
  "$runner" audit "$tmp/os-unfair-lock-probe" "${shim_allow[@]}" >/dev/null
  "$runner" run "$tmp/os-unfair-lock-probe" --seed 1 >"$tmp/os-unfair-lock-1"
  "$runner" run "$tmp/os-unfair-lock-probe" --seed 1 >"$tmp/os-unfair-lock-2"
  cmp "$tmp/os-unfair-lock-1" "$tmp/os-unfair-lock-2"
  grep -Eq '^OS_UNFAIR_LOCK_RESULT order=' "$tmp/os-unfair-lock-1"

  "$runner" build "$tmp/os_unfair_lock_misuse_probe.rs" \
    --output "$tmp/os-unfair-lock-misuse-probe" >/dev/null
  if "$runner" run "$tmp/os-unfair-lock-misuse-probe" --seed 1 \
      >"$tmp/os-unfair-lock-misuse-out" 2>"$tmp/os-unfair-lock-misuse-err"; then
    echo 'validate-native-shim: os_unfair_lock misuse did not abort' >&2
    exit 1
  fi
  grep -q 'os_unfair_lock_unlock' "$tmp/os-unfair-lock-misuse-err"
  if grep -q 'OS_UNFAIR_LOCK_MISUSE_SURVIVED' "$tmp/os-unfair-lock-misuse-out"; then
    echo 'validate-native-shim: os_unfair_lock misuse survived a foreign unlock' >&2
    exit 1
  fi

  # clock_gettime_nsec_np reads the virtual clock and agrees with clock_gettime
  # (the probe asserts equality internally), and is identical across two same-seed
  # runs.
  "$runner" build "$tmp/clock_nsec_probe.rs" --output "$tmp/clock-nsec-probe" >/dev/null
  "$runner" audit "$tmp/clock-nsec-probe" "${shim_allow[@]}" >/dev/null
  "$runner" run "$tmp/clock-nsec-probe" --seed 1 >"$tmp/clock-nsec-1"
  "$runner" run "$tmp/clock-nsec-probe" --seed 1 >"$tmp/clock-nsec-2"
  cmp "$tmp/clock-nsec-1" "$tmp/clock-nsec-2"
  grep -Eq '^CLOCK_NSEC_RESULT mono_ns=[0-9]+ real_ns=[0-9]+$' "$tmp/clock-nsec-1"
fi

"$runner" build "$tmp/sleep_order_probe.rs" --output "$tmp/sleep-order-probe" >/dev/null
"$runner" audit "$tmp/sleep-order-probe" "${shim_allow[@]}" >/dev/null
for seed in 5 6; do
  "$runner" run "$tmp/sleep-order-probe" --seed "$seed" >"$tmp/sleep-order-seed-$seed-1"
  "$runner" run "$tmp/sleep-order-probe" --seed "$seed" >"$tmp/sleep-order-seed-$seed-2"
  cmp "$tmp/sleep-order-seed-$seed-1" "$tmp/sleep-order-seed-$seed-2"
  grep -Eq '^NATIVE_SLEEP_ORDER_RESULT order=(AB|BA) a_elapsed_ns=100000000 work=4950$' \
    "$tmp/sleep-order-seed-$seed-1"
done

"$runner" build "$tmp/udp_latency_probe.rs" --output "$tmp/udp-latency-probe" >/dev/null
"$runner" audit "$tmp/udp-latency-probe" "${shim_allow[@]}" >/dev/null
udp_latency_nanos=250000000
"$runner" run "$tmp/udp-latency-probe" --seed 5 \
  --net-latency-nanos "$udp_latency_nanos" >"$tmp/udp-latency-seed-5-1"
"$runner" run "$tmp/udp-latency-probe" --seed 5 \
  --net-latency-nanos "$udp_latency_nanos" >"$tmp/udp-latency-seed-5-2"
cmp "$tmp/udp-latency-seed-5-1" "$tmp/udp-latency-seed-5-2"
grep -qx 'NATIVE_UDP_LATENCY_RESULT elapsed_ns=250000000 payload=ping' \
  "$tmp/udp-latency-seed-5-1"
"$runner" run "$tmp/udp-latency-probe" --seed 5 \
  --net-latency-nanos "$udp_latency_nanos" --record "$tmp/udp-latency.patina" \
  --fingerprint native-udp-latency-v1 >"$tmp/udp-latency-record"
"$runner" run "$tmp/udp-latency-probe" --seed 5 \
  --net-latency-nanos "$udp_latency_nanos" --record "$tmp/udp-latency-repeat.patina" \
  --fingerprint native-udp-latency-v1 >/dev/null
cmp "$tmp/udp-latency.patina" "$tmp/udp-latency-repeat.patina"
# Flag-free replay: the base net latency is recorded in the trace metadata, so it
# is restored from the trace rather than re-supplied (replay rejects the knob).
"$runner" replay "$tmp/udp-latency-probe" "$tmp/udp-latency.patina" \
  --fingerprint native-udp-latency-v1 >"$tmp/udp-latency-replay"
cmp "$tmp/udp-latency-record" "$tmp/udp-latency-replay"
cmp "$tmp/udp-latency-seed-5-1" "$tmp/udp-latency-replay"
"$runner" run "$tmp/udp-latency-probe" --seed 5 \
  --net-latency-nanos 0 >"$tmp/udp-latency-zero-1"
"$runner" run "$tmp/udp-latency-probe" --seed 5 \
  --net-latency-nanos 0 >"$tmp/udp-latency-zero-2"
cmp "$tmp/udp-latency-zero-1" "$tmp/udp-latency-zero-2"
udp_zero_elapsed=$(sed -n 's/^NATIVE_UDP_LATENCY_RESULT elapsed_ns=\([0-9][0-9]*\) payload=ping$/\1/p' \
  "$tmp/udp-latency-zero-1")
if [[ -z "$udp_zero_elapsed" ]]; then
  echo 'validate-native-shim: zero-latency udp probe did not print a parseable RESULT line' >&2
  exit 1
fi
if [[ "$udp_zero_elapsed" == "$udp_latency_nanos" ]]; then
  echo "validate-native-shim: zero-latency udp elapsed matched non-zero latency: $udp_zero_elapsed" >&2
  exit 1
fi

"$runner" build "$tmp/tcp_probe.rs" --output "$tmp/tcp-probe" >/dev/null
"$runner" audit "$tmp/tcp-probe" "${shim_allow[@]}" >/dev/null
for seed in 5 6; do
  "$runner" run "$tmp/tcp-probe" --seed "$seed" >"$tmp/tcp-seed-$seed-1"
  "$runner" run "$tmp/tcp-probe" --seed "$seed" >"$tmp/tcp-seed-$seed-2"
  cmp "$tmp/tcp-seed-$seed-1" "$tmp/tcp-seed-$seed-2"
  grep -qx 'NATIVE_TCP_RESULT reply=PING peer=127.0.0.1:49152 ipv6_closed=true dns_closed=true' \
    "$tmp/tcp-seed-$seed-1"
done
"$runner" run "$tmp/tcp-probe" --seed 5 --record "$tmp/tcp.patina" \
  --fingerprint native-tcp-v1 >"$tmp/tcp-record"
"$runner" run "$tmp/tcp-probe" --seed 5 --record "$tmp/tcp-repeat.patina" \
  --fingerprint native-tcp-v1 >/dev/null
cmp "$tmp/tcp.patina" "$tmp/tcp-repeat.patina"
"$runner" replay "$tmp/tcp-probe" "$tmp/tcp.patina" \
  --fingerprint native-tcp-v1 >"$tmp/tcp-replay"
cmp "$tmp/tcp-record" "$tmp/tcp-replay"
cmp "$tmp/tcp-seed-5-1" "$tmp/tcp-replay"

# -----------------------------------------------------------------------------
# Class g, in-process slice: pipe / pipe2 / socketpair modeled as deterministic
# in-memory byte channels wired to the scheduler baton (ESCAPE-CLASSES.md row g).
# Both endpoints live inside the one guest (an async runtime's IO-driver / signal
# self-pipe), so no cross-address-space escape is involved: the channels reuse
# the SAME waiter machinery the virtual sockets do, so the sources import
# pipe/socketpair with NO new allowance and are byte-identical per seed, and
# record + flag-free replay converge. The cross-process siblings stay refused
# (the shm_open leg at the end).
cat >"$tmp/pipe_probe.rs" <<'RS'
// Two managed tasks exchange bytes through an in-process pipe(). The reader
// (main) blocks on the empty pipe and is woken through the baton when the writer
// thread writes; partial writes (4-byte buffer vs 9-byte message) and EOF on the
// writer's close are exercised. The result is a pure function of the transfer,
// so it is byte-identical across same-seed runs.
use std::thread;
unsafe extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn close(fd: i32) -> i32;
}
fn main() {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0, "pipe() failed");
    let (r, w) = (fds[0], fds[1]);
    let writer = thread::spawn(move || {
        let msg = b"ping-pong";
        let mut off = 0usize;
        while off < msg.len() {
            let n = unsafe { write(w, msg[off..].as_ptr(), msg.len() - off) };
            assert!(n > 0, "write returned {n}");
            off += n as usize;
        }
        unsafe { close(w) };
    });
    let mut got = Vec::new();
    let mut buf = [0u8; 4];
    loop {
        let n = unsafe { read(r, buf.as_mut_ptr(), buf.len()) };
        assert!(n >= 0, "read returned {n}");
        if n == 0 { break; } // EOF: the writer closed its end.
        got.extend_from_slice(&buf[..n as usize]);
    }
    writer.join().unwrap();
    unsafe { close(r) };
    println!("NATIVE_PIPE_RESULT got={}", String::from_utf8_lossy(&got));
}
RS
cat >"$tmp/socketpair_probe.rs" <<'RS'
// A duplex AF_UNIX/SOCK_STREAM socketpair: a server task reads a request on one
// endpoint and writes the uppercased reply back through the SAME endpoint; main
// writes the request and reads the reply on the other. Both directions flow
// through the deterministic scheduler.
use std::thread;
const AF_UNIX: i32 = 1;
const SOCK_STREAM: i32 = 1;
unsafe extern "C" {
    fn socketpair(domain: i32, ty: i32, protocol: i32, sv: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn close(fd: i32) -> i32;
}
fn write_all(fd: i32, bytes: &[u8]) {
    let mut off = 0usize;
    while off < bytes.len() {
        let n = unsafe { write(fd, bytes[off..].as_ptr(), bytes.len() - off) };
        assert!(n > 0, "write returned {n}");
        off += n as usize;
    }
}
fn main() {
    let mut sv = [0i32; 2];
    assert_eq!(unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) }, 0);
    let (a, b) = (sv[0], sv[1]);
    let server = thread::spawn(move || {
        let mut buf = [0u8; 16];
        let n = unsafe { read(b, buf.as_mut_ptr(), buf.len()) };
        assert!(n > 0);
        let reply: Vec<u8> =
            buf[..n as usize].iter().map(|c| c.to_ascii_uppercase()).collect();
        write_all(b, &reply);
        unsafe { close(b) };
    });
    write_all(a, b"ping");
    let mut reply = Vec::new();
    let mut buf = [0u8; 16];
    loop {
        let n = unsafe { read(a, buf.as_mut_ptr(), buf.len()) };
        assert!(n >= 0);
        if n == 0 { break; }
        reply.extend_from_slice(&buf[..n as usize]);
    }
    server.join().unwrap();
    unsafe { close(a) };
    println!("NATIVE_SOCKETPAIR_RESULT reply={}", String::from_utf8_lossy(&reply));
}
RS
cat >"$tmp/pipe_epipe_probe.rs" <<'RS'
// EOF + EPIPE semantics. Writing to a pipe whose read end is closed returns
// EPIPE (errno 32) and, crucially, raises NO SIGPIPE — reaching the println at
// all proves the process was not killed by a signal. EOF: a pipe whose write end
// is closed reads 0.
const EPIPE: i32 = 32;
unsafe extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn close(fd: i32) -> i32;
}
fn errno() -> i32 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) }
fn main() {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
    let (r, w) = (fds[0], fds[1]);
    unsafe { close(r) };
    let n = unsafe { write(w, b"x".as_ptr(), 1) };
    let epipe = n == -1 && errno() == EPIPE;
    unsafe { close(w) };
    let mut fds2 = [0i32; 2];
    assert_eq!(unsafe { pipe(fds2.as_mut_ptr()) }, 0);
    let (r2, w2) = (fds2[0], fds2[1]);
    unsafe { close(w2) };
    let mut buf = [0u8; 4];
    let eof = unsafe { read(r2, buf.as_mut_ptr(), buf.len()) } == 0;
    unsafe { close(r2) };
    println!("NATIVE_PIPE_EPIPE_RESULT epipe={epipe} eof={eof}");
}
RS
cat >"$tmp/pipe_nonblock_probe.rs" <<'RS'
// O_NONBLOCK honored on an in-process pipe: an empty non-blocking read returns
// EWOULDBLOCK instead of parking. The fcntl(F_SETFL) path (set later) is
// portable; the pipe2(O_NONBLOCK) creation path is Linux-only. `ok` ANDs every
// applicable sub-check so the output line is stable across platforms.
#[cfg(target_os = "macos")] const O_NONBLOCK: i32 = 0x0004;
#[cfg(target_os = "linux")] const O_NONBLOCK: i32 = 0o4000;
#[cfg(target_os = "macos")] const EWOULDBLOCK: i32 = 35;
#[cfg(target_os = "linux")] const EWOULDBLOCK: i32 = 11;
const F_SETFL: i32 = 4;
unsafe extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn close(fd: i32) -> i32;
}
#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn pipe2(fds: *mut i32, flags: i32) -> i32;
}
fn errno() -> i32 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) }
fn main() {
    let mut buf = [0u8; 4];
    let mut ok = true;
    // fcntl(F_SETFL, O_NONBLOCK) on a plain pipe — the "set later" path, portable.
    let mut b = [0i32; 2];
    assert_eq!(unsafe { pipe(b.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { fcntl(b[0], F_SETFL, O_NONBLOCK) }, 0);
    ok &= unsafe { read(b[0], buf.as_mut_ptr(), buf.len()) } == -1 && errno() == EWOULDBLOCK;
    unsafe { write(b[1], b"hi".as_ptr(), 2) };
    ok &= unsafe { read(b[0], buf.as_mut_ptr(), buf.len()) } == 2;
    unsafe { close(b[0]) };
    unsafe { close(b[1]) };
    // Creation-time O_NONBLOCK via pipe2 (Linux exports it).
    #[cfg(target_os = "linux")]
    {
        let mut a = [0i32; 2];
        assert_eq!(unsafe { pipe2(a.as_mut_ptr(), O_NONBLOCK) }, 0);
        ok &= unsafe { read(a[0], buf.as_mut_ptr(), buf.len()) } == -1 && errno() == EWOULDBLOCK;
        unsafe { close(a[0]) };
        unsafe { close(a[1]) };
    }
    println!("NATIVE_PIPE_NONBLOCK_RESULT ok={ok}");
}
RS
cat >"$tmp/pipe_dup_probe.rs" <<'RS'
// dup aliases a pipe endpoint into the same channel side: bytes written through
// either fd reach the one reader, EOF appears only after the LAST write-side fd
// closes, and EPIPE only after the LAST read-side fd closes. Both entry points
// are exercised: raw dup(2) and fcntl(F_DUPFD_CLOEXEC) (std's try_clone path).
#[cfg(target_os = "macos")] const O_NONBLOCK: i32 = 0x0004;
#[cfg(target_os = "linux")] const O_NONBLOCK: i32 = 0o4000;
#[cfg(target_os = "macos")] const EWOULDBLOCK: i32 = 35;
#[cfg(target_os = "linux")] const EWOULDBLOCK: i32 = 11;
#[cfg(target_os = "macos")] const F_DUPFD_CLOEXEC: i32 = 67;
#[cfg(target_os = "linux")] const F_DUPFD_CLOEXEC: i32 = 1030;
const EPIPE: i32 = 32;
const F_SETFL: i32 = 4;
unsafe extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn dup(fd: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn close(fd: i32) -> i32;
}
fn errno() -> i32 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) }
fn main() {
    let mut ok = true;
    let mut buf = [0u8; 4];
    // Write-side alias: close the ORIGINAL writer first — the drained reader
    // must see would-block (side still open), not EOF, until the dup closes too.
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
    let (r, w) = (fds[0], fds[1]);
    assert_eq!(unsafe { fcntl(r, F_SETFL, O_NONBLOCK) }, 0);
    let w_dup = unsafe { dup(w) };
    ok &= w_dup >= 0;
    ok &= unsafe { write(w, b"a".as_ptr(), 1) } == 1;
    unsafe { close(w) };
    ok &= unsafe { read(r, buf.as_mut_ptr(), buf.len()) } == 1 && buf[0] == b'a';
    ok &= unsafe { read(r, buf.as_mut_ptr(), buf.len()) } == -1 && errno() == EWOULDBLOCK;
    ok &= unsafe { write(w_dup, b"b".as_ptr(), 1) } == 1;
    ok &= unsafe { read(r, buf.as_mut_ptr(), buf.len()) } == 1 && buf[0] == b'b';
    unsafe { close(w_dup) };
    let eof = unsafe { read(r, buf.as_mut_ptr(), buf.len()) } == 0;
    unsafe { close(r) };
    // Read-side alias: writes succeed while EITHER read fd lives; EPIPE only
    // after the last one closes.
    let mut fds2 = [0i32; 2];
    assert_eq!(unsafe { pipe(fds2.as_mut_ptr()) }, 0);
    let (r2, w2) = (fds2[0], fds2[1]);
    let r2_dup = unsafe { fcntl(r2, F_DUPFD_CLOEXEC, 0) };
    ok &= r2_dup >= 0;
    unsafe { close(r2) };
    ok &= unsafe { write(w2, b"x".as_ptr(), 1) } == 1;
    unsafe { close(r2_dup) };
    let epipe = unsafe { write(w2, b"y".as_ptr(), 1) } == -1 && errno() == EPIPE;
    unsafe { close(w2) };
    println!("NATIVE_PIPE_DUP_RESULT ok={ok} eof={eof} epipe={epipe}");
}
RS

# (a) pipe round-trip: byte-identical across two same-seed runs, at two seeds.
# The imports resolve to shim defs, so the source audits clean (no allowance).
"$runner" build "$tmp/pipe_probe.rs" --output "$tmp/pipe-probe" >/dev/null
"$runner" audit "$tmp/pipe-probe" "${shim_allow[@]}" >/dev/null
for seed in 1 2; do
  "$runner" run "$tmp/pipe-probe" --seed "$seed" >"$tmp/pipe-seed-$seed-1"
  "$runner" run "$tmp/pipe-probe" --seed "$seed" >"$tmp/pipe-seed-$seed-2"
  cmp "$tmp/pipe-seed-$seed-1" "$tmp/pipe-seed-$seed-2"
  grep -qx 'NATIVE_PIPE_RESULT got=ping-pong' "$tmp/pipe-seed-$seed-1"
done
"$runner" run "$tmp/pipe-probe" --seed 1 --record "$tmp/pipe.patina" \
  --fingerprint native-pipe-v1 >"$tmp/pipe-record"
"$runner" run "$tmp/pipe-probe" --seed 1 --record "$tmp/pipe-repeat.patina" \
  --fingerprint native-pipe-v1 >/dev/null
cmp "$tmp/pipe.patina" "$tmp/pipe-repeat.patina"
"$runner" replay "$tmp/pipe-probe" "$tmp/pipe.patina" \
  --fingerprint native-pipe-v1 >"$tmp/pipe-replay"
cmp "$tmp/pipe-record" "$tmp/pipe-replay"
cmp "$tmp/pipe-seed-1-1" "$tmp/pipe-replay"

# (b) socketpair duplex round-trip.
"$runner" build "$tmp/socketpair_probe.rs" --output "$tmp/socketpair-probe" >/dev/null
"$runner" audit "$tmp/socketpair-probe" "${shim_allow[@]}" >/dev/null
for seed in 1 2; do
  "$runner" run "$tmp/socketpair-probe" --seed "$seed" >"$tmp/socketpair-seed-$seed-1"
  "$runner" run "$tmp/socketpair-probe" --seed "$seed" >"$tmp/socketpair-seed-$seed-2"
  cmp "$tmp/socketpair-seed-$seed-1" "$tmp/socketpair-seed-$seed-2"
  grep -qx 'NATIVE_SOCKETPAIR_RESULT reply=PING' "$tmp/socketpair-seed-$seed-1"
done
"$runner" run "$tmp/socketpair-probe" --seed 1 --record "$tmp/socketpair.patina" \
  --fingerprint native-socketpair-v1 >"$tmp/socketpair-record"
"$runner" replay "$tmp/socketpair-probe" "$tmp/socketpair.patina" \
  --fingerprint native-socketpair-v1 >"$tmp/socketpair-replay"
cmp "$tmp/socketpair-record" "$tmp/socketpair-replay"
cmp "$tmp/socketpair-seed-1-1" "$tmp/socketpair-replay"

# (c) EOF + EPIPE (no SIGPIPE): reaching the result line proves no signal fired.
"$runner" build "$tmp/pipe_epipe_probe.rs" --output "$tmp/pipe-epipe-probe" >/dev/null
"$runner" audit "$tmp/pipe-epipe-probe" "${shim_allow[@]}" >/dev/null
"$runner" run "$tmp/pipe-epipe-probe" --seed 1 >"$tmp/pipe-epipe-out"
grep -qx 'NATIVE_PIPE_EPIPE_RESULT epipe=true eof=true' "$tmp/pipe-epipe-out"

# (d) O_NONBLOCK → EWOULDBLOCK, set at creation (pipe2, Linux) and via fcntl.
"$runner" build "$tmp/pipe_nonblock_probe.rs" --output "$tmp/pipe-nonblock-probe" >/dev/null
"$runner" audit "$tmp/pipe-nonblock-probe" "${shim_allow[@]}" >/dev/null
"$runner" run "$tmp/pipe-nonblock-probe" --seed 1 >"$tmp/pipe-nonblock-out"
grep -qx 'NATIVE_PIPE_NONBLOCK_RESULT ok=true' "$tmp/pipe-nonblock-out"

# (e) dup/F_DUPFD_CLOEXEC alias a pipe endpoint refcounted: EOF only after the
# LAST write-side fd closes, EPIPE only after the LAST read-side fd closes.
"$runner" build "$tmp/pipe_dup_probe.rs" --output "$tmp/pipe-dup-probe" >/dev/null
"$runner" audit "$tmp/pipe-dup-probe" "${shim_allow[@]}" >/dev/null
"$runner" run "$tmp/pipe-dup-probe" --seed 1 >"$tmp/pipe-dup-1"
"$runner" run "$tmp/pipe-dup-probe" --seed 1 >"$tmp/pipe-dup-2"
cmp "$tmp/pipe-dup-1" "$tmp/pipe-dup-2"
grep -qx 'NATIVE_PIPE_DUP_RESULT ok=true eof=true epipe=true' "$tmp/pipe-dup-1"

# (f) The cross-process class-g siblings stay REFUSED: interposing the
# in-process pipe/socketpair/eventfd must not weaken the gate for a real IPC
# escape. eventfd used to stand in here on Linux, but it is now interposed (the
# real interposer supersedes the deny — the pipe row-g precedent), so shm_open —
# genuinely cross-address-space on BOTH platforms — carries the leg's detection
# power. The audit must refuse it as `shared-memory-ipc`.
cat >"$tmp/shared_ipc_refusal_probe.c" <<'C'
#include <fcntl.h>
#include <sys/mman.h>
int main(void) { return shm_open("/patina-refused", O_RDONLY, 0) < 0; }
C
"$cc" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
  "$tmp/shared_ipc_refusal_probe.c" -o "$tmp/shared-ipc-refusal-probe"
if "$runner" audit "$tmp/shared-ipc-refusal-probe" --raw \
  >"$tmp/shared-ipc-refusal-out" 2>"$tmp/shared-ipc-refusal-error"; then
  echo 'validate-native-shim: cross-process shared-memory-ipc symbol unexpectedly passed audit' >&2
  exit 1
fi
grep -q 'shared-memory-ipc' "$tmp/shared-ipc-refusal-error"

# -----------------------------------------------------------------------------
# kqueue / kevent readiness reactor (macOS): a deterministic in-process model
# of the BSD readiness multiplexer that mio (and therefore tokio) builds its IO
# driver on. kqueue/kevent have no Linux counterpart, so the raw-libc legs are
# gated on Darwin (the Linux mirror is the epoll block below; the shared tokio
# acceptance leg runs un-gated after both). The reactor carries NO trace events
# of its own (the registry is deterministic given the recorded schedule, like
# the pipe channels and mutex words); only the scheduler parks/wakes are
# recorded, so record and flag-free replay converge.
# -----------------------------------------------------------------------------
if [[ "$(uname -s)" == Darwin ]]; then
  # (a) Raw-libc kqueue: EVFILT_READ interest over a socketpair endpoint. A
  # register call returns its EV_ERROR receipt (data 0 = success); a blocking
  # kevent then parks until a writer task writes, and reports the correct event
  # fields (ident/filter/udata). Two same-seed runs are byte-identical.
  cat >"$tmp/kqueue_probe.rs" <<'RS'
// A reader (main) registers EVFILT_READ on a socketpair endpoint and blocks in
// kevent; a writer task writes, waking the fan-in park through the baton.
use std::ffi::{c_int, c_void};

#[repr(C)]
#[derive(Clone, Copy)]
struct KEvent { ident: usize, filter: i16, flags: u16, fflags: u32, data: isize, udata: *mut c_void }

const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const EVFILT_READ: i16 = -1;
const EV_ADD: u16 = 0x0001;
const EV_CLEAR: u16 = 0x0020;
const EV_RECEIPT: u16 = 0x0040;
const EV_ERROR: u16 = 0x4000;

unsafe extern "C" {
    fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    fn kqueue() -> c_int;
    fn kevent(kq: c_int, cl: *const KEvent, nc: c_int, el: *mut KEvent, ne: c_int, ts: *const c_void) -> c_int;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
}
fn zero() -> KEvent { KEvent { ident: 0, filter: 0, flags: 0, fflags: 0, data: 0, udata: std::ptr::null_mut() } }

fn main() {
    let mut sv = [0 as c_int; 2];
    assert_eq!(unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) }, 0, "socketpair");
    let (a, b) = (sv[0], sv[1]);
    let kq = unsafe { kqueue() };
    assert!(kq >= 0, "kqueue");

    let change = KEvent { ident: a as usize, filter: EVFILT_READ, flags: EV_ADD | EV_CLEAR | EV_RECEIPT, fflags: 0, data: 0, udata: 0x1234 as *mut c_void };
    let mut receipt = [zero()];
    assert_eq!(unsafe { kevent(kq, &change, 1, receipt.as_mut_ptr(), 1, std::ptr::null()) }, 1, "register receipt");
    assert!(receipt[0].flags & EV_ERROR != 0 && receipt[0].data == 0, "receipt ok");

    let writer = std::thread::spawn(move || {
        let msg = b"ping";
        assert_eq!(unsafe { write(b, msg.as_ptr() as *const c_void, msg.len()) }, 4);
    });

    let mut events = [zero()];
    let n = unsafe { kevent(kq, std::ptr::null(), 0, events.as_mut_ptr(), 1, std::ptr::null()) };
    assert_eq!(n, 1, "one ready event");
    assert_eq!(events[0].ident, a as usize, "event ident");
    assert_eq!(events[0].filter, EVFILT_READ, "event filter");
    assert_eq!(events[0].udata, 0x1234 as *mut c_void, "event udata");

    let mut buf = [0u8; 8];
    let got = unsafe { read(a, buf.as_mut_ptr() as *mut c_void, buf.len()) };
    assert_eq!(got, 4);
    writer.join().unwrap();
    println!("NATIVE_KQUEUE_RESULT got={}", std::str::from_utf8(&buf[..got as usize]).unwrap());
}
RS
  "$runner" build "$tmp/kqueue_probe.rs" --output "$tmp/kqueue-probe" >/dev/null
  "$runner" audit "$tmp/kqueue-probe" "${shim_allow[@]}" >/dev/null
  for seed in 1 2; do
    "$runner" run "$tmp/kqueue-probe" --seed "$seed" >"$tmp/kqueue-seed-$seed-1"
    "$runner" run "$tmp/kqueue-probe" --seed "$seed" >"$tmp/kqueue-seed-$seed-2"
    cmp "$tmp/kqueue-seed-$seed-1" "$tmp/kqueue-seed-$seed-2"
    grep -qx 'NATIVE_KQUEUE_RESULT got=ping' "$tmp/kqueue-seed-$seed-1"
  done
  # Same seed is byte-identical across a record and its flag-free replay.
  "$runner" run "$tmp/kqueue-probe" --seed 1 --record "$tmp/kqueue.patina" \
    --fingerprint native-kqueue-v1 >"$tmp/kqueue-record"
  "$runner" replay "$tmp/kqueue-probe" "$tmp/kqueue.patina" \
    --fingerprint native-kqueue-v1 >"$tmp/kqueue-replay"
  cmp "$tmp/kqueue-record" "$tmp/kqueue-replay"
  cmp "$tmp/kqueue-seed-1-1" "$tmp/kqueue-replay"

  # (b) EVFILT_USER self-wakeup (mio's Waker): another task triggers NOTE_TRIGGER,
  # unparking main's blocked kevent. (c) EVFILT-free timeout: a kevent with a
  # timespec and nothing ready returns 0 after EXACTLY the virtual-clock duration
  # (asserted via Instant, which reads the virtual clock).
  cat >"$tmp/kqueue_user_probe.rs" <<'RS'
use std::ffi::{c_int, c_void};
use std::time::Instant;

#[repr(C)]
#[derive(Clone, Copy)]
struct KEvent { ident: usize, filter: i16, flags: u16, fflags: u32, data: isize, udata: *mut c_void }
#[repr(C)]
struct TimeSpec { tv_sec: isize, tv_nsec: isize }

const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const EVFILT_READ: i16 = -1;
const EVFILT_USER: i16 = -10;
const EV_ADD: u16 = 0x0001;
const EV_CLEAR: u16 = 0x0020;
const EV_RECEIPT: u16 = 0x0040;
const NOTE_TRIGGER: u32 = 0x0100_0000;

unsafe extern "C" {
    fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    fn kqueue() -> c_int;
    fn kevent(kq: c_int, cl: *const KEvent, nc: c_int, el: *mut KEvent, ne: c_int, ts: *const TimeSpec) -> c_int;
}
fn zero() -> KEvent { KEvent { ident: 0, filter: 0, flags: 0, fflags: 0, data: 0, udata: std::ptr::null_mut() } }

fn main() {
    // EVFILT_USER: a writer task triggers, main's blocked kevent returns it.
    let kq = unsafe { kqueue() };
    let reg = KEvent { ident: 42, filter: EVFILT_USER, flags: EV_ADD | EV_CLEAR | EV_RECEIPT, fflags: 0, data: 0, udata: 0 as *mut c_void };
    let mut r = [zero()];
    assert_eq!(unsafe { kevent(kq, &reg, 1, r.as_mut_ptr(), 1, std::ptr::null()) }, 1);
    let t = std::thread::spawn(move || {
        let trig = KEvent { ident: 42, filter: EVFILT_USER, flags: EV_ADD | EV_RECEIPT, fflags: NOTE_TRIGGER, data: 0, udata: 0 as *mut c_void };
        let mut rr = [zero()];
        assert_eq!(unsafe { kevent(kq, &trig, 1, rr.as_mut_ptr(), 1, std::ptr::null()) }, 1);
    });
    let mut ev = [zero()];
    let user_n = unsafe { kevent(kq, std::ptr::null(), 0, ev.as_mut_ptr(), 1, std::ptr::null()) };
    assert_eq!(user_n, 1, "user event");
    assert_eq!(ev[0].filter, EVFILT_USER);
    assert_eq!(ev[0].ident, 42);
    t.join().unwrap();

    // Timeout: nothing ready, kevent returns 0 after exactly 50ms virtual time.
    let mut sv = [0 as c_int; 2];
    assert_eq!(unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) }, 0);
    let kq2 = unsafe { kqueue() };
    let reg2 = KEvent { ident: sv[0] as usize, filter: EVFILT_READ, flags: EV_ADD | EV_CLEAR | EV_RECEIPT, fflags: 0, data: 0, udata: 0 as *mut c_void };
    let mut r2 = [zero()];
    assert_eq!(unsafe { kevent(kq2, &reg2, 1, r2.as_mut_ptr(), 1, std::ptr::null()) }, 1);
    let ts = TimeSpec { tv_sec: 0, tv_nsec: 50_000_000 };
    let before = Instant::now();
    let mut ev2 = [zero()];
    let n2 = unsafe { kevent(kq2, std::ptr::null(), 0, ev2.as_mut_ptr(), 1, &ts) };
    let elapsed_ms = before.elapsed().as_millis();
    assert_eq!(n2, 0, "timeout returns zero events");
    assert_eq!(elapsed_ms, 50, "timeout elapsed exactly the virtual duration");
    println!("NATIVE_KQUEUE_USER_TIMEOUT user_ok={} timeout_ms={}", user_n == 1, elapsed_ms);
}
RS
  "$runner" build "$tmp/kqueue_user_probe.rs" --output "$tmp/kqueue-user-probe" >/dev/null
  "$runner" audit "$tmp/kqueue-user-probe" "${shim_allow[@]}" >/dev/null
  "$runner" run "$tmp/kqueue-user-probe" --seed 1 >"$tmp/kqueue-user-1"
  "$runner" run "$tmp/kqueue-user-probe" --seed 1 >"$tmp/kqueue-user-2"
  cmp "$tmp/kqueue-user-1" "$tmp/kqueue-user-2"
  grep -qx 'NATIVE_KQUEUE_USER_TIMEOUT user_ok=true timeout_ms=50' "$tmp/kqueue-user-1"

  cat "$tmp/kqueue-seed-1-1"
  cat "$tmp/kqueue-user-1"
fi

# -----------------------------------------------------------------------------
# epoll / eventfd readiness reactor (Linux). The Linux mirror of the Darwin
# kqueue block above: the same shared readiness core behind an epoll frontend
# (one interest per fd, EPOLLET arrival-sequence edge latch, millisecond
# timeouts on the virtual clock) plus the deterministic eventfd counter (mio's
# Waker vehicle). Like the kqueue registry, it carries NO trace events of its
# own, so record and flag-free replay converge.
# -----------------------------------------------------------------------------
if [[ "$(uname -s)" == Linux ]]; then
  # (a) Raw-libc epoll, EPOLLIN|EPOLLET over a socketpair endpoint. A blocking
  # epoll_wait parks until a writer task writes and reports the registered
  # epoll_data. THE EDGE ASSERTION: after a PARTIAL drain the fd is still
  # readable but the edge is latched, so a poll (timeout 0) must report
  # NOTHING; new data must re-fire (the kernel's per-arrival edge). Two
  # same-seed runs are byte-identical; record + flag-free replay converge.
  cat >"$tmp/epoll_probe.rs" <<'RS'
// A reader (main) registers EPOLLIN|EPOLLET on a socketpair endpoint and blocks
// in epoll_wait; a writer task writes, waking the fan-in park through the
// baton. Then the edge-latch discipline is asserted with the writes issued from
// main itself, so the sequence is schedule-independent.
use std::ffi::{c_int, c_void};

#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Clone, Copy)]
struct EpollEvent { events: u32, data: u64 }

const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const EPOLL_CTL_ADD: c_int = 1;
const EPOLLIN: u32 = 0x001;
const EPOLLET: u32 = 1 << 31;

unsafe extern "C" {
    fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    fn epoll_create1(flags: c_int) -> c_int;
    fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: *mut EpollEvent) -> c_int;
    fn epoll_wait(epfd: c_int, evs: *mut EpollEvent, max: c_int, timeout: c_int) -> c_int;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
}
fn zero() -> EpollEvent { EpollEvent { events: 0, data: 0 } }

fn main() {
    let mut sv = [0 as c_int; 2];
    assert_eq!(unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) }, 0, "socketpair");
    let (a, b) = (sv[0], sv[1]);
    let ep = unsafe { epoll_create1(0) };
    assert!(ep >= 0, "epoll_create1");
    let mut reg = EpollEvent { events: EPOLLIN | EPOLLET, data: 0x1234 };
    assert_eq!(unsafe { epoll_ctl(ep, EPOLL_CTL_ADD, a, &mut reg) }, 0, "epoll_ctl add");

    let writer = std::thread::spawn(move || {
        let msg = b"ping";
        assert_eq!(unsafe { write(b, msg.as_ptr() as *const c_void, msg.len()) }, 4);
    });
    let mut evs = [zero()];
    let n = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, -1) };
    assert_eq!(n, 1, "one ready event");
    assert_eq!({ evs[0].data }, 0x1234, "event data");
    assert!({ evs[0].events } & EPOLLIN != 0, "EPOLLIN set");
    writer.join().unwrap();

    // Partial drain: 2 of the 4 bytes. The fd stays readable, but the ET edge
    // is latched — a poll must NOT re-report it.
    let mut buf = [0u8; 2];
    assert_eq!(unsafe { read(a, buf.as_mut_ptr() as *mut c_void, 2) }, 2);
    assert_eq!(&buf, b"pi");
    let latched = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, 0) };
    assert_eq!(latched, 0, "latched edge must not re-report after partial drain");

    // New data re-fires the edge even though readiness never dropped.
    assert_eq!(unsafe { write(b, b"!!".as_ptr() as *const c_void, 2) }, 2);
    let refired = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, 0) };
    assert_eq!(refired, 1, "new arrival must re-fire the edge");
    let mut rest = [0u8; 4];
    assert_eq!(unsafe { read(a, rest.as_mut_ptr() as *mut c_void, 4) }, 4);
    assert_eq!(&rest, b"ng!!");
    println!("NATIVE_EPOLL_RESULT latched={latched} refired={refired}");
}
RS
  "$runner" build "$tmp/epoll_probe.rs" --output "$tmp/epoll-probe" >/dev/null
  "$runner" audit "$tmp/epoll-probe" "${shim_allow[@]}" >/dev/null
  for seed in 1 2; do
    "$runner" run "$tmp/epoll-probe" --seed "$seed" >"$tmp/epoll-seed-$seed-1"
    "$runner" run "$tmp/epoll-probe" --seed "$seed" >"$tmp/epoll-seed-$seed-2"
    cmp "$tmp/epoll-seed-$seed-1" "$tmp/epoll-seed-$seed-2"
    grep -qx 'NATIVE_EPOLL_RESULT latched=0 refired=1' "$tmp/epoll-seed-$seed-1"
  done
  # Same seed is byte-identical across a record and its flag-free replay.
  "$runner" run "$tmp/epoll-probe" --seed 1 --record "$tmp/epoll.patina" \
    --fingerprint native-epoll-v1 >"$tmp/epoll-record"
  "$runner" replay "$tmp/epoll-probe" "$tmp/epoll.patina" \
    --fingerprint native-epoll-v1 >"$tmp/epoll-replay"
  cmp "$tmp/epoll-record" "$tmp/epoll-replay"
  cmp "$tmp/epoll-seed-1-1" "$tmp/epoll-replay"

  # (b) eventfd wakeup (mio's Waker shape): an eventfd registered EPOLLIN|EPOLLET
  # with a blocked epoll_wait is unparked by a second thread's 8-byte write. A
  # SECOND write re-fires the edge without the counter ever being drained (the
  # kernel's per-arrival edge, which mio's Waker depends on); the read then
  # returns-and-resets, and a drained nonblocking read is EAGAIN.
  cat >"$tmp/eventfd_probe.rs" <<'RS'
use std::ffi::{c_int, c_void};

#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Clone, Copy)]
struct EpollEvent { events: u32, data: u64 }

const EPOLL_CTL_ADD: c_int = 1;
const EPOLLIN: u32 = 0x001;
const EPOLLET: u32 = 1 << 31;
const EFD_CLOEXEC: c_int = 0o2000000;
const EFD_NONBLOCK: c_int = 0o4000;
const EFD_SEMAPHORE: c_int = 0o1;
const EAGAIN: i32 = 11;

unsafe extern "C" {
    fn eventfd(initval: u32, flags: c_int) -> c_int;
    fn epoll_create1(flags: c_int) -> c_int;
    fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: *mut EpollEvent) -> c_int;
    fn epoll_wait(epfd: c_int, evs: *mut EpollEvent, max: c_int, timeout: c_int) -> c_int;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
    fn __errno_location() -> *mut i32;
}
fn zero() -> EpollEvent { EpollEvent { events: 0, data: 0 } }
fn wr1(fd: c_int) { let one: u64 = 1; assert_eq!(unsafe { write(fd, &one as *const u64 as *const c_void, 8) }, 8); }

fn main() {
    let efd = unsafe { eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) };
    assert!(efd >= 0, "eventfd");
    let ep = unsafe { epoll_create1(0) };
    let mut reg = EpollEvent { events: EPOLLIN | EPOLLET, data: 7 };
    assert_eq!(unsafe { epoll_ctl(ep, EPOLL_CTL_ADD, efd, &mut reg) }, 0);

    // A second thread's write unparks the blocked epoll_wait.
    let waker = std::thread::spawn(move || wr1(efd));
    let mut evs = [zero()];
    let woke = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, -1) };
    assert_eq!(woke, 1, "eventfd write unparks epoll_wait");
    assert_eq!({ evs[0].data }, 7);
    waker.join().unwrap();

    // Undrained counter: the latch holds until a NEW write arrives.
    assert_eq!(unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, 0) }, 0, "latched");
    wr1(efd);
    let refired = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, 0) };
    assert_eq!(refired, 1, "undrained re-arrival re-fires");

    // Read returns-and-resets; a drained nonblocking read is EAGAIN.
    let mut val: u64 = 0;
    assert_eq!(unsafe { read(efd, (&raw mut val).cast(), 8) }, 8);
    assert_eq!(val, 2, "counter accumulated both writes");
    assert_eq!(unsafe { read(efd, (&raw mut val).cast(), 8) }, -1);
    assert_eq!(unsafe { *__errno_location() }, EAGAIN, "drained read is EAGAIN");

    // EFD_SEMAPHORE decrements by one per read.
    let sem = unsafe { eventfd(2, EFD_SEMAPHORE) };
    assert_eq!(unsafe { read(sem, (&raw mut val).cast(), 8) }, 8);
    assert_eq!(val, 1);
    assert_eq!(unsafe { read(sem, (&raw mut val).cast(), 8) }, 8);
    assert_eq!(val, 1);
    println!("NATIVE_EVENTFD_RESULT woke={woke} refired={refired} sem_ok=true");
}
RS
  "$runner" build "$tmp/eventfd_probe.rs" --output "$tmp/eventfd-probe" >/dev/null
  "$runner" audit "$tmp/eventfd-probe" "${shim_allow[@]}" >/dev/null
  "$runner" run "$tmp/eventfd-probe" --seed 1 >"$tmp/eventfd-1"
  "$runner" run "$tmp/eventfd-probe" --seed 1 >"$tmp/eventfd-2"
  cmp "$tmp/eventfd-1" "$tmp/eventfd-2"
  grep -qx 'NATIVE_EVENTFD_RESULT woke=1 refired=1 sem_ok=true' "$tmp/eventfd-1"

  # (c) Timeout: epoll_wait with a 50ms timeout and nothing ready returns 0
  # after EXACTLY the virtual-clock duration (Instant reads the virtual clock).
  cat >"$tmp/epoll_timeout_probe.rs" <<'RS'
use std::ffi::c_int;
use std::time::Instant;

#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Clone, Copy)]
struct EpollEvent { events: u32, data: u64 }

const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const EPOLL_CTL_ADD: c_int = 1;
const EPOLLIN: u32 = 0x001;
const EPOLLET: u32 = 1 << 31;

unsafe extern "C" {
    fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    fn epoll_create1(flags: c_int) -> c_int;
    fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, ev: *mut EpollEvent) -> c_int;
    fn epoll_wait(epfd: c_int, evs: *mut EpollEvent, max: c_int, timeout: c_int) -> c_int;
}

fn main() {
    let mut sv = [0 as c_int; 2];
    assert_eq!(unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr()) }, 0);
    let ep = unsafe { epoll_create1(0) };
    let mut reg = EpollEvent { events: EPOLLIN | EPOLLET, data: 0 };
    assert_eq!(unsafe { epoll_ctl(ep, EPOLL_CTL_ADD, sv[0], &mut reg) }, 0);
    let before = Instant::now();
    let mut evs = [EpollEvent { events: 0, data: 0 }];
    let n = unsafe { epoll_wait(ep, evs.as_mut_ptr(), 1, 50) };
    let elapsed_ms = before.elapsed().as_millis();
    assert_eq!(n, 0, "timeout returns zero events");
    assert_eq!(elapsed_ms, 50, "timeout elapsed exactly the virtual duration");
    println!("NATIVE_EPOLL_TIMEOUT timeout_ms={elapsed_ms}");
}
RS
  "$runner" build "$tmp/epoll_timeout_probe.rs" --output "$tmp/epoll-timeout-probe" >/dev/null
  "$runner" audit "$tmp/epoll-timeout-probe" "${shim_allow[@]}" >/dev/null
  "$runner" run "$tmp/epoll-timeout-probe" --seed 1 >"$tmp/epoll-timeout-1"
  "$runner" run "$tmp/epoll-timeout-probe" --seed 1 >"$tmp/epoll-timeout-2"
  cmp "$tmp/epoll-timeout-1" "$tmp/epoll-timeout-2"
  grep -qx 'NATIVE_EPOLL_TIMEOUT timeout_ms=50' "$tmp/epoll-timeout-1"

  cat "$tmp/epoll-seed-1-1"
  cat "$tmp/eventfd-1"
  cat "$tmp/epoll-timeout-1"
fi

# -----------------------------------------------------------------------------
# The cross-platform acceptance workload: a real tokio current-thread runtime
# driving an async socketpair ping-pong entirely through the deterministic
# readiness reactor — mio's kqueue selector + EVFILT_USER Waker on macOS, mio's
# epoll selector + eventfd Waker on Linux — and the in-process net shim. The
# `signal` feature matters: with it compiled, `enable_all()` also arms tokio's
# signal driver, which creates a UnixStream::pair and try_clones one end —
# fcntl(F_DUPFD_CLOEXEC) on a virtual socketpair endpoint, the refcounted pipe
# dup path. parking_lot and rustix ride along so their surfaces are exercised
# on EVERY validate run, not only when someone happens to build such a guest:
# parking_lot locks through its interposed platform primitive (os_unfair_lock
# on macOS, futex-via-syscall on Linux), and rustix — flipped onto its libc
# backend by the `--cfg rustix_use_libc` the package build injects (its DEFAULT
# Linux backend emits raw inline syscalls the audit refuses) — reads back a
# file through the interposed openat/openat64 into the deterministic FS. It
# builds via `cargo patina build`, audits with NO allowance beyond the existing
# shim residue, runs seed-stable, and records/replays byte-identically. The
# dependency tree is pinned by the committed Cargo.lock for a reproducible
# build.
# -----------------------------------------------------------------------------
mkdir -p "$tmp/tokio-probe-src/src"
cat >"$tmp/tokio-probe-src/Cargo.toml" <<'TOML'
[package]
name = "patina-tokio-probe"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
tokio = { version = "=1.53.1", features = ["rt", "net", "io-util", "macros", "time", "signal"] }
parking_lot = "=0.12.5"
rustix = { version = "=1.1.4", features = ["fs"] }

[[bin]]
name = "patina-tokio-probe"
path = "src/main.rs"
TOML
cat >"$tmp/tokio-probe-src/Cargo.lock" <<'LOCK'
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "bitflags"
version = "2.13.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da"

[[package]]
name = "bytes"
version = "1.12.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fc652a48c352aef3ea3aed32080501cf3ef6ed5da78602a020c991775b0aff04"

[[package]]
name = "cfg-if"
version = "1.0.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801"

[[package]]
name = "errno"
version = "0.3.14"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "39cab71617ae0d63f51a36d69f866391735b51691dbda63cf6f96d042b63efeb"
dependencies = [
 "libc",
 "windows-sys",
]

[[package]]
name = "libc"
version = "0.2.189"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2"

[[package]]
name = "linux-raw-sys"
version = "0.12.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "32a66949e030da00e8c7d4434b251670a91556f4144941d37452769c25d58a53"

[[package]]
name = "lock_api"
version = "0.4.14"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "224399e74b87b5f3557511d98dff8b14089b3dadafcab6bb93eab67d3aace965"
dependencies = [
 "scopeguard",
]

[[package]]
name = "mio"
version = "1.2.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "30d65c71f1ce40ab09135ce117d742b9f8a19ff91a41a8b57ed50bc2de59c427"
dependencies = [
 "libc",
 "wasi",
 "windows-sys",
]

[[package]]
name = "parking_lot"
version = "0.12.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "93857453250e3077bd71ff98b6a65ea6621a19bb0f559a85248955ac12c45a1a"
dependencies = [
 "lock_api",
 "parking_lot_core",
]

[[package]]
name = "parking_lot_core"
version = "0.9.12"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2621685985a2ebf1c516881c026032ac7deafcda1a2c9b7850dc81e3dfcb64c1"
dependencies = [
 "cfg-if",
 "libc",
 "redox_syscall",
 "smallvec",
 "windows-link",
]

[[package]]
name = "patina-tokio-probe"
version = "0.0.0"
dependencies = [
 "parking_lot",
 "rustix",
 "tokio",
]

[[package]]
name = "pin-project-lite"
version = "0.2.17"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a89322df9ebe1c1578d689c92318e070967d1042b512afbe49518723f4e6d5cd"

[[package]]
name = "proc-macro2"
version = "1.0.107"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9"
dependencies = [
 "unicode-ident",
]

[[package]]
name = "quote"
version = "1.0.47"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001"
dependencies = [
 "proc-macro2",
]

[[package]]
name = "redox_syscall"
version = "0.5.18"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ed2bf2547551a7053d6fdfafda3f938979645c44812fbfcda098faae3f1a362d"
dependencies = [
 "bitflags",
]

[[package]]
name = "rustix"
version = "1.1.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190"
dependencies = [
 "bitflags",
 "errno",
 "libc",
 "linux-raw-sys",
 "windows-sys",
]

[[package]]
name = "scopeguard"
version = "1.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "94143f37725109f92c262ed2cf5e59bce7498c01bcc1502d7b9afe439a4e9f49"

[[package]]
name = "signal-hook-registry"
version = "1.4.8"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c4db69cba1110affc0e9f7bcd48bbf87b3f4fc7c61fc9155afd4c469eb3d6c1b"
dependencies = [
 "errno",
 "libc",
]

[[package]]
name = "smallvec"
version = "1.15.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "8ed6a63f02c8539c91a8685a86f4099661ba3da017932f6ebbea6de3f0fa7c90"

[[package]]
name = "socket2"
version = "0.6.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c3d1e2c7f27f8d4cb10542a02c49005dbd6e93095799d6f3be745fae9f8fedd4"
dependencies = [
 "libc",
 "windows-sys",
]

[[package]]
name = "syn"
version = "3.0.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "53e9bae58849f64dfa4f5d5ae372c8341f7305f82a3868709269343628b659a3"
dependencies = [
 "proc-macro2",
 "quote",
 "unicode-ident",
]

[[package]]
name = "tokio"
version = "1.53.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed"
dependencies = [
 "bytes",
 "libc",
 "mio",
 "pin-project-lite",
 "signal-hook-registry",
 "socket2",
 "tokio-macros",
 "windows-sys",
]

[[package]]
name = "tokio-macros"
version = "2.7.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "78773a2a397f451582ce068015985c33193cf6dea8b74d2a639fe457b2f07b0e"
dependencies = [
 "proc-macro2",
 "quote",
 "syn",
]

[[package]]
name = "unicode-ident"
version = "1.0.24"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e6e4313cd5fcd3dad5cafa179702e2b244f760991f45397d14d4ebf38247da75"

[[package]]
name = "wasi"
version = "0.11.1+wasi-snapshot-preview1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ccf3ec651a847eb01de73ccad15eb7d99f80485de043efb2f370cd654f4ea44b"

[[package]]
name = "windows-link"
version = "0.2.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5"

[[package]]
name = "windows-sys"
version = "0.61.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc"
dependencies = [
 "windows-link",
]
LOCK
cat >"$tmp/tokio-probe-src/src/main.rs" <<'RS'
// A real tokio current-thread runtime driving an async socketpair ping-pong.
// UnixStream::pair lowers to socketpair(2); tokio's IO driver registers the
// endpoints with mio's selector (kqueue on macOS, epoll on Linux) and wakes
// itself through mio's Waker (EVFILT_USER / eventfd) — all serviced by the
// deterministic reactor + net shim. parking_lot rides its interposed platform
// primitive (os_unfair_lock on macOS, futex-via-syscall on Linux), and rustix
// — carried onto its libc backend by the injected --cfg rustix_use_libc —
// reaches the deterministic FS through the interposed openat/openat64.
use std::io::Read;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let out = rt.block_on(async {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            b.read_exact(&mut buf).await.unwrap();
            b.write_all(b"pong").await.unwrap();
            buf
        });
        a.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        a.read_exact(&mut buf).await.unwrap();
        let server_got = server.await.unwrap();
        (buf, server_got)
    });

    let lock = parking_lot::Mutex::new(0u64);
    *lock.lock() += 41;
    let lock_val = *lock.lock() + 1;

    std::fs::write("/tmp/patina-tokio-probe-data", b"rustix-ok").unwrap();
    let fd = rustix::fs::openat(
        rustix::fs::CWD,
        "/tmp/patina-tokio-probe-data",
        rustix::fs::OFlags::RDONLY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let mut contents = String::new();
    std::fs::File::from(fd).read_to_string(&mut contents).unwrap();

    println!(
        "NATIVE_TOKIO_RESULT client_got={} server_got={} lock={} rustix_read={}",
        std::str::from_utf8(&out.0).unwrap(),
        std::str::from_utf8(&out.1).unwrap(),
        lock_val,
        contents
    );
}
RS
# The probe's dep graph (tokio + friends) is identical across runs; a persistent
# target dir under the repo's target/ turns the ~14s cold build into ~3s warm and
# rides the same CI cache as everything else. The source lives in a fresh tempdir
# each run, so a stale cache can never mask a source change (fingerprints differ).
CARGO_TARGET_DIR="$target_dir/tokio-probe-cache" \
  "$runner" build "$tmp/tokio-probe-src" --bin patina-tokio-probe --output "$tmp/tokio-probe" >/dev/null
"$runner" audit "$tmp/tokio-probe" "${shim_allow[@]}" >/dev/null
"$runner" run "$tmp/tokio-probe" --seed 1 >"$tmp/tokio-seed-1"
"$runner" run "$tmp/tokio-probe" --seed 1 >"$tmp/tokio-seed-2"
cmp "$tmp/tokio-seed-1" "$tmp/tokio-seed-2"
grep -qx 'NATIVE_TOKIO_RESULT client_got=pong server_got=ping lock=42 rustix_read=rustix-ok' "$tmp/tokio-seed-1"
"$runner" run "$tmp/tokio-probe" --seed 1 --record "$tmp/tokio.patina" \
  --fingerprint native-tokio-v1 >"$tmp/tokio-record"
"$runner" replay "$tmp/tokio-probe" "$tmp/tokio.patina" \
  --fingerprint native-tokio-v1 >"$tmp/tokio-replay"
cmp "$tmp/tokio-record" "$tmp/tokio-replay"
cmp "$tmp/tokio-seed-1" "$tmp/tokio-replay"
cat "$tmp/tokio-seed-1"

# ===========================================================================
# syscall-user-dispatch (SUD) legs (Linux). SUD traps a guest's raw inline
# `syscall`/`svc` instruction into the deterministic runtime via a SIGSYS
# handler (SUD-DESIGN.md). It requires the kernel's generic-entry code —
# x86_64 since 5.11, arm64 not yet — so the legs branch on a live kernel probe:
# a SUD kernel runs the positive battery, a non-SUD kernel (the arm64 VM) runs
# the refusal leg plus the kernel-independent legs, and prints a loud, counted
# SKIPPED line (never a silent pass). Detection-before-fixes: the refusal, the
# unmapped-syscall abort, the SIGSYS-hijack refusal, and the marker gating are
# each proved to fire.
# ===========================================================================
if [[ "$(uname -s)" == Linux ]]; then
  # Live kernel SUD probe: the same prctl(PR_SYS_DISPATCH_OFF) probe the shim
  # and audit use (0 on a SUD kernel, EINVAL where the feature is absent).
  cat >"$tmp/sud_support.c" <<'C'
#include <sys/prctl.h>
#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
int main(void) {
    return prctl(PR_SET_SYSCALL_USER_DISPATCH, 0, 0, 0, 0) == 0 ? 0 : 1;
}
C
  "$cc" "$tmp/sud_support.c" -o "$tmp/sud_support"
  if "$tmp/sud_support"; then sud_kernel=1; else sud_kernel=0; fi

  # raw_syscall_probe: raw inline syscalls (no libc wrapper, no rustix) for the
  # clock, filesystem, and entropy families, plus a three-thread fanout that
  # each read the raw monotonic clock (per-thread arming). Built through the
  # packaged native target, so it is shim-linked (carries the SUD dispatch
  # marker) and runs under the supervisor (which sets PATINA_MODE, the arming
  # trigger). The inline asm is the exact direct-syscall escape class the
  # instruction scan refuses without SUD.
  cat >"$tmp/raw_syscall_probe.rs" <<'RS'
#[cfg(target_arch = "x86_64")]
mod raw {
    use std::arch::asm;
    pub const CLOCK_GETTIME: i64 = 228;
    pub const OPENAT: i64 = 257;
    pub const WRITE: i64 = 1;
    pub const READ: i64 = 0;
    pub const LSEEK: i64 = 8;
    pub const CLOSE: i64 = 3;
    pub const GETRANDOM: i64 = 318;
    pub unsafe fn syscall6(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
        let ret: i64;
        unsafe {
            asm!("syscall", inlateout("rax") nr => ret, in("rdi") a0, in("rsi") a1,
                 in("rdx") a2, in("r10") a3, in("r8") a4, in("r9") a5,
                 out("rcx") _, out("r11") _, options(nostack));
        }
        ret
    }
}

#[cfg(target_arch = "aarch64")]
mod raw {
    use std::arch::asm;
    pub const CLOCK_GETTIME: i64 = 113;
    pub const OPENAT: i64 = 56;
    pub const WRITE: i64 = 64;
    pub const READ: i64 = 63;
    pub const LSEEK: i64 = 62;
    pub const CLOSE: i64 = 57;
    pub const GETRANDOM: i64 = 278;
    pub unsafe fn syscall6(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
        let ret: i64;
        unsafe {
            asm!("svc #0", in("x8") nr, inlateout("x0") a0 => ret, in("x1") a1,
                 in("x2") a2, in("x3") a3, in("x4") a4, in("x5") a5, options(nostack));
        }
        ret
    }
}

const CLOCK_MONOTONIC: i64 = 1;
const AT_FDCWD: i64 = -100;
const O_CREAT: i64 = 0o100;
const O_RDWR: i64 = 2;
// The virtual clock starts near zero and only advances via sleeps; a wall clock
// would read ~1.7e18 ns. Anything under this bound proves the read was virtual.
const VIRTUAL_BOUND: u64 = 1_000_000_000_000_000;

unsafe fn clock_mono() -> u64 {
    let mut ts = [0i64; 2];
    let rc = unsafe { raw::syscall6(raw::CLOCK_GETTIME, CLOCK_MONOTONIC, ts.as_mut_ptr() as i64, 0, 0, 0, 0) };
    assert_eq!(rc, 0, "raw clock_gettime rc");
    ts[0] as u64 * 1_000_000_000 + ts[1] as u64
}

fn main() {
    // REGRESSION SHAPE — keep the raw clock reads FIRST, before any thread spawn:
    // the main thread gets its managed TaskId lazily (on first thread-subsystem
    // use), so these deliberately trap on the PRE-ACTIVATION main thread. A
    // dispatch-side check stricter than the interposer thread-semantics (the CI
    // failure that removed §4.2 invariant 1's hard abort) turns this leg red.
    let t0 = unsafe { clock_mono() };
    let t1 = unsafe { clock_mono() };
    let path = b"/sud-raw\0";
    let fd = unsafe { raw::syscall6(raw::OPENAT, AT_FDCWD, path.as_ptr() as i64, O_CREAT | O_RDWR, 0o600, 0, 0) };
    assert!(fd >= 0, "raw openat fd={fd}");
    let msg = b"sud";
    let w = unsafe { raw::syscall6(raw::WRITE, fd, msg.as_ptr() as i64, msg.len() as i64, 0, 0, 0) };
    assert_eq!(w, 3, "raw write");
    let _ = unsafe { raw::syscall6(raw::LSEEK, fd, 0, 0, 0, 0, 0) };
    let mut buf = [0u8; 3];
    let r = unsafe { raw::syscall6(raw::READ, fd, buf.as_mut_ptr() as i64, 3, 0, 0, 0) };
    assert_eq!(r, 3, "raw read");
    let _ = unsafe { raw::syscall6(raw::CLOSE, fd, 0, 0, 0, 0, 0) };
    let mut rnd = [0u8; 8];
    let g = unsafe { raw::syscall6(raw::GETRANDOM, rnd.as_mut_ptr() as i64, 8, 0, 0, 0, 0) };
    assert_eq!(g, 8, "raw getrandom");
    let handles: Vec<_> = (0..3).map(|_| std::thread::spawn(|| unsafe { clock_mono() })).collect();
    let mut all_virtual = t0 < VIRTUAL_BOUND && t1 < VIRTUAL_BOUND && t1 >= t0;
    for h in handles {
        all_virtual &= h.join().unwrap() < VIRTUAL_BOUND;
    }
    let rand_hex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "RAW_SUD_RESULT fs={} rand={} threads_virtual={}",
        std::str::from_utf8(&buf).unwrap(),
        rand_hex,
        all_virtual
    );
}
RS
  "$runner" build "$tmp/raw_syscall_probe.rs" --output "$tmp/raw-syscall-probe" >/dev/null

  # Static audit (kernel-independent): `audit` has no live kernel probe, so on
  # EVERY kernel it reports the raw-syscall sites as SUD-managed with both
  # potential outcomes (runnable under SUD; refused on kernels without it),
  # succeeding rather than refusing — the marker makes the difference (contrast
  # the no-marker planted probe below, which stays refused).
  "$runner" audit "$tmp/raw-syscall-probe" "${shim_allow[@]}" >"$tmp/raw-audit" 2>&1
  grep -q 'SUD-managed' "$tmp/raw-audit"
  grep -q 'refused on kernels without it' "$tmp/raw-audit"

  # sigsys-hijack (kernel-independent): a guest sigaction(SIGSYS,…) is refused —
  # under SUD the SIGSYS handler IS the deterministic containment, so the guest
  # may not re-register it. This is proved on every Linux kernel (the symbol-door
  # interposer does not depend on SUD arming). RED before §7.5 landed: the old
  # allowlist let it succeed silently.
  cat >"$tmp/sigsys_probe.rs" <<'RS'
fn main() {
    unsafe extern "C" {
        fn sigaction(sig: i32, act: *const core::ffi::c_void, old: *mut core::ffi::c_void) -> i32;
    }
    const SIGSYS: i32 = 31;
    // The interposer refuses SIGSYS before dereferencing `act`, so null is safe.
    let rc = unsafe { sigaction(SIGSYS, core::ptr::null(), core::ptr::null_mut()) };
    println!("SIGSYS_REGISTER_REFUSED={}", rc != 0);
}
RS
  "$runner" build "$tmp/sigsys_probe.rs" --output "$tmp/sigsys-probe" >/dev/null
  "$runner" run "$tmp/sigsys-probe" --seed 1 >"$tmp/sigsys-out"
  grep -qx 'SIGSYS_REGISTER_REFUSED=true' "$tmp/sigsys-out"

  # marker-gating (static, kernel-independent): a NON-shim-linked binary with a
  # planted raw syscall and NO patina_sud_dispatch marker must STILL be refused
  # by audit — the direct-syscall downgrade is conditional on the marker, never
  # unconditional. Guards against the gate silently opening.
  cat >"$tmp/planted_raw.c" <<'C'
int main(void) {
#if defined(__x86_64__)
    __asm__ volatile("mov $39, %%rax\n\tsyscall" ::: "rax", "rcx", "r11");
#elif defined(__aarch64__)
    __asm__ volatile("mov x8, #172\n\tsvc #0" ::: "x8", "x0");
#endif
    return 0;
}
C
  "$cc" "$tmp/planted_raw.c" -o "$tmp/planted-raw"
  if "$runner" audit "$tmp/planted-raw" --raw >"$tmp/planted-audit" 2>&1; then
    echo 'validate-native-shim: SUD marker-gating — a no-marker raw-syscall binary audited clean (downgrade must require the marker)' >&2
    exit 1
  fi
  grep -q 'direct-syscall' "$tmp/planted-audit"

  # AT_RANDOM determinization (SUD-DESIGN.md §9 slice 3, kernel-INDEPENDENT): the
  # shim overwrites the auxv AT_RANDOM 16 bytes with seed-derived deterministic
  # bytes on EVERY managed run (whether or not SUD arms), closing the entropy
  # leak glibc's canary and a guest's getauxval(AT_RANDOM) both read. getauxval
  # is allowlisted (a libc call, no raw syscall), so this probe audits clean and
  # runs on any Linux kernel — the assertion is that the same seed yields the
  # same 16 bytes and distinct seeds differ. RED mutation (documented): drop the
  # patina_sud_determinize_at_random call in patina_sud_init and the same-seed
  # runs diverge (the kernel hands fresh random per exec).
  cat >"$tmp/at_random_probe.rs" <<'RS'
fn main() {
    unsafe extern "C" {
        fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
    }
    const AT_RANDOM: core::ffi::c_ulong = 25;
    let p = unsafe { getauxval(AT_RANDOM) } as *const u8;
    assert!(!p.is_null(), "AT_RANDOM pointer is null");
    // SAFETY: the kernel places 16 random bytes at the AT_RANDOM pointer.
    let bytes = unsafe { core::slice::from_raw_parts(p, 16) };
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("AT_RANDOM={hex}");
}
RS
  "$runner" build "$tmp/at_random_probe.rs" --output "$tmp/at-random-probe" >/dev/null
  ar_s1a="$("$runner" run "$tmp/at-random-probe" --seed 1 2>/dev/null)"
  ar_s1b="$("$runner" run "$tmp/at-random-probe" --seed 1 2>/dev/null)"
  ar_s2="$("$runner" run "$tmp/at-random-probe" --seed 2 2>/dev/null)"
  if [[ "$ar_s1a" != "$ar_s1b" ]]; then
    echo "validate-native-shim: AT_RANDOM not deterministic across same-seed runs ($ar_s1a vs $ar_s1b)" >&2
    exit 1
  fi
  if [[ "$ar_s1a" == "$ar_s2" ]]; then
    echo "validate-native-shim: AT_RANDOM did not vary across seeds ($ar_s1a)" >&2
    exit 1
  fi

  # vsyscall-page audit refusal (SUD-DESIGN.md §6.3, x86_64-only, kernel-
  # INDEPENDENT static audit): a binary whose text materializes the legacy
  # vsyscall page address (0xffffffffff600000) as a 64-bit immediate is refused
  # — that page is kernel-emulated with no `syscall` instruction, invisible to
  # both the scan and SUD. RED mutation (documented): neuter
  # scan_vsyscall_references and this hand-built binary audits clean.
  if [[ "$(uname -m)" == x86_64 ]]; then
    cat >"$tmp/vsyscall_probe.c" <<'C'
int main(void) {
    void *p;
    /* movabs $0xffffffffff600000, %reg — a single 64-bit immediate in .text. */
    __asm__ volatile("movabs $0xffffffffff600000, %0" : "=r"(p));
    return p != 0;
}
C
    "$cc" "$tmp/vsyscall_probe.c" -o "$tmp/vsyscall-probe"
    if "$runner" audit "$tmp/vsyscall-probe" --raw >"$tmp/vsyscall-audit" 2>&1; then
      echo 'validate-native-shim: vsyscall-page reference audited clean (must be refused)' >&2
      cat "$tmp/vsyscall-audit" >&2
      exit 1
    fi
    grep -q 'vsyscall' "$tmp/vsyscall-audit"
  fi

  if [[ $sud_kernel == 1 ]]; then
    echo "sud: ENABLED (kernel supports syscall-user-dispatch) — running the positive battery"

    # Runs; two same-seed runs are byte-identical; record→replay is byte-identical.
    "$runner" run "$tmp/raw-syscall-probe" --seed 5 >"$tmp/raw-seed-1"
    "$runner" run "$tmp/raw-syscall-probe" --seed 5 >"$tmp/raw-seed-2"
    cmp "$tmp/raw-seed-1" "$tmp/raw-seed-2"
    grep -q '^RAW_SUD_RESULT fs=sud ' "$tmp/raw-seed-1"
    # The three-thread fanout: every thread observed virtual (not wall) time,
    # proving per-thread SUD arming in the trampoline.
    grep -q 'threads_virtual=true' "$tmp/raw-seed-1"
    # Entropy is seed-derived: raw getrandom varies across seeds (not wall-random,
    # not constant).
    raw_distinct=$(for s in 1 2 3 4; do
      "$runner" run "$tmp/raw-syscall-probe" --seed "$s"
    done | grep -o 'rand=[0-9a-f]*' | sort -u | wc -l)
    if [[ "$raw_distinct" -lt 2 ]]; then
      echo 'validate-native-shim: SUD raw-syscall entropy did not vary across seeds' >&2
      exit 1
    fi
    "$runner" run "$tmp/raw-syscall-probe" --seed 5 --record "$tmp/raw.patina" \
      --fingerprint sud-raw-v1 >"$tmp/raw-record"
    "$runner" replay "$tmp/raw-syscall-probe" "$tmp/raw.patina" \
      --fingerprint sud-raw-v1 >"$tmp/raw-replay"
    cmp "$tmp/raw-record" "$tmp/raw-replay"
    cmp "$tmp/raw-seed-1" "$tmp/raw-replay"

    # unmapped-syscall abort: a raw reboot (a syscall the dispatch table must
    # never map) traps to a named, deterministic abort — not a silent escape.
    # Bad magic numbers mean the kernel would reject it harmlessly even if the
    # trap were broken, and the leg still fails loudly on that escape.
    cat >"$tmp/raw_unmapped_probe.rs" <<'RS'
use std::arch::asm;
fn main() {
    #[cfg(target_arch = "x86_64")]
    let nr: i64 = 169; // reboot
    #[cfg(target_arch = "aarch64")]
    let nr: i64 = 142; // reboot
    let ret: i64;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!("syscall", inlateout("rax") nr => ret, in("rdi") 0, in("rsi") 0, in("rdx") 0, in("r10") 0, out("rcx") _, out("r11") _, options(nostack));
        #[cfg(target_arch = "aarch64")]
        asm!("svc #0", in("x8") nr, inlateout("x0") 0i64 => ret, in("x1") 0, in("x2") 0, in("x3") 0, options(nostack));
    }
    println!("UNMAPPED_RET={ret}"); // unreachable: dispatch aborts before returning
}
RS
    "$runner" build "$tmp/raw_unmapped_probe.rs" --output "$tmp/raw-unmapped-probe" >/dev/null
    if "$runner" run "$tmp/raw-unmapped-probe" --seed 1 >"$tmp/raw-unmapped-out" 2>&1; then
      echo 'validate-native-shim: SUD unmapped-syscall probe did not abort' >&2
      exit 1
    fi
    grep -q 'SUD trapped unsupported syscall' "$tmp/raw-unmapped-out"

    # vDSO escape closed: after the auxv scrub, getauxval(AT_SYSINFO_EHDR) is 0,
    # so a vDSO-resolving crate finds no vDSO and falls back to a raw syscall
    # (which SUD traps). getauxval is a libc call (no raw syscall), so the probe
    # audits clean and runs on any kernel — but the scrub only happens on an armed
    # (SUD) run, so the assertion is SUD-only.
    cat >"$tmp/auxv_probe.rs" <<'RS'
fn main() {
    unsafe extern "C" {
        fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
    }
    const AT_SYSINFO_EHDR: core::ffi::c_ulong = 33;
    println!("AUXV_SYSINFO_EHDR={}", unsafe { getauxval(AT_SYSINFO_EHDR) });
}
RS
    "$runner" build "$tmp/auxv_probe.rs" --output "$tmp/auxv-probe" >/dev/null
    "$runner" run "$tmp/auxv-probe" --seed 1 >"$tmp/auxv-out"
    grep -qx 'AUXV_SYSINFO_EHDR=0' "$tmp/auxv-out"

    # ---- Slice 2 rows ----
    # (a) The committed rustix-default MRE testbed: a std+rustix program on the
    # DEFAULT (linux_raw) backend exercising raw clocks, fs (openat/write/read/
    # fstat=statx), directory iteration (getdents64 over a SUD directory fd),
    # getrandom, sleep, and SimNet (socket/bind/sendto/recvfrom/getsockname +
    # TCP socket lifecycle). Its own run-patina.sh asserts audit→SUD-managed,
    # seed-stable, and record/replay byte-identical, then prints RUSTIX_LEGS_RAN.
    # This is the acceptance MRE — the exact binary class refused before SUD.
    if bash "$root/testbeds/rustix-default/run-patina.sh" >"$tmp/rustix-mre.out" 2>&1; then
      grep -q 'RUSTIX_LEGS_RAN branch=sud' "$tmp/rustix-mre.out" || {
        echo 'validate-native-shim: rustix-default MRE did not run its SUD battery' >&2
        cat "$tmp/rustix-mre.out" >&2; exit 1; }
    else
      echo 'validate-native-shim: rustix-default MRE run-patina.sh failed' >&2
      cat "$tmp/rustix-mre.out" >&2; exit 1
    fi

    # The remaining raw-syscall probes are x86_64 asm (the positive SUD battery
    # is x86_64 today; a future arm64 SUD kernel would extend them).
    if [[ "$(uname -m)" == x86_64 ]]; then
      # (b) Deterministic process-state constants: raw getpid=1, getuid=1000,
      # uname=-ENOSYS — the same values the interposers return. RED mutation:
      # drop the nr::GETPID/GETUID/UNAME arms and dispatch aborts (unmapped).
      cat >"$tmp/raw_procstate.rs" <<'RS'
use std::arch::asm;
unsafe fn sc(nr: i64, a0: i64) -> i64 {
    let r: i64;
    unsafe { asm!("syscall", inlateout("rax") nr => r, in("rdi") a0,
        out("rcx") _, out("r11") _, options(nostack)); }
    r
}
fn main() {
    let pid = unsafe { sc(39, 0) };
    let uid = unsafe { sc(102, 0) };
    let mut utsname = [0u8; 390];
    let uname_rc = unsafe { sc(63, utsname.as_mut_ptr() as i64) };
    assert_eq!(pid, 1, "getpid");
    assert_eq!(uid, 1000, "getuid");
    assert!(uname_rc < 0, "uname must be ENOSYS, got {uname_rc}");
    println!("RAW_PROCSTATE pid={pid} uid={uid} uname_rc={uname_rc}");
}
RS
      "$runner" build "$tmp/raw_procstate.rs" --output "$tmp/raw-procstate" >/dev/null
      "$runner" run "$tmp/raw-procstate" --seed 1 >"$tmp/raw-procstate-out"
      grep -qx 'RAW_PROCSTATE pid=1 uid=1000 uname_rc=-38' "$tmp/raw-procstate-out"

      # (c) Readiness rows: raw eventfd2 + epoll_create1 + epoll_ctl(ADD,EPOLLIN)
      # + a raw write to the eventfd + epoll_wait returns the armed fd with the
      # registered data. Proves the SUD rows call the SAME epoll frontend the C
      # interposers do. RED mutation: drop the nr::EPOLL_* arms → unmapped abort.
      cat >"$tmp/raw_epoll.rs" <<'RS'
use std::arch::asm;
unsafe fn sc(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    let r: i64;
    unsafe { asm!("syscall", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1,
        in("rdx") a2, in("r10") a3, out("rcx") _, out("r11") _, options(nostack)); }
    r
}
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ev { events: u32, data: u64 }
fn main() {
    let efd = unsafe { sc(290, 0, 0, 0, 0) };       // eventfd2(0, 0)
    assert!(efd >= 0, "eventfd2 {efd}");
    let ep = unsafe { sc(291, 0, 0, 0, 0) };        // epoll_create1(0)
    assert!(ep >= 0, "epoll_create1 {ep}");
    let mut ev = Ev { events: 0x1, data: 0xC0FFEE }; // EPOLLIN
    let ctl = unsafe { sc(233, ep, 1, efd, &mut ev as *mut Ev as i64) }; // ADD
    assert_eq!(ctl, 0, "epoll_ctl ADD {ctl}");
    let one: u64 = 1;
    let w = unsafe { sc(1, efd, &one as *const u64 as i64, 8, 0) }; // write(efd, &1, 8)
    assert_eq!(w, 8, "eventfd write {w}");
    let mut out = [Ev { events: 0, data: 0 }; 4];
    let n = unsafe { sc(232, ep, out.as_mut_ptr() as i64, 4, 0) }; // epoll_wait(-1 via r10=0? use timeout 0)
    assert!(n >= 1, "epoll_wait {n}");
    let data = { out[0].data };
    assert_eq!(data, 0xC0FFEE, "epoll data {data:#x}");
    println!("RAW_EPOLL n={n} data={data:#x}");
}
RS
      "$runner" build "$tmp/raw_epoll.rs" --output "$tmp/raw-epoll" >/dev/null
      "$runner" run "$tmp/raw-epoll" --seed 1 >"$tmp/raw-epoll-out"
      grep -q '^RAW_EPOLL n=' "$tmp/raw-epoll-out"

      # (d) sendmsg/recvmsg mirror the C interposers EXACTLY: both fail closed
      # with ENOSYS (the deterministic net layer models only sendto/recvfrom).
      # The raw rows must therefore return -ENOSYS (-38) — NOT a per-iovec
      # sendto/recvfrom loop, which for a DATAGRAM socket would fragment one
      # message into N datagrams (silently-wrong; house doctrine forbids it).
      # RED mutation: reinstating a per-iovec fragmenting sendmsg/recvmsg makes
      # this leg red (the calls would return a byte count, not -38).
      cat >"$tmp/raw_msg.rs" <<'RS'
use std::arch::asm;
unsafe fn sc(nr: i64, a0: i64, a1: i64, a2: i64) -> i64 {
    let r: i64;
    unsafe { asm!("syscall", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1,
        in("rdx") a2, out("rcx") _, out("r11") _, options(nostack)); }
    r
}
#[repr(C)] struct SockaddrIn { family: u16, port: u16, addr: u32, zero: [u8; 8] }
#[repr(C)] struct Iovec { base: *mut u8, len: usize }
#[repr(C)] struct Msghdr {
    name: *mut u8, namelen: u32, _pad0: u32,
    iov: *mut Iovec, iovlen: u64,
    control: *mut u8, controllen: u64, flags: i32, _pad1: u32,
}
fn main() {
    let sock = unsafe { sc(41, 2, 2, 0) }; // socket(AF_INET, SOCK_DGRAM, 0)
    assert!(sock >= 0, "socket {sock}");
    let mut sa = SockaddrIn { family: 2, port: 34569u16.to_be(), addr: 0x7f000001u32.to_be(), zero: [0; 8] };
    let b = unsafe { sc(49, sock, &mut sa as *mut SockaddrIn as i64, core::mem::size_of::<SockaddrIn>() as i64) };
    assert_eq!(b, 0, "bind {b}");
    // A TWO-iovec datagram: a fragmenting implementation would send two
    // datagrams; the correct (interposer-mirroring) row refuses with ENOSYS.
    let a = *b"frag-";
    let c = *b"ment";
    let (mut abuf, mut cbuf) = (a, c);
    let mut iov = [
        Iovec { base: abuf.as_mut_ptr(), len: abuf.len() },
        Iovec { base: cbuf.as_mut_ptr(), len: cbuf.len() },
    ];
    let msg = Msghdr {
        name: &mut sa as *mut SockaddrIn as *mut u8, namelen: core::mem::size_of::<SockaddrIn>() as u32, _pad0: 0,
        iov: iov.as_mut_ptr(), iovlen: 2, control: core::ptr::null_mut(), controllen: 0, flags: 0, _pad1: 0,
    };
    let sent = unsafe { sc(46, sock, &msg as *const Msghdr as i64, 0) }; // sendmsg
    assert_eq!(sent, -38, "sendmsg must mirror the interposer ENOSYS, got {sent}");
    let mut recv_buf = [0u8; 32];
    let mut riov = Iovec { base: recv_buf.as_mut_ptr(), len: recv_buf.len() };
    let mut rmsg = Msghdr {
        name: core::ptr::null_mut(), namelen: 0, _pad0: 0,
        iov: &mut riov as *mut Iovec, iovlen: 1, control: core::ptr::null_mut(), controllen: 0, flags: 0, _pad1: 0,
    };
    let got = unsafe { sc(47, sock, &mut rmsg as *mut Msghdr as i64, 0) }; // recvmsg
    assert_eq!(got, -38, "recvmsg must mirror the interposer ENOSYS, got {got}");
    println!("RAW_MSG sendmsg={sent} recvmsg={got}");
}
RS
      "$runner" build "$tmp/raw_msg.rs" --output "$tmp/raw-msg" >/dev/null
      "$runner" run "$tmp/raw-msg" --seed 1 >"$tmp/raw-msg-out"
      grep -qx 'RAW_MSG sendmsg=-38 recvmsg=-38' "$tmp/raw-msg-out"

      # (e) prctl(PR_GET_AUXV): rustix's linux_raw init reads the aux vector with
      # a raw prctl(PR_GET_AUXV, buf, size, 0, 0) (Linux >= 6.4) — the syscall
      # that crashed the rustix-default MRE before this row existed. The row must
      # serve the shim's SCRUBBED auxv, not the kernel's pristine saved_auxv:
      # walking the returned buffer, AT_RANDOM must equal the seed-derived bytes
      # getauxval(AT_RANDOM) reads (determinized, identical across same-seed runs)
      # and AT_SYSINFO_EHDR must be gone (scrubbed to AT_IGNORE) — proving the row
      # copies the live scrubbed array rather than re-asking the kernel. RED
      # mutation: drop the nr::PRCTL arm and this run aborts (unmapped), or serve
      # the kernel's saved_auxv and AT_SYSINFO_EHDR reappears / AT_RANDOM diverges.
      cat >"$tmp/raw_prctl_auxv.rs" <<'RS'
use std::arch::asm;
unsafe fn prctl(option: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
    let r: i64;
    unsafe { asm!("syscall", inlateout("rax") 157i64 => r, in("rdi") option,
        in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5,
        out("rcx") _, out("r11") _, options(nostack)); }
    r
}
fn main() {
    const PR_GET_AUXV: i64 = 0x4155_5856;
    const AT_NULL: u64 = 0;
    const AT_RANDOM: u64 = 25;
    const AT_SYSINFO_EHDR: u64 = 33;
    unsafe extern "C" {
        fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
    }
    let mut buf = [0u8; 4096];
    let ret = unsafe { prctl(PR_GET_AUXV, buf.as_mut_ptr() as i64, buf.len() as i64, 0, 0) };
    assert!(ret > 0, "PR_GET_AUXV returned {ret}");
    let full = ret as usize;
    assert!(full <= buf.len(), "auxv ({full}) larger than probe buffer");
    // Walk the returned copy: 16-byte (a_type: u64, a_val: u64) entries to AT_NULL.
    let mut at_random_ptr: u64 = 0;
    let mut saw_sysinfo = false;
    let mut terminated = false;
    let mut i = 0usize;
    while i + 16 <= full {
        let t = u64::from_ne_bytes(buf[i..i + 8].try_into().unwrap());
        let v = u64::from_ne_bytes(buf[i + 8..i + 16].try_into().unwrap());
        if t == AT_NULL { terminated = true; break; }
        if t == AT_RANDOM { at_random_ptr = v; }
        if t == AT_SYSINFO_EHDR { saw_sysinfo = true; }
        i += 16;
    }
    assert!(terminated, "PR_GET_AUXV buffer had no AT_NULL terminator");
    assert!(!saw_sysinfo, "AT_SYSINFO_EHDR must be scrubbed from the served auxv");
    assert!(at_random_ptr != 0, "AT_RANDOM missing from the served auxv");
    // The AT_RANDOM entry must point at the SAME scrubbed 16 bytes getauxval reads.
    let ga = unsafe { getauxval(AT_RANDOM as core::ffi::c_ulong) } as u64;
    assert!(ga != 0, "getauxval(AT_RANDOM) null");
    // SAFETY: both pointers address the 16 seed-derived AT_RANDOM bytes.
    let via_prctl = unsafe { core::slice::from_raw_parts(at_random_ptr as *const u8, 16) };
    let via_getaux = unsafe { core::slice::from_raw_parts(ga as *const u8, 16) };
    assert_eq!(via_prctl, via_getaux, "PR_GET_AUXV AT_RANDOM != getauxval(AT_RANDOM)");
    let hex: String = via_prctl.iter().map(|b| format!("{b:02x}")).collect();
    println!("PR_GET_AUXV len={full} random={hex}");
}
RS
      "$runner" build "$tmp/raw_prctl_auxv.rs" --output "$tmp/raw-prctl-auxv" >/dev/null
      "$runner" run "$tmp/raw-prctl-auxv" --seed 1 >"$tmp/raw-prctl-auxv-1"
      "$runner" run "$tmp/raw-prctl-auxv" --seed 1 >"$tmp/raw-prctl-auxv-2"
      cmp "$tmp/raw-prctl-auxv-1" "$tmp/raw-prctl-auxv-2"
      grep -q '^PR_GET_AUXV len=' "$tmp/raw-prctl-auxv-1"

      # A denied prctl option (PR_SET_NAME=15) must abort with the NAMED prctl
      # message — never route to the host. RED: routing non-GET_AUXV options would
      # let the run succeed (no abort) and this leg would fail to find the message.
      cat >"$tmp/raw_prctl_deny.rs" <<'RS'
use std::arch::asm;
fn main() {
    let name = b"patina\0";
    let r: i64;
    unsafe { asm!("syscall", inlateout("rax") 157i64 => r, in("rdi") 15i64,
        in("rsi") name.as_ptr() as i64, in("rdx") 0i64, in("r10") 0i64, in("r8") 0i64,
        out("rcx") _, out("r11") _, options(nostack)); }
    println!("PR_SET_NAME_RET={r}"); // unreachable: dispatch aborts before returning
}
RS
      "$runner" build "$tmp/raw_prctl_deny.rs" --output "$tmp/raw-prctl-deny" >/dev/null
      if "$runner" run "$tmp/raw-prctl-deny" --seed 1 >"$tmp/raw-prctl-deny-out" 2>&1; then
        echo 'validate-native-shim: denied prctl option did not abort' >&2
        cat "$tmp/raw-prctl-deny-out" >&2; exit 1
      fi
      grep -q 'SUD trapped prctl' "$tmp/raw-prctl-deny-out"

      # (f) x86_64 LEGACY fs aliases route to the SAME deterministic FS as their
      # modern *at forms. rustix's linux_raw backend emits raw legacy `open`(2)
      # on x86_64 (the round-5 failure), and hand-asm/older code emits creat(85)
      # and unlink(87). Each must alias to openat(AT_FDCWD)/unlinkat: create+write
      # via legacy open, read-back via legacy open, create via legacy creat (flags
      # SYNTHESIZED), remove via legacy unlink, then a legacy open of the removed
      # path fails. It THEN reproduces rustix `Dir::read_from` in raw asm — legacy
      # open(2) of a DIRECTORY, fcntl(F_GETFL), openat(dir_fd, "."), getdents64 —
      # which is the round-6 failure: a SUD directory fd must accept fcntl(F_GETFL)
      # and openat(".") (before the fix, fcntl returned EBADF as a "virtual socket"
      # and Dir::read_from failed). RED mutations: drop the nr::OPEN/CREAT/UNLINK
      # arms → unmapped abort; mis-synthesize creat's flags → creat fails; drop the
      # SUD-dir-fd fcntl/openat handling → fcntl(F_GETFL)=EBADF or openat(".")=EINVAL
      # and no entries are listed.
      cat >"$tmp/raw_legacy_fs.rs" <<'RS'
use std::arch::asm;
unsafe fn sc(nr: i64, a0: i64, a1: i64, a2: i64) -> i64 {
    let r: i64;
    unsafe { asm!("syscall", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1,
        in("rdx") a2, in("r10") 0i64, out("rcx") _, out("r11") _, options(nostack)); }
    r
}
fn main() {
    const OPEN: i64 = 2; const READ: i64 = 0; const WRITE: i64 = 1; const CLOSE: i64 = 3;
    const CREAT: i64 = 85; const UNLINK: i64 = 87; const MKDIR: i64 = 83;
    const OPENAT: i64 = 257; const GETDENTS64: i64 = 217; const FCNTL: i64 = 72;
    const O_WRONLY: i64 = 0o1; const O_CREAT: i64 = 0o100; const O_TRUNC: i64 = 0o1000;
    const O_DIRECTORY: i64 = 0o200000; const F_GETFL: i64 = 3;
    let path = b"/legacy-open.txt\0";
    let msg = b"legacy-alias";
    // legacy open(2) create+write.
    let fd = unsafe { sc(OPEN, path.as_ptr() as i64, O_WRONLY | O_CREAT | O_TRUNC, 0o600) };
    assert!(fd >= 0, "legacy open(create) {fd}");
    let w = unsafe { sc(WRITE, fd, msg.as_ptr() as i64, msg.len() as i64) };
    assert_eq!(w, msg.len() as i64, "write {w}");
    assert_eq!(unsafe { sc(CLOSE, fd, 0, 0) }, 0, "close");
    // legacy open(2) read-back.
    let rfd = unsafe { sc(OPEN, path.as_ptr() as i64, 0 /*O_RDONLY*/, 0) };
    assert!(rfd >= 0, "legacy open(read) {rfd}");
    let mut buf = [0u8; 32];
    let n = unsafe { sc(READ, rfd, buf.as_mut_ptr() as i64, buf.len() as i64) };
    assert_eq!(&buf[..n as usize], msg, "legacy open read-back mismatch");
    let _ = unsafe { sc(CLOSE, rfd, 0, 0) };
    // legacy creat(85): flags synthesized to O_CREAT|O_WRONLY|O_TRUNC.
    let path2 = b"/legacy-creat.txt\0";
    let cfd = unsafe { sc(CREAT, path2.as_ptr() as i64, 0o600, 0) };
    assert!(cfd >= 0, "legacy creat {cfd}");
    let _ = unsafe { sc(CLOSE, cfd, 0, 0) };
    // legacy unlink(87) removes it; a subsequent legacy open must fail.
    assert_eq!(unsafe { sc(UNLINK, path2.as_ptr() as i64, 0, 0) }, 0, "legacy unlink");
    let gone = unsafe { sc(OPEN, path2.as_ptr() as i64, 0, 0) };
    assert!(gone < 0, "legacy open of unlinked path must fail, got {gone}");

    // ---- directory listing through the raw rustix `Dir::read_from` dance ----
    let dir = b"/legacy-dir\0";
    assert_eq!(unsafe { sc(MKDIR, dir.as_ptr() as i64, 0o755, 0) }, 0, "legacy mkdir");
    for f in [b"/legacy-dir/alpha\0".as_ref(), b"/legacy-dir/beta\0".as_ref()] {
        let cfd = unsafe { sc(OPEN, f.as_ptr() as i64, O_WRONLY | O_CREAT | O_TRUNC, 0o600) };
        assert!(cfd >= 0, "create-in-dir {cfd}");
        let _ = unsafe { sc(CLOSE, cfd, 0, 0) };
    }
    // legacy open(2) of the DIRECTORY yields a SUD directory fd.
    let dfd = unsafe { sc(OPEN, dir.as_ptr() as i64, O_DIRECTORY, 0) };
    assert!(dfd >= 0, "legacy open(dir) {dfd}");
    // rustix Dir::read_from: fcntl(F_GETFL) then openat(dir_fd, ".", flags).
    let fl = unsafe { sc(FCNTL, dfd, F_GETFL, 0) };
    assert!(fl >= 0, "fcntl(F_GETFL) on SUD dir fd was EBADF before the fix, got {fl}");
    let dot = b".\0";
    let dfd2 = unsafe { sc(OPENAT, dfd, dot.as_ptr() as i64, fl) };
    assert!(dfd2 >= 0, "openat(dir_fd, \".\") {dfd2}");
    // raw getdents64 over the fresh handle.
    let mut dbuf = [0u8; 1024];
    let mut names: Vec<String> = Vec::new();
    loop {
        let g = unsafe { sc(GETDENTS64, dfd2, dbuf.as_mut_ptr() as i64, dbuf.len() as i64) };
        assert!(g >= 0, "getdents64 {g}");
        if g == 0 { break; }
        let mut off = 0usize;
        while off < g as usize {
            let reclen = u16::from_ne_bytes([dbuf[off + 16], dbuf[off + 17]]) as usize;
            assert!(reclen >= 19 && off + reclen <= g as usize, "bad d_reclen {reclen}");
            let nb = &dbuf[off + 19..off + reclen];
            let end = nb.iter().position(|&b| b == 0).unwrap_or(nb.len());
            let name = String::from_utf8_lossy(&nb[..end]).into_owned();
            if name != "." && name != ".." { names.push(name); }
            off += reclen;
        }
    }
    names.sort();
    assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()], "legacy dir listing {names:?}");
    let _ = unsafe { sc(CLOSE, dfd2, 0, 0) };
    let _ = unsafe { sc(CLOSE, dfd, 0, 0) };
    println!("LEGACY_ALIASES open+creat+unlink+getdents ok");
}
RS
      "$runner" build "$tmp/raw_legacy_fs.rs" --output "$tmp/raw-legacy-fs" >/dev/null
      "$runner" run "$tmp/raw-legacy-fs" --seed 1 >"$tmp/raw-legacy-fs-out"
      grep -qx 'LEGACY_ALIASES open+creat+unlink+getdents ok' "$tmp/raw-legacy-fs-out"

      # (g) raw socketpair: interposed socketpair works but raw aborted before the
      # row existed (the strongest raw-vs-interposed asymmetry). Create an AF_UNIX
      # STREAM pair, write one end, read the other, assert the bytes, close both.
      # Then dup2(eventfd, eventfd) must be EBADF — the C dup2 validity accepts
      # only net/pipe fds, NOT epoll/eventfd. RED: drop nr::SOCKETPAIR → abort;
      # re-widen dup2 validity to accept eventfd → the EBADF assert fails.
      cat >"$tmp/raw_socketpair.rs" <<'RS'
use std::arch::asm;
unsafe fn sc(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64) -> i64 {
    let r: i64;
    unsafe { asm!("syscall", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1,
        in("rdx") a2, in("r10") a3, out("rcx") _, out("r11") _, options(nostack)); }
    r
}
fn main() {
    const SOCKETPAIR: i64 = 53; const WRITE: i64 = 1; const READ: i64 = 0; const CLOSE: i64 = 3;
    const EVENTFD2: i64 = 290; const DUP2: i64 = 33;
    const AF_UNIX: i64 = 1; const SOCK_STREAM: i64 = 1;
    let mut sv = [0i32; 2];
    let rc = unsafe { sc(SOCKETPAIR, AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as i64) };
    assert_eq!(rc, 0, "socketpair rc {rc}");
    let (a, b) = (sv[0] as i64, sv[1] as i64);
    assert!(a >= 0 && b >= 0, "socketpair fds {a} {b}");
    let msg = b"pair-ping";
    let w = unsafe { sc(WRITE, a, msg.as_ptr() as i64, msg.len() as i64, 0) };
    assert_eq!(w, msg.len() as i64, "socketpair write {w}");
    let mut buf = [0u8; 16];
    let n = unsafe { sc(READ, b, buf.as_mut_ptr() as i64, buf.len() as i64, 0) };
    assert_eq!(&buf[..n as usize], msg, "socketpair payload mismatch");
    let _ = unsafe { sc(CLOSE, a, 0, 0, 0) };
    let _ = unsafe { sc(CLOSE, b, 0, 0, 0) };
    // dup2(eventfd, eventfd): the equal-fd validity must reject an eventfd (EBADF),
    // mirroring the C dup2 interposer exactly.
    let efd = unsafe { sc(EVENTFD2, 0, 0, 0, 0) };
    assert!(efd >= 0, "eventfd2 {efd}");
    let d = unsafe { sc(DUP2, efd, efd, 0, 0) };
    assert_eq!(d, -9, "dup2(eventfd,eventfd) must be EBADF(-9), got {d}");
    let _ = unsafe { sc(CLOSE, efd, 0, 0, 0) };
    println!("SOCKETPAIR_ROW pair+dup2ebadf ok");
}
RS
      "$runner" build "$tmp/raw_socketpair.rs" --output "$tmp/raw-socketpair" >/dev/null
      "$runner" run "$tmp/raw-socketpair" --seed 1 >"$tmp/raw-socketpair-out"
      grep -qx 'SOCKETPAIR_ROW pair+dup2ebadf ok' "$tmp/raw-socketpair-out"

      # (h) raw ppoll: an empty descriptor set with a 5ms timeout returns 0 after
      # advancing VIRTUAL time by >= 5ms (deterministic — a second same-seed run is
      # byte-identical), and a real-events ppoll (POLLIN on an fd) is a SOFT -ENOSYS
      # the probe survives. RED: drop nr::PPOLL → abort; make the real-events path
      # fatal → the run aborts instead of printing the marker.
      cat >"$tmp/raw_ppoll.rs" <<'RS'
use std::arch::asm;
#[repr(C)] struct Ts { sec: i64, nsec: i64 }
#[repr(C)] struct Pollfd { fd: i32, events: i16, revents: i16 }
unsafe fn sc5(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> i64 {
    let r: i64;
    unsafe { asm!("syscall", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1,
        in("rdx") a2, in("r10") a3, in("r8") a4, out("rcx") _, out("r11") _, options(nostack)); }
    r
}
fn mono_ns() -> i64 {
    let mut ts = Ts { sec: 0, nsec: 0 };
    unsafe { sc5(228 /*clock_gettime*/, 1 /*MONOTONIC*/, &mut ts as *mut Ts as i64, 0, 0, 0); }
    ts.sec * 1_000_000_000 + ts.nsec
}
fn main() {
    const PPOLL: i64 = 271;
    let before = mono_ns();
    let tmo = Ts { sec: 0, nsec: 5_000_000 }; // 5ms
    let rc = unsafe { sc5(PPOLL, 0, 0, &tmo as *const Ts as i64, 0, 0) };
    assert_eq!(rc, 0, "ppoll empty+timeout rc {rc}");
    let delta = mono_ns() - before;
    assert!(delta >= 5_000_000, "ppoll must advance virtual time >= 5ms, got {delta}");
    // Real events with an fd: the deterministic layer models no readiness → soft ENOSYS.
    let mut pfd = Pollfd { fd: 0, events: 1 /*POLLIN*/, revents: 0 };
    let z = Ts { sec: 0, nsec: 0 };
    let r2 = unsafe { sc5(PPOLL, &mut pfd as *mut Pollfd as i64, 1, &z as *const Ts as i64, 0, 0) };
    assert_eq!(r2, -38, "real-events ppoll must be soft -ENOSYS(-38), got {r2}");
    println!("PPOLL_ROW empty_sleep={delta} real_enosys={r2}");
}
RS
      "$runner" build "$tmp/raw_ppoll.rs" --output "$tmp/raw-ppoll" >/dev/null
      "$runner" run "$tmp/raw-ppoll" --seed 1 >"$tmp/raw-ppoll-1"
      "$runner" run "$tmp/raw-ppoll" --seed 1 >"$tmp/raw-ppoll-2"
      cmp "$tmp/raw-ppoll-1" "$tmp/raw-ppoll-2"   # deterministic virtual-time delta
      grep -q '^PPOLL_ROW empty_sleep=' "$tmp/raw-ppoll-1"

      # (i) fcntl(F_GETFL) parity: the SAME op via TWO vehicles — a raw syscall and
      # the interposed libc symbol — must give the SAME result on a regular file:
      # a soft ENOSYS (raw returns -38; libc returns -1 with errno 38). This pins
      # the round-8 fcntl-tail alignment: neither vehicle returns 0 or aborts.
      cat >"$tmp/raw_fcntl_parity.rs" <<'RS'
use std::arch::asm;
use std::os::fd::AsRawFd;
fn main() {
    let f = std::fs::File::create("/fcntl-parity.txt").expect("create");
    let fd = f.as_raw_fd();
    const FCNTL: i64 = 72; const F_GETFL: i64 = 3;
    let raw: i64;
    unsafe { asm!("syscall", inlateout("rax") FCNTL => raw, in("rdi") fd as i64,
        in("rsi") F_GETFL, in("rdx") 0i64, in("r10") 0i64,
        out("rcx") _, out("r11") _, options(nostack)); }
    assert_eq!(raw, -38, "raw fcntl(F_GETFL) must be -ENOSYS(-38), got {raw}");
    unsafe extern "C" { fn fcntl(fd: i32, cmd: i32, ...) -> i32; }
    let lib = unsafe { fcntl(fd, 3) };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    assert_eq!(lib, -1, "libc fcntl(F_GETFL) must fail, got {lib}");
    assert_eq!(errno, 38, "libc fcntl(F_GETFL) errno must be ENOSYS(38), got {errno}");
    println!("FCNTL_PARITY raw={raw} libc_errno={errno}");
}
RS
      "$runner" build "$tmp/raw_fcntl_parity.rs" --output "$tmp/raw-fcntl-parity" >/dev/null
      "$runner" run "$tmp/raw-fcntl-parity" --seed 1 >"$tmp/raw-fcntl-parity-out"
      grep -qx 'FCNTL_PARITY raw=-38 libc_errno=38' "$tmp/raw-fcntl-parity-out"

      cat "$tmp/raw-procstate-out"
      cat "$tmp/raw-epoll-out"
      cat "$tmp/raw-msg-out"
      cat "$tmp/raw-prctl-auxv-1"
      cat "$tmp/raw-legacy-fs-out"
      cat "$tmp/raw-socketpair-out"
      cat "$tmp/raw-ppoll-1"
      cat "$tmp/raw-fcntl-parity-out"
    fi

    cat "$tmp/raw-seed-1"
    cat "$tmp/sigsys-out"
    cat "$tmp/auxv-out"
    # Loud execution proof for CI-log grepping: this line prints only after every
    # positive leg above passed, so a skipped-but-green SUD section is impossible
    # to mistake for an executed one.
    echo 'SUD_LEGS_RAN branch=positive legs=audit-sud-managed,seed-stable,record-replay,thread-arming,seed-varying-entropy,unmapped-abort,auxv-canary,sigsys-hijack,marker-gating,at-random,vsyscall-audit,rustix-mre,procstate-constants,epoll-rows,sendmsg-recvmsg,prctl-get-auxv,legacy-fs-aliases,socketpair-row,ppoll-row,fcntl-getfl-parity'
  else
    echo "sud: SKIPPED (kernel lacks syscall-user-dispatch) — running the refusal + kernel-independent legs"

    # Refusal leg (RED-proved): the raw-syscall probe carries the SUD marker but
    # this kernel has no SUD, so the pre-run gate refuses it with the extended
    # hint (rustix_use_libc / x86_64). This is the exact binary class the arm64
    # VM exercises for real.
    if "$runner" run "$tmp/raw-syscall-probe" --seed 1 >"$tmp/raw-refuse-out" 2>&1; then
      echo 'validate-native-shim: SUD raw-syscall probe was NOT refused on a no-SUD kernel' >&2
      exit 1
    fi
    grep -q 'lacks syscall-user-dispatch' "$tmp/raw-refuse-out"
    grep -q 'direct-syscall' "$tmp/raw-refuse-out"

    # REPLAY refusal: a trace recorded under SUD (on an x86_64 SUD kernel) must
    # refuse to replay here, pre-exec, naming the real situation — not diverge
    # mid-run and not fail with a generic trace error. In slice 1 this is
    # enforced by the same pre-run gate (SUD arming is a pure function of the
    # binary marker × kernel probe, with NO independent toggle, so the marker
    # binary the fingerprint already pins subsumes a sud metadata byte; the
    # explicit `sud` RunMetadata field is slice 2, SUD-DESIGN.md §7.3/§9). The
    # gate runs before the trace is opened, so a placeholder trace file proves
    # the refusal is pre-exec.
    : >"$tmp/sud-foreign.patina"
    if "$runner" replay "$tmp/raw-syscall-probe" "$tmp/sud-foreign.patina" \
      >"$tmp/raw-replay-refuse-out" 2>&1; then
      echo 'validate-native-shim: SUD raw-syscall replay was NOT refused on a no-SUD kernel' >&2
      exit 1
    fi
    grep -q 'lacks syscall-user-dispatch' "$tmp/raw-replay-refuse-out"

    cat "$tmp/raw-refuse-out"
    cat "$tmp/sigsys-out"
    # Loud execution proof, mirroring the positive branch: prints only after the
    # refusal + kernel-independent legs above passed.
    echo 'SUD_LEGS_RAN branch=refusal legs=audit-sud-managed,run-refusal,replay-refusal,sigsys-hijack,marker-gating,at-random'
  fi
fi

cat "$tmp/pipe-seed-1-1"
cat "$tmp/socketpair-seed-1-1"
cat "$tmp/pipe-epipe-out"
cat "$tmp/pipe-nonblock-out"
cat "$tmp/pipe-dup-1"

cat "$tmp/replay"
cat "$tmp/std-replay"
cat "$tmp/tcp-replay"
