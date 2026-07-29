#!/usr/bin/env bash
set -euo pipefail

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
    if (patina_shutdown() != 0) return 25;

    printf("NATIVE_OPENAT_RESULT seed=%" PRIu64 " contents=%s\n", seed, contents);
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

if "$runner" audit "$tmp/std-probe" >/dev/null 2>"$tmp/audit-error"; then
  echo 'validate-native-shim: audit unexpectedly allowed control-plane aliases without --allow' >&2
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
// Imports an uninterposed process-class libc symbol (`kill`) the audit denies as
// "process". The spawn family (fork/posix_spawn*/waitpid/...) is now shim-defined
// (deny-traps), so a Command::spawn leaves no process *import* to flag; this
// reaches for a still-uninterposed member of the class. Taking its address forces
// the undefined import; building succeeds, the audit must reject the product.
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}
fn main() {
    let reached = kill as *const ();
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
# (the eventfd/shm_open leg at the end).
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

# (e) The cross-process class-g siblings stay REFUSED: interposing the in-process
# pipe/socketpair must not weaken the gate for a real IPC escape. eventfd is the
# still-denied sibling on Linux; macOS has no eventfd, so shm_open (same class)
# stands in there. Either way the audit must refuse it as `shared-memory-ipc`.
cat >"$tmp/shared_ipc_refusal_probe.c" <<'C'
#include <fcntl.h>
#include <sys/mman.h>
#ifdef __linux__
#include <sys/eventfd.h>
int main(void) { return eventfd(0, 0) < 0; }
#else
int main(void) { return shm_open("/patina-refused", O_RDONLY, 0) < 0; }
#endif
C
"$cc" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
  "$tmp/shared_ipc_refusal_probe.c" -o "$tmp/shared-ipc-refusal-probe"
if "$runner" audit "$tmp/shared-ipc-refusal-probe" --raw \
  >"$tmp/shared-ipc-refusal-out" 2>"$tmp/shared-ipc-refusal-error"; then
  echo 'validate-native-shim: cross-process shared-memory-ipc symbol unexpectedly passed audit' >&2
  exit 1
fi
grep -q 'shared-memory-ipc' "$tmp/shared-ipc-refusal-error"

cat "$tmp/pipe-seed-1-1"
cat "$tmp/socketpair-seed-1-1"
cat "$tmp/pipe-epipe-out"
cat "$tmp/pipe-nonblock-out"

cat "$tmp/replay"
cat "$tmp/std-replay"
cat "$tmp/tcp-replay"
