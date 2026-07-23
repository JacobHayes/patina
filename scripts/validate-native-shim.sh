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

cat >"$tmp/std_probe.rs" <<'RS'
// An ordinary Rust program: no Patina-specific init/shutdown calls. The
// packaged `cargo patina native-build`/`native-run` startup path installs and
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

cargo build --locked --manifest-path "$root/Cargo.toml" -p patina-native-shim -p cargo-patina >/dev/null
runner="$target_dir/debug/cargo-patina"
"$cc" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
  -I"$root/crates/patina-native-shim/include" \
  "$tmp/probe.c" "$target_dir/debug/libpatina_native_shim.a" \
  -o "$tmp/probe"
"$cc" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror \
  -I"$root/crates/patina-native-shim/include" \
  "$tmp/posix_probe.c" "$root/crates/patina-native-shim/c/patina_posix.c" \
  "$target_dir/debug/libpatina_native_shim.a" -o "$tmp/posix-probe"
"$tmp/posix-probe"
# The interposed ordinary-std probe is built and driven through the packaged
# `cargo patina` native target: native-build compiles the shim layer, injects
# cfg(patina)/cfg(dst), and links the shim below the program; native-run wires
# the PATINA_TRACE_FD supervisor channel for record/replay. The probe carries no
# Patina-specific init/shutdown calls: the packaged startup path installs and
# finalizes the deterministic runtime around ordinary application code.
"$runner" native-build "$tmp/std_probe.rs" --output "$tmp/std-probe" >/dev/null

# Fail-closed startup: running the same binary directly, outside the supervisor,
# must abort with a clear message rather than silently run undeterministically.
if "$tmp/std-probe" >/dev/null 2>"$tmp/standalone-error"; then
  echo 'validate-native-shim: native binary ran standalone without the supervisor' >&2
  exit 1
fi
grep -q 'must run under' "$tmp/standalone-error"

"$runner" native-run "$tmp/std-probe" --seed 9 >"$tmp/std-seed-1"
"$runner" native-run "$tmp/std-probe" --seed 9 >"$tmp/std-seed-2"
"$runner" native-run "$tmp/std-probe" --seed 10 >"$tmp/std-seed-other"
cmp "$tmp/std-seed-1" "$tmp/std-seed-2"
if cmp -s "$tmp/std-seed-1" "$tmp/std-seed-other"; then
  echo 'validate-native-shim: distinct std-probe seeds produced identical output' >&2
  exit 1
fi
"$runner" native-run "$tmp/std-probe" --seed 9 --record "$tmp/std.patina" \
  --fingerprint native-std-v1 >"$tmp/std-record"
"$runner" native-run "$tmp/std-probe" --seed 9 --record "$tmp/std-repeat.patina" \
  --fingerprint native-std-v1 >/dev/null
cmp "$tmp/std.patina" "$tmp/std-repeat.patina"
"$runner" native-run "$tmp/std-probe" --replay "$tmp/std.patina" \
  --fingerprint native-std-v1 >"$tmp/std-replay"
cmp "$tmp/std-record" "$tmp/std-replay"
cmp "$tmp/std-seed-1" "$tmp/std-replay"
grep -qx 'PATINA_STRACE_MARKER' "$tmp/std-replay"
grep -Eq '^NATIVE_STD_RESULT epoch_ns=0 first_hash=[0-9a-f]{16} second_hash=[0-9a-f]{16} fs=link:symlink,nested:dir,value:file$' "$tmp/std-replay"
if "$runner" native-run "$tmp/std-probe" --replay "$tmp/std.patina" \
  --fingerprint native-std-other >/dev/null 2>&1; then
  echo 'validate-native-shim: std-probe replay accepted a changed fingerprint' >&2
  exit 1
fi

# The audit's static allowlist covers only effect-free host-deferred symbols.
# Everything the SHIM itself uses as its host control plane is `--allow`ed per
# audited binary here instead, so an unmanaged binary importing the same
# symbols (to read/write, spawn, or block outside the scheduler) still fails
# the audit: the trace-fd read/write aliases; the managed host-thread vehicle
# (macOS: pthread_create_suspended_np + pthread_mach_thread_np + thread_resume;
# Linux: the __real_pthread_create import left by -Wl,--wrap=pthread_create);
# and the scheduler's execution batons (macOS: dispatch semaphores; Linux:
# POSIX sem_* — glibc-internal futexes invisible to the guest's interposed
# syscall()).
if [[ "$(uname -s)" == Darwin ]]; then
  control_plane=(
    --allow '_read$NOCANCEL' --allow '_write$NOCANCEL'
    --allow pthread_create_suspended_np --allow pthread_mach_thread_np
    --allow thread_resume
    --allow dispatch_semaphore_create --allow dispatch_semaphore_wait
    --allow dispatch_semaphore_signal --allow dispatch_release
  )
else
  control_plane=(
    --allow __read --allow __write --allow pthread_create
    --allow sem_init --allow sem_post --allow sem_wait
  )
fi
shim_allow=("${control_plane[@]}")
"$runner" native-audit "$tmp/std-probe" \
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

if "$runner" native-audit "$tmp/std-probe" >/dev/null 2>"$tmp/audit-error"; then
  echo 'validate-native-shim: audit unexpectedly allowed control-plane aliases without --allow' >&2
  exit 1
fi
"$cc" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror "$tmp/escape_probe.c" -o "$tmp/escape-probe"
if "$runner" native-audit "$tmp/escape-probe" \
  >"$tmp/escape-out" 2>"$tmp/escape-error"; then
  echo 'validate-native-shim: native escape probe unexpectedly passed audit' >&2
  exit 1
fi
grep -Eq 'direct-syscall|unmanaged-thread' "$tmp/escape-error"
"$cc" -std=c11 -Wall -Wextra -Werror "$tmp/unknown_import_probe.c" -o "$tmp/unknown-import-probe"
if "$runner" native-audit "$tmp/unknown-import-probe" \
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
"$runner" native-build "$tmp/thread_probe.rs" --output "$tmp/thread-probe" >/dev/null
"$runner" native-run "$tmp/thread-probe" --seed 7 >"$tmp/thread-seed-1"
"$runner" native-run "$tmp/thread-probe" --seed 7 >"$tmp/thread-seed-2"
cmp "$tmp/thread-seed-1" "$tmp/thread-seed-2"
grep -q 'counter=12' "$tmp/thread-seed-1"
# The acquisition order must actually vary across seeds. Interleaving
# granularity differs by platform — macOS takes a scheduling point at every
# interposed lock, while on Linux uncontended locks are pure userspace atomics
# and only futex contention points interleave — so assert variation over a
# range of seeds rather than between two fixed ones.
thread_distinct=$(for s in 1 2 3 4 5 6; do
  "$runner" native-run "$tmp/thread-probe" --seed "$s"
done | sort -u | wc -l)
if [[ "$thread_distinct" -lt 2 ]]; then
  echo 'validate-native-shim: thread-probe order did not vary across seeds' >&2
  exit 1
fi
"$runner" native-run "$tmp/thread-probe" --seed 7 --record "$tmp/thread.patina" \
  --fingerprint native-thread-v1 >"$tmp/thread-record"
"$runner" native-run "$tmp/thread-probe" --seed 7 --record "$tmp/thread-repeat.patina" \
  --fingerprint native-thread-v1 >/dev/null
cmp "$tmp/thread.patina" "$tmp/thread-repeat.patina"
"$runner" native-run "$tmp/thread-probe" --replay "$tmp/thread.patina" \
  --fingerprint native-thread-v1 >"$tmp/thread-replay"
cmp "$tmp/thread-record" "$tmp/thread-replay"
cmp "$tmp/thread-seed-1" "$tmp/thread-replay"
if "$runner" native-run "$tmp/thread-probe" --replay "$tmp/thread.patina" \
  --fingerprint native-thread-other >/dev/null 2>&1; then
  echo 'validate-native-shim: thread-probe replay accepted a changed fingerprint' >&2
  exit 1
fi
# The pthread symbols are shim-provided (managed), so the thread probe audits
# clean under the same allowlist as the single-threaded probe, while a bare
# host pthread_create (the escape probe) is still denied as an unmanaged thread.
"$runner" native-audit "$tmp/thread-probe" "${shim_allow[@]}" >"$tmp/thread-imports"

# A std::sync::Mutex held across a boundary op while another thread contends:
# proves lock contention is routed through the scheduler (virtual mutex) and not
# a host kernel lock. `timeout` guards against a regression that reintroduces a
# real host lock (which would deadlock); seeded mode uses no trace descriptor,
# so timeout does not disturb the control plane.
"$runner" native-build "$tmp/contend_probe.rs" --output "$tmp/contend-probe" >/dev/null
contend_1=$(timeout 60 "$runner" native-run "$tmp/contend-probe" --seed 2)
contend_2=$(timeout 60 "$runner" native-run "$tmp/contend-probe" --seed 2)
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
"$runner" native-audit "$tmp/contend-probe" "${shim_allow[@]}" >/dev/null

# Ordinary std::net::UdpSocket datagrams over SimNet: workers send to a
# collector whose arrival order is scheduler-decided, so it is seed-stable and
# varies across seeds, and record/replay reproduces the exact ordering. The
# sockets are fully virtual, so the probe audits clean with no new allowance.
"$runner" native-build "$tmp/udp_probe.rs" --output "$tmp/udp-probe" >/dev/null
"$runner" native-run "$tmp/udp-probe" --seed 1 >"$tmp/udp-seed-1"
"$runner" native-run "$tmp/udp-probe" --seed 1 >"$tmp/udp-seed-2"
cmp "$tmp/udp-seed-1" "$tmp/udp-seed-2"
grep -Eq 'NATIVE_UDP_RESULT order=[012]{3}$' "$tmp/udp-seed-1"
# Delivery order is scheduler-decided; assert it varies across a seed range.
udp_distinct=$(for s in 1 2 3 4 5 6; do
  "$runner" native-run "$tmp/udp-probe" --seed "$s"
done | sort -u | wc -l)
if [[ "$udp_distinct" -lt 2 ]]; then
  echo 'validate-native-shim: udp-probe delivery order did not vary across seeds' >&2
  exit 1
fi
"$runner" native-run "$tmp/udp-probe" --seed 1 --record "$tmp/udp.patina" \
  --fingerprint native-udp-v1 >"$tmp/udp-record"
"$runner" native-run "$tmp/udp-probe" --replay "$tmp/udp.patina" \
  --fingerprint native-udp-v1 >"$tmp/udp-replay"
cmp "$tmp/udp-record" "$tmp/udp-replay"
cmp "$tmp/udp-seed-1" "$tmp/udp-replay"
"$runner" native-audit "$tmp/udp-probe" "${shim_allow[@]}" >/dev/null

# Deterministic descriptor duplication: File::try_clone routes through
# fcntl(F_DUPFD_CLOEXEC) to the recorded FsDup operation, and the duplicate
# shares the open-file cursor.
"$runner" native-build "$tmp/dup_probe.rs" --output "$tmp/dup-probe" >/dev/null
"$runner" native-audit "$tmp/dup-probe" "${shim_allow[@]}" >/dev/null
"$runner" native-run "$tmp/dup-probe" --seed 3 >"$tmp/dup-seed-1"
"$runner" native-run "$tmp/dup-probe" --seed 3 >"$tmp/dup-seed-2"
cmp "$tmp/dup-seed-1" "$tmp/dup-seed-2"
grep -qx 'NATIVE_DUP_RESULT head=abc rest=def mid=bc' "$tmp/dup-seed-1"
"$runner" native-run "$tmp/dup-probe" --seed 3 --record "$tmp/dup.patina" \
  --fingerprint native-dup-v1 >"$tmp/dup-record"
"$runner" native-run "$tmp/dup-probe" --replay "$tmp/dup.patina" \
  --fingerprint native-dup-v1 >"$tmp/dup-replay"
cmp "$tmp/dup-record" "$tmp/dup-replay"
cmp "$tmp/dup-seed-1" "$tmp/dup-replay"

# The deterministic environment is empty, including direct environ iteration.
# Host canaries (even PATINA_-prefixed ones) must not affect output or traces.
"$runner" native-build "$tmp/env_probe.rs" --output "$tmp/env-probe" >/dev/null
"$runner" native-audit "$tmp/env-probe" "${shim_allow[@]}" >/dev/null
PATINA_ENV_CANARY_HOST=one "$runner" native-run "$tmp/env-probe" --seed 3 >"$tmp/env-seed-1"
CANARY_HOST=two "$runner" native-run "$tmp/env-probe" --seed 3 >"$tmp/env-seed-2"
cmp "$tmp/env-seed-1" "$tmp/env-seed-2"
grep -qx 'NATIVE_ENV_RESULT vars=0' "$tmp/env-seed-1"
CANARY_HOST=one "$runner" native-run "$tmp/env-probe" --seed 3 --record "$tmp/env.patina" \
  --fingerprint native-env-v1 >"$tmp/env-record"
CANARY_HOST=two "$runner" native-run "$tmp/env-probe" --replay "$tmp/env.patina" \
  --fingerprint native-env-v1 >"$tmp/env-replay"
cmp "$tmp/env-record" "$tmp/env-replay"
cmp "$tmp/env-seed-1" "$tmp/env-replay"

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
// Imports a process-spawning libc symbol the audit denies as "process".
fn main() {
    let status = std::process::Command::new("/bin/true").status().unwrap();
    std::process::exit(status.code().unwrap_or(1));
}
RS

"$runner" native-build "$pkg/app" --bin patina-native-pkg --output "$tmp/pkg-probe" >/dev/null
"$runner" native-audit "$tmp/pkg-probe" "${shim_allow[@]}" >/dev/null
"$runner" native-run "$tmp/pkg-probe" --seed 5 >"$tmp/pkg-seed-1"
"$runner" native-run "$tmp/pkg-probe" --seed 5 >"$tmp/pkg-seed-2"
"$runner" native-run "$tmp/pkg-probe" --seed 6 >"$tmp/pkg-seed-other"
cmp "$tmp/pkg-seed-1" "$tmp/pkg-seed-2"
if cmp -s "$tmp/pkg-seed-1" "$tmp/pkg-seed-other"; then
  echo 'validate-native-shim: distinct pkg-probe seeds produced identical output' >&2
  exit 1
fi
grep -q 'built=1' "$tmp/pkg-seed-1"
grep -q 'stored=hello from greeter' "$tmp/pkg-seed-1"
"$runner" native-run "$tmp/pkg-probe" --seed 5 --record "$tmp/pkg.patina" \
  --fingerprint native-pkg-v1 >"$tmp/pkg-record"
"$runner" native-run "$tmp/pkg-probe" --replay "$tmp/pkg.patina" \
  --fingerprint native-pkg-v1 >"$tmp/pkg-replay"
cmp "$tmp/pkg-record" "$tmp/pkg-replay"
cmp "$tmp/pkg-seed-1" "$tmp/pkg-replay"

# Multiple binary targets with no --bin selection fails closed rather than
# guessing which binary to build.
if "$runner" native-build "$pkg/app" --output "$tmp/pkg-ambiguous" \
  >/dev/null 2>"$tmp/pkg-ambiguous-error"; then
  echo 'validate-native-shim: multi-bin package built without --bin selection' >&2
  exit 1
fi
grep -q 'multiple binary targets' "$tmp/pkg-ambiguous-error"

# A package binary whose build product imports an off-allowlist symbol builds
# but fails the audit with the existing category diagnostic.
"$runner" native-build "$pkg/app" --bin leaky --output "$tmp/pkg-leaky" >/dev/null
if "$runner" native-audit "$tmp/pkg-leaky" >/dev/null 2>"$tmp/pkg-leaky-error"; then
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

"$runner" native-build "$tmp/timed_wait_probe.rs" --output "$tmp/timed-wait-probe" >/dev/null
"$runner" native-audit "$tmp/timed-wait-probe" "${shim_allow[@]}" >/dev/null
for seed in 5 6; do
  "$runner" native-run "$tmp/timed-wait-probe" --seed "$seed" >"$tmp/timed-wait-seed-$seed-1"
  "$runner" native-run "$tmp/timed-wait-probe" --seed "$seed" >"$tmp/timed-wait-seed-$seed-2"
  cmp "$tmp/timed-wait-seed-$seed-1" "$tmp/timed-wait-seed-$seed-2"
  grep -qx 'NATIVE_TIMED_WAIT_RESULT signalled_elapsed_ns=25000000 timeout_elapsed_ns=100000000' \
    "$tmp/timed-wait-seed-$seed-1"
done
"$runner" native-run "$tmp/timed-wait-probe" --seed 5 --record "$tmp/timed-wait.patina" \
  --fingerprint native-timed-wait-v1 >"$tmp/timed-wait-record"
"$runner" native-run "$tmp/timed-wait-probe" --seed 5 --record "$tmp/timed-wait-repeat.patina" \
  --fingerprint native-timed-wait-v1 >/dev/null
cmp "$tmp/timed-wait.patina" "$tmp/timed-wait-repeat.patina"
"$runner" native-run "$tmp/timed-wait-probe" --replay "$tmp/timed-wait.patina" \
  --fingerprint native-timed-wait-v1 >"$tmp/timed-wait-replay"
cmp "$tmp/timed-wait-record" "$tmp/timed-wait-replay"
cmp "$tmp/timed-wait-seed-5-1" "$tmp/timed-wait-replay"

"$runner" native-build "$tmp/sleep_order_probe.rs" --output "$tmp/sleep-order-probe" >/dev/null
"$runner" native-audit "$tmp/sleep-order-probe" "${shim_allow[@]}" >/dev/null
for seed in 5 6; do
  "$runner" native-run "$tmp/sleep-order-probe" --seed "$seed" >"$tmp/sleep-order-seed-$seed-1"
  "$runner" native-run "$tmp/sleep-order-probe" --seed "$seed" >"$tmp/sleep-order-seed-$seed-2"
  cmp "$tmp/sleep-order-seed-$seed-1" "$tmp/sleep-order-seed-$seed-2"
  grep -Eq '^NATIVE_SLEEP_ORDER_RESULT order=(AB|BA) a_elapsed_ns=100000000 work=4950$' \
    "$tmp/sleep-order-seed-$seed-1"
done

"$runner" native-build "$tmp/udp_latency_probe.rs" --output "$tmp/udp-latency-probe" >/dev/null
"$runner" native-audit "$tmp/udp-latency-probe" "${shim_allow[@]}" >/dev/null
udp_latency_nanos=250000000
"$runner" native-run "$tmp/udp-latency-probe" --seed 5 \
  --net-latency-nanos "$udp_latency_nanos" >"$tmp/udp-latency-seed-5-1"
"$runner" native-run "$tmp/udp-latency-probe" --seed 5 \
  --net-latency-nanos "$udp_latency_nanos" >"$tmp/udp-latency-seed-5-2"
cmp "$tmp/udp-latency-seed-5-1" "$tmp/udp-latency-seed-5-2"
grep -qx 'NATIVE_UDP_LATENCY_RESULT elapsed_ns=250000000 payload=ping' \
  "$tmp/udp-latency-seed-5-1"
"$runner" native-run "$tmp/udp-latency-probe" --seed 5 \
  --net-latency-nanos "$udp_latency_nanos" --record "$tmp/udp-latency.patina" \
  --fingerprint native-udp-latency-v1 >"$tmp/udp-latency-record"
"$runner" native-run "$tmp/udp-latency-probe" --seed 5 \
  --net-latency-nanos "$udp_latency_nanos" --record "$tmp/udp-latency-repeat.patina" \
  --fingerprint native-udp-latency-v1 >/dev/null
cmp "$tmp/udp-latency.patina" "$tmp/udp-latency-repeat.patina"
"$runner" native-run "$tmp/udp-latency-probe" \
  --net-latency-nanos "$udp_latency_nanos" --replay "$tmp/udp-latency.patina" \
  --fingerprint native-udp-latency-v1 >"$tmp/udp-latency-replay"
cmp "$tmp/udp-latency-record" "$tmp/udp-latency-replay"
cmp "$tmp/udp-latency-seed-5-1" "$tmp/udp-latency-replay"
"$runner" native-run "$tmp/udp-latency-probe" --seed 5 \
  --net-latency-nanos 0 >"$tmp/udp-latency-zero-1"
"$runner" native-run "$tmp/udp-latency-probe" --seed 5 \
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

"$runner" native-build "$tmp/tcp_probe.rs" --output "$tmp/tcp-probe" >/dev/null
"$runner" native-audit "$tmp/tcp-probe" "${shim_allow[@]}" >/dev/null
for seed in 5 6; do
  "$runner" native-run "$tmp/tcp-probe" --seed "$seed" >"$tmp/tcp-seed-$seed-1"
  "$runner" native-run "$tmp/tcp-probe" --seed "$seed" >"$tmp/tcp-seed-$seed-2"
  cmp "$tmp/tcp-seed-$seed-1" "$tmp/tcp-seed-$seed-2"
  grep -qx 'NATIVE_TCP_RESULT reply=PING peer=127.0.0.1:49152 ipv6_closed=true dns_closed=true' \
    "$tmp/tcp-seed-$seed-1"
done
"$runner" native-run "$tmp/tcp-probe" --seed 5 --record "$tmp/tcp.patina" \
  --fingerprint native-tcp-v1 >"$tmp/tcp-record"
"$runner" native-run "$tmp/tcp-probe" --seed 5 --record "$tmp/tcp-repeat.patina" \
  --fingerprint native-tcp-v1 >/dev/null
cmp "$tmp/tcp.patina" "$tmp/tcp-repeat.patina"
"$runner" native-run "$tmp/tcp-probe" --replay "$tmp/tcp.patina" \
  --fingerprint native-tcp-v1 >"$tmp/tcp-replay"
cmp "$tmp/tcp-record" "$tmp/tcp-replay"
cmp "$tmp/tcp-seed-5-1" "$tmp/tcp-replay"

cat "$tmp/replay"
cat "$tmp/std-replay"
cat "$tmp/tcp-replay"
