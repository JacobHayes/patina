#!/usr/bin/env bash
set -euo pipefail

# One ordinary-std Rust smoke program, built for every Patina target this host
# supports: the wasm32-wasip1 WASI target and the native (macOS/Linux) linked
# shim. Each target runs seeded smoke tests with recorded and replayable
# traces, and the deterministic program output must match across targets.

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target_dir=${CARGO_TARGET_DIR:-$root/target}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if ! rustup target list --installed | grep -qx wasm32-wasip1; then
  echo 'smoke-cross-target: install the required target with: rustup target add wasm32-wasip1' >&2
  exit 2
fi
cc=${CC:-cc}
if ! command -v "$cc" >/dev/null 2>&1; then
  echo "smoke-cross-target: C compiler not found: $cc" >&2
  exit 2
fi

cat >"$tmp/smoke.rs" <<'RS'
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(not(target_os = "wasi"))]
unsafe extern "C" {
    fn patina_init_from_env() -> i32;
    fn patina_shutdown() -> i32;
}

fn main() {
    #[cfg(not(target_os = "wasi"))]
    if unsafe { patina_init_from_env() } != 0 {
        std::process::exit(20);
    }

    let epoch_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let started = Instant::now();
    std::thread::sleep(Duration::from_millis(7));
    let slept_ns = started.elapsed().as_nanos();

    let mut hasher = RandomState::new().build_hasher();
    hasher.write(b"patina-smoke");
    let entropy_hash = hasher.finish();

    std::fs::create_dir("/smoke").unwrap();
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open("/smoke/log")
        .unwrap();
    file.write_all(b"deterministic-payload").unwrap();
    file.sync_all().unwrap();
    file.seek(SeekFrom::Start(14)).unwrap();
    let mut tail = String::new();
    file.read_to_string(&mut tail).unwrap();
    drop(file);
    std::fs::rename("/smoke/log", "/smoke/renamed").unwrap();
    let len = std::fs::metadata("/smoke/renamed").unwrap().len();
    std::fs::remove_file("/smoke/renamed").unwrap();
    std::fs::remove_dir("/smoke").unwrap();

    println!(
        "SMOKE_RESULT epoch_ns={epoch_ns} slept_ns={slept_ns} \
entropy_hash={entropy_hash:016x} tail={tail} len={len}"
    );

    #[cfg(not(target_os = "wasi"))]
    if unsafe { patina_shutdown() } != 0 {
        std::process::exit(21);
    }
}
RS

cargo build --locked --manifest-path "$root/Cargo.toml" -p cargo-patina -p patina-native-shim >/dev/null
runner="$target_dir/debug/cargo-patina"

# --- WASI target: seeded smoke plus record/replay ---
rustc --edition 2024 --target wasm32-wasip1 "$tmp/smoke.rs" -o "$tmp/smoke.wasm"
"$runner" wasi-audit "$tmp/smoke.wasm" >/dev/null
"$runner" wasi-run "$tmp/smoke.wasm" --seed 123 >"$tmp/wasi-seed-1"
"$runner" wasi-run "$tmp/smoke.wasm" --seed 123 >"$tmp/wasi-seed-2"
"$runner" wasi-run "$tmp/smoke.wasm" --seed 124 >"$tmp/wasi-seed-other"
cmp "$tmp/wasi-seed-1" "$tmp/wasi-seed-2"
if cmp -s "$tmp/wasi-seed-1" "$tmp/wasi-seed-other"; then
  echo 'smoke-cross-target: distinct WASI seeds produced identical output' >&2
  exit 1
fi
"$runner" wasi-run "$tmp/smoke.wasm" --seed 123 --record "$tmp/wasi.patina" >"$tmp/wasi-record"
"$runner" wasi-run "$tmp/smoke.wasm" --replay "$tmp/wasi.patina" >"$tmp/wasi-replay"
cmp "$tmp/wasi-record" "$tmp/wasi-replay"
cmp "$tmp/wasi-seed-1" "$tmp/wasi-replay"

# --- Native target: the same source built and driven by the packaged target ---
"$runner" native-build "$tmp/smoke.rs" --output "$tmp/smoke-native" >/dev/null
# Shim control-plane symbols are --allow'ed per binary rather than statically
# allowlisted (see validate-native-shim.sh for the full rationale).
if [[ "$(uname -s)" == Darwin ]]; then
  control_plane=(
    --allow '_read$NOCANCEL' --allow '_write$NOCANCEL'
    --allow pthread_create_suspended_np --allow pthread_mach_thread_np
    --allow thread_resume
    --allow semaphore_create --allow semaphore_wait
    --allow semaphore_signal --allow mach_task_self_
  )
else
  control_plane=(
    --allow dlsym --allow pthread_create
  )
fi
"$runner" native-audit "$tmp/smoke-native" "${control_plane[@]}" >/dev/null
"$runner" native-run "$tmp/smoke-native" --seed 123 >"$tmp/native-seed-1"
"$runner" native-run "$tmp/smoke-native" --seed 123 >"$tmp/native-seed-2"
"$runner" native-run "$tmp/smoke-native" --seed 124 >"$tmp/native-seed-other"
cmp "$tmp/native-seed-1" "$tmp/native-seed-2"
if cmp -s "$tmp/native-seed-1" "$tmp/native-seed-other"; then
  echo 'smoke-cross-target: distinct native seeds produced identical output' >&2
  exit 1
fi
"$runner" native-run "$tmp/smoke-native" --seed 123 --record "$tmp/native.patina" \
  --fingerprint smoke-native-v1 >"$tmp/native-record"
"$runner" native-run "$tmp/smoke-native" --replay "$tmp/native.patina" \
  --fingerprint smoke-native-v1 >"$tmp/native-replay"
cmp "$tmp/native-record" "$tmp/native-replay"
cmp "$tmp/native-seed-1" "$tmp/native-replay"

# --- Cross-target: the deterministic program output must match ---
grep '^SMOKE_RESULT ' "$tmp/wasi-replay" >"$tmp/wasi-line"
grep '^SMOKE_RESULT ' "$tmp/native-replay" >"$tmp/native-line"
cmp "$tmp/wasi-line" "$tmp/native-line"

echo "Cross-target deterministic output ($(uname -s) + wasm32-wasip1):"
cat "$tmp/native-line"
