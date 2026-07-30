#!/usr/bin/env bash
set -euo pipefail

# One ordinary-std Rust smoke program, built for every Patina target this host
# supports: the wasm32-wasip1 WASI target and the native (macOS/Linux) linked
# shim. Each target runs seeded smoke tests with recorded and replayable
# traces, and the deterministic program output must match across targets.

help() {
  cat <<'EOF'
smoke-cross-target.sh — cross-target deterministic-output smoke test.

Builds ONE ordinary-std Rust smoke program for every Patina target this host
supports (wasm32-wasip1 WASI and the native macOS/Linux linked shim), runs seeded
smoke tests with record/replay on each, and asserts the deterministic SMOKE_RESULT
(including a pinned seeded-entropy anchor) is byte-identical across seeds, across
record vs replay, across cold vs warm build cache, and ACROSS targets.

Usage: smoke-cross-target.sh [-h|--help]

Takes no positional arguments. Requires the wasm32-wasip1 target
(rustup target add wasm32-wasip1) and a C compiler.

Environment:
  CARGO_TARGET_DIR   override the Cargo target directory (default <repo>/target).
  CC                 C compiler to use (default cc).

Exit status: 0 = cross-target determinism validated; 1 = a determinism/entropy
check failed; 2 = usage error or a missing prerequisite (target/compiler).
EOF
}
case "${1:-}" in
  -h|--help) help; exit 0 ;;
  "") ;;
  *) echo "smoke-cross-target.sh: unexpected argument '$1' (takes no positional arguments; see --help)" >&2; exit 2 ;;
esac

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

cargo build --locked --manifest-path "$root/Cargo.toml" -p cargo-patina -p patina-dst-native-shim >/dev/null
runner="$target_dir/debug/cargo-patina"

# --- WASI target: seeded smoke plus record/replay ---
rustc --edition 2024 --target wasm32-wasip1 "$tmp/smoke.rs" -o "$tmp/smoke.wasm"
"$runner" audit "$tmp/smoke.wasm" >/dev/null
"$runner" run "$tmp/smoke.wasm" --seed 123 >"$tmp/wasi-seed-1"
"$runner" run "$tmp/smoke.wasm" --seed 123 >"$tmp/wasi-seed-2"
"$runner" run "$tmp/smoke.wasm" --seed 124 >"$tmp/wasi-seed-other"
cmp "$tmp/wasi-seed-1" "$tmp/wasi-seed-2"
if cmp -s "$tmp/wasi-seed-1" "$tmp/wasi-seed-other"; then
  echo 'smoke-cross-target: distinct WASI seeds produced identical output' >&2
  exit 1
fi
"$runner" run "$tmp/smoke.wasm" --seed 123 --record "$tmp/wasi.patina" >"$tmp/wasi-record"
"$runner" replay "$tmp/smoke.wasm" "$tmp/wasi.patina" >"$tmp/wasi-replay"
cmp "$tmp/wasi-record" "$tmp/wasi-replay"
cmp "$tmp/wasi-seed-1" "$tmp/wasi-replay"

# --- Native target: the same source built and driven by the packaged target ---
"$runner" build "$tmp/smoke.rs" --output "$tmp/smoke-native" >/dev/null
# Shim control-plane symbols are --allow'ed per binary rather than statically
# allowlisted (see validate-native-shim.sh for the full rationale). Post
# host-alias doctrine the control plane is a single symbol on both platforms: the
# shim's dlsym resolution primitive. Every former named vehicle (suspended-thread
# create, Mach/POSIX semaphores, $NOCANCEL/__ I/O, and — on Linux —
# `pthread_create`, now interposed by a plain strong def with its real creator
# resolved through the same dlsym table) is resolved at runtime by the shim and
# must stay DENIED for guest binaries, so none is allowlisted here.
control_plane=(
  --allow dlsym
)
"$runner" audit "$tmp/smoke-native" "${control_plane[@]}" >/dev/null
"$runner" run "$tmp/smoke-native" --seed 123 >"$tmp/native-seed-1"
"$runner" run "$tmp/smoke-native" --seed 123 >"$tmp/native-seed-2"
"$runner" run "$tmp/smoke-native" --seed 124 >"$tmp/native-seed-other"
cmp "$tmp/native-seed-1" "$tmp/native-seed-2"
if cmp -s "$tmp/native-seed-1" "$tmp/native-seed-other"; then
  echo 'smoke-cross-target: distinct native seeds produced identical output' >&2
  exit 1
fi
"$runner" run "$tmp/smoke-native" --seed 123 --record "$tmp/native.patina" \
  --fingerprint smoke-native-v1 >"$tmp/native-record"
"$runner" replay "$tmp/smoke-native" "$tmp/native.patina" \
  --fingerprint smoke-native-v1 >"$tmp/native-replay"
cmp "$tmp/native-record" "$tmp/native-replay"
cmp "$tmp/native-seed-1" "$tmp/native-replay"

# --- R20 config-differential double-run: build-cache cold vs warm ---
# Rebuild the SAME source a second time (now against a warm cargo cache) and
# re-record at the same seed through a fresh supervisor process. The recorded
# trace must be byte-identical to the cold-cache build's, and so must the
# SMOKE_RESULT line. This closes the gap the same-process/same-binary repeats
# above leave open: it proves that neither the build-cache state nor an
# independent build+record invocation perturbs the deterministic result or the
# trace bytes (debug-info timestamps may differ in the binary; the observable
# behavior and the trace must not).
"$runner" build "$tmp/smoke.rs" --output "$tmp/smoke-native-warm" >/dev/null
"$runner" run "$tmp/smoke-native-warm" --seed 123 --record "$tmp/native-warm.patina" \
  --fingerprint smoke-native-v1 >"$tmp/native-warm-record"
cmp "$tmp/native.patina" "$tmp/native-warm.patina"
grep '^SMOKE_RESULT ' "$tmp/native-record" >"$tmp/native-cold-line"
grep '^SMOKE_RESULT ' "$tmp/native-warm-record" >"$tmp/native-warm-line"
cmp "$tmp/native-cold-line" "$tmp/native-warm-line"

# --- Cross-target: the deterministic program output must match ---
grep '^SMOKE_RESULT ' "$tmp/wasi-replay" >"$tmp/wasi-line"
grep '^SMOKE_RESULT ' "$tmp/native-replay" >"$tmp/native-line"
cmp "$tmp/wasi-line" "$tmp/native-line"

# Canonical entropy anchor. Every check above is purely DIFFERENTIAL (native vs
# wasi, seed vs seed, record vs replay, cold vs warm): a drift that shifts the
# seeded entropy IDENTICALLY on both targets -- an RNG-algorithm or seeding
# change -- keeps every cmp equal and passes silently. Pin the exact literal so
# any change to the observable seeded entropy fails loudly here with the observed
# value. The hash is platform-invariant by design (the seeded RNG is
# deterministic across targets); if a platform ever disagrees, THAT is the bug
# this gate exists to catch. An intentional entropy-affecting change MUST update
# this literal deliberately -- that friction is the point, the same discipline as
# the workq canonical outcome hash and the record/replay identity above.
canonical_entropy='entropy_hash=2d4cdb668affa7b2'
for tgt in wasi native; do
  if ! grep -qF "$canonical_entropy" "$tmp/$tgt-line"; then
    echo "smoke-cross-target: $tgt SMOKE_RESULT entropy drift -- expected $canonical_entropy, observed:" >&2
    cat "$tmp/$tgt-line" >&2
    exit 1
  fi
done

echo "Cross-target deterministic output ($(uname -s) + wasm32-wasip1):"
cat "$tmp/native-line"
