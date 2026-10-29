#!/usr/bin/env bash
set -euo pipefail

# One ordinary-std Rust smoke program, built against the native (macOS/Linux)
# linked shim, runs seeded smoke tests with recorded and replayable traces, and
# its deterministic program output must match a pinned anchor.

help() {
  cat <<'EOF'
smoke-native.sh — native deterministic-output smoke test.

Builds ONE ordinary-std Rust smoke program against the native macOS/Linux linked
shim, runs seeded smoke tests with record/replay, and asserts the deterministic
SMOKE_RESULT (including a pinned seeded-entropy anchor) is byte-identical across
repeated seeds, across record vs replay, and across cold vs warm build cache.

Usage: smoke-native.sh [-h|--help]

Takes no positional arguments. Requires a C compiler.

Environment:
  CARGO_TARGET_DIR   override the Cargo target directory (default <repo>/target).
  PATINA_CLI         a cargo-patina built from this checkout, used instead of
                     building the release CLI.
  CC                 C compiler to use (default cc).

Exit status: 0 = determinism validated; 1 = a determinism/entropy check failed;
2 = usage error or a missing prerequisite (compiler).
EOF
}
case "${1:-}" in
  -h|--help) help; exit 0 ;;
  "") ;;
  *) echo "smoke-native.sh: unexpected argument '$1' (takes no positional arguments; see --help)" >&2; exit 2 ;;
esac

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target_dir=${CARGO_TARGET_DIR:-$root/target}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cc=${CC:-cc}
if ! command -v "$cc" >/dev/null 2>&1; then
  echo "smoke-native: C compiler not found: $cc" >&2
  exit 2
fi

cat >"$tmp/smoke.rs" <<'RS'
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

unsafe extern "C" {
    fn patina_init_from_env() -> i32;
    fn patina_shutdown() -> i32;
}

fn main() {
    if unsafe { patina_init_from_env() } != 0 {
        std::process::exit(20);
    }

    let epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let started = Instant::now();
    std::thread::sleep(Duration::from_millis(7));
    // In milliseconds: the guest's calls cost virtual time (nanoseconds each),
    // which the anchor should not pin.
    let slept_ms = started.elapsed().as_millis();

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
        "SMOKE_RESULT epoch_ms={epoch_ms} slept_ms={slept_ms} \
entropy_hash={entropy_hash:016x} tail={tail} len={len}"
    );

    if unsafe { patina_shutdown() } != 0 {
        std::process::exit(21);
    }
}
RS

# Drive the guest with the optimized supervisor used by the other core
# validation scripts, or the CLI the caller built from this checkout
# (PATINA_CLI).
if [[ -n ${PATINA_CLI:-} ]]; then
  runner=$PATINA_CLI
else
  cargo build --release --locked --manifest-path "$root/Cargo.toml" -p cargo-patina >/dev/null
  runner="$target_dir/release/cargo-patina"
fi
if [[ ! -x $runner ]]; then
  echo "smoke-native: $runner is not an executable cargo-patina" >&2
  exit 2
fi

# --- Seeded smoke plus record/replay ---
"$runner" build "$tmp/smoke.rs" --output "$tmp/smoke-native" >/dev/null
# Shim control-plane symbols are --allow'ed per binary rather than statically
# allowlisted (see testbeds/native-boundary/README.md for the native test map). Post
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
  echo 'smoke-native: distinct native seeds produced identical output' >&2
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

grep '^SMOKE_RESULT ' "$tmp/native-replay" >"$tmp/native-line"

# Canonical entropy anchor. Every check above is purely DIFFERENTIAL (seed vs
# seed, record vs replay, cold vs warm): a drift that shifts the seeded entropy
# IDENTICALLY everywhere -- an RNG-algorithm or seeding change -- keeps every cmp
# equal and passes silently. Pin the exact literal so any change to the
# observable seeded entropy fails loudly here with the observed value. The hash
# is platform-invariant by design (the seeded RNG is deterministic across
# platforms); if a platform ever disagrees, THAT is the bug this gate exists to
# catch. An intentional entropy-affecting change MUST update
# this literal deliberately -- that friction is the point, the same discipline as
# the workq canonical outcome hash and the record/replay identity above.
canonical_entropy='entropy_hash=0e3b7fa3c0b2dbb9'
if ! grep -qF "$canonical_entropy" "$tmp/native-line"; then
  echo "smoke-native: SMOKE_RESULT entropy drift -- expected $canonical_entropy, observed:" >&2
  cat "$tmp/native-line" >&2
  exit 1
fi

echo "Native smoke: PASS ($(uname -s))"
