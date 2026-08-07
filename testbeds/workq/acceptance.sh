#!/usr/bin/env bash
###############################################################################
# workq -- the unified-fault-knobs arc's acceptance demo (docs/arcs/
# unified-fault-knobs.md:543): "a campaign over a storage+network testbed with
# --faults --swarm shows fs/dns-fault generations firing (non-vacuous
# reports), at least one planted-bug class ... caught and minimized, and
# flag-free replay of a failing generation."
#
# This script proves five things end to end against ONE `cargo patina
# campaign` run over workq with the planted `--bug ignore-short-write`
# (testbeds/workq/src/wal.rs) enabled:
#   [a-fs]  a generation fired the fs-short fault non-vacuously
#           (PATINA_FS_FAULT_REPORT shorts_applied>0)
#   [a-dns] a generation fired a dns fault non-vacuously
#           (PATINA_DNS_FAULT_REPORT resolutions>0 with an injected effect)
#   [b]     the planted bug was caught: a WORKQ_VIOLATION or the recovery
#           gate's `WORKQ_ABORT ... wal corruption` fail-closed abort, WITH
#           shorts_applied>0 in the SAME generation (see the [b] comment below
#           for why the shorts_applied>0 requirement is load-bearing, not
#           incidental)
#   [c]     `cargo patina minimize` shrinks the catching trace and the
#           minimized trace still reproduces the same marker
#   [d]     flag-free `cargo patina replay` (no fault flags -- the trace is
#           self-contained) reproduces the violation byte-identically
#
# workq otherwise has NO DNS surface at all: every socket address in
# producer.rs/worker.rs/main.rs is a literal 127.0.0.1 numeric address, so a
# campaign DNS band has nothing to apply to by default. This script exercises
# the guest's `--server-host NAME` option (producers/workers resolve
# `NAME:port` once at thread startup, see wire::resolve_server_host) together
# with the campaign's `--dns-entry NAME=127.0.0.1` host table, giving the DNS
# fault plane a real call site.
#
# Exit nonzero on ANY unmet criterion (see the PASS/FAIL table at the end).
###############################################################################
set -uo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
acceptance.sh -- unified-fault-knobs arc acceptance demo over workq.

Usage: acceptance.sh [--help]

Builds cargo-patina + the workq harness, runs one `cargo patina campaign
--faults --swarm` sweep with `--bug ignore-short-write` enabled, then proves:
  a generation fired fs faults non-vacuously, a generation fired dns faults
  non-vacuously, the planted bug was caught, `cargo patina minimize` shrinks
  the catching trace and it still reproduces, and a flag-free `cargo patina
  replay` reproduces the violation byte-identically.

Env overrides:
  WORKQ_ACCEPTANCE_GENS   campaign generation count (default 40)
  PATINA_ALLOW_SYMS       forwarded to --allow-unsupported-symbols (escape
                          hatch for a transient unclassified-symbol gap)

Exits nonzero if any of the five criteria is unmet; the failure names which
one and why.
EOF
  exit 0
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
built="$here/target/patina/workq"
PATINA="$repo_root/target/release/cargo-patina"

ALLOW=()
if [[ -n "${PATINA_ALLOW_SYMS:-}" ]]; then
  ALLOW=(--allow-unsupported-symbols "$PATINA_ALLOW_SYMS")
fi

GENS="${WORKQ_ACCEPTANCE_GENS:-40}"

cd "$repo_root"
echo "==> building cargo-patina and the workq harness under Patina"
if ! cargo build --release --quiet -p cargo-patina; then
  echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
fi
if ! mkdir -p "$here/target/patina"; then
  echo "FATAL: mkdir $here/target/patina failed" >&2; exit 3
fi
if ! "$PATINA" patina build "$here" --output "$built" --release >/dev/null; then
  echo "FATAL: patina build of the workq harness failed" >&2; exit 3
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0
declare -a CRITERIA_LINES=()
record() { CRITERIA_LINES+=("$1"); } # criterion: PASS/FAIL evidence-or-reason

run() { "$PATINA" patina run "$built" "$@"; }
replay() { "$PATINA" patina replay "$built" "$@"; }

# Tiny, fast workload: small enough that campaign traces stay in the
# hundreds-of-decisions range (`cargo patina minimize` is oracle-call-bound --
# a 24-job/3-worker trace runs ~10k scheduling decisions and minimize takes
# many minutes; jobs=2/workers=1/producers=1 keeps the WAL/durability surface
# this bug needs while keeping the demo bounded). --server-host names the
# server so producers/workers actually resolve it (see wire::resolve_server_host)
# instead of dialing 127.0.0.1 directly -- the DNS band's only real call site.
SERVER_HOST=workq-server
HARGS=(--seed 7 --jobs 2 --workers 1 --producers 1 --base-port 5001
       --data-dir /workq --timeout-secs 30 --server-host "$SERVER_HOST")

OUT="$work/campaign-out"
echo "==> [1] cargo patina campaign --faults --swarm --gens $GENS (--bug ignore-short-write, --dns-entry $SERVER_HOST)"
campaign_json="$work/campaign.json"
campaign_err="$work/campaign.err"
"$PATINA" patina campaign "$built" --gens "$GENS" --out-dir "$OUT" --faults --swarm \
  --dns-entry "$SERVER_HOST=127.0.0.1" \
  --format json ${ALLOW[@]+"${ALLOW[@]}"} \
  -- "${HARGS[@]}" --bug ignore-short-write \
  >"$campaign_json" 2>"$campaign_err" || true

if ! python3 -c "import json; json.load(open('$campaign_json'))" 2>/dev/null; then
  echo "FATAL: campaign did not emit a valid JSON envelope" >&2
  echo "--- campaign stderr ---" >&2; cat "$campaign_err" >&2
  exit 3
fi

classes_line="$(python3 -c "
import json
d = json.load(open('$campaign_json'))
print('generations=%s classes=%s' % (d.get('generations'), d.get('classes')))
")"
echo "    $classes_line"

# ---------------------------------------------------------------------------
# [b] catch: scan VIOLATION- and UNCLASSIFIED-classified generations (in
# generation order -- deterministic, gens are a pure function of the spec) for
# the planted bug's SPECIFIC signature: a WORKQ_VIOLATION or a
# `WORKQ_ABORT ... wal corruption` marker (the two ways a torn short write
# surfaces, see wal.rs) TOGETHER WITH PATINA_FS_FAULT_REPORT shorts_applied>0
# in the SAME generation.
#
# shorts_applied>0 is required, not just the marker text, because red-proofing
# this script surfaced an UNRELATED pre-existing workq defect: a plain
# fs-error (shorts_applied=0) can also leave an acked job's Enqueue record
# missing from the durable WAL while the worker still phantom-applies it --
# reproducible even with --bug unset and even without this arc's
# --server-host/--dns-entry changes, so it predates and is independent of both.
# It happens to land a WORKQ_VIOLATION with matching "durability
# acked-job-N-missing-from-wal" TEXT at a fixed generation in this exact
# campaign shape, so marker-text matching alone would have silently accepted
# that unrelated bug's catch as "the planted bug caught". Filed as a separate
# finding for follow-up; not fixed here (out of this unit's scope).
# ---------------------------------------------------------------------------
candidate_gens=()
while IFS= read -r g; do
  [[ -n "$g" ]] && candidate_gens+=("$g")
done < <(python3 -c "
import json
d = json.load(open('$campaign_json'))
gens = sorted(r['generation'] for r in d.get('notable_runs', []) if r['class'] in ('VIOLATION', 'UNCLASSIFIED'))
print('\n'.join(str(g) for g in gens))
")

catch_gen=""
catch_marker=""
catch_err="$work/catch.err"
for g in ${candidate_gens[@]+"${candidate_gens[@]}"}; do
  trace="$OUT/failures/generation-$g.patina"
  [[ -f "$trace" ]] || continue
  err="$(replay "$trace" ${ALLOW[@]+"${ALLOW[@]}"} 2>&1 >/dev/null)"
  marker="$(printf '%s\n' "$err" | grep -m1 -E 'WORKQ_VIOLATION|WORKQ_ABORT final-wal wal corruption' || true)"
  [[ -n "$marker" ]] || continue
  fs_line="$(printf '%s\n' "$err" | grep -m1 'PATINA_FS_FAULT_REPORT' || true)"
  shorts="$(printf '%s' "$fs_line" | grep -o 'shorts_applied=[0-9]*' | cut -d= -f2)"
  if [[ "${shorts:-0}" -gt 0 ]]; then
    catch_gen="$g"; catch_marker="$marker"
    printf '%s' "$err" > "$catch_err"
    break
  fi
done

if [[ -z "$catch_gen" ]]; then
  echo "    FAIL: no generation shows a WORKQ_VIOLATION/wal-corruption marker WITH shorts_applied>0 in $GENS generations -- planted bug NOT caught"
  record "b-catch: FAIL (no generation with a violation/corruption marker AND shorts_applied>0 in $GENS gens)"
  fail=1
else
  trace="$OUT/failures/generation-$catch_gen.patina"
  echo "    caught: generation $catch_gen -- $catch_marker"
  record "b-catch: PASS (generation $catch_gen: $catch_marker)"

  # -------------------------------------------------------------------
  # [a-fs] non-vacuous fs-fault firing, read off the SAME catching
  # generation's fs report (shorts_applied>0 already confirmed above).
  # -------------------------------------------------------------------
  fs_line="$(grep -m1 'PATINA_FS_FAULT_REPORT' "$catch_err" || true)"
  echo "    fs non-vacuous: generation $catch_gen -- $fs_line"
  record "a-fs: PASS (generation $catch_gen: $fs_line)"
fi

# ---------------------------------------------------------------------------
# [a-dns] non-vacuous dns-fault firing. Scan every saved failing trace's
# replay for a PATINA_DNS_FAULT_REPORT line with a real injected effect (a
# failure OR a latency application -- --faults bands both dns-fail-permille
# and dns-latency-nanos once --dns-entry is supplied, and either is a genuine
# fire, not just the other).
# ---------------------------------------------------------------------------
dns_fired=0
dns_evidence=""
for f in "$OUT"/failures/*.patina; do
  [[ -e "$f" ]] || continue
  err="$(replay "$f" ${ALLOW[@]+"${ALLOW[@]}"} 2>&1 >/dev/null)"
  line="$(printf '%s\n' "$err" | grep -m1 'PATINA_DNS_FAULT_REPORT' || true)"
  if [[ -n "$line" ]]; then
    resolutions="$(printf '%s' "$line" | grep -o 'resolutions=[0-9]*' | cut -d= -f2)"
    failures_injected="$(printf '%s' "$line" | grep -o 'failures_injected=[0-9]*' | cut -d= -f2)"
    latency_applied="$(printf '%s' "$line" | grep -o 'latency_applied=[0-9]*' | cut -d= -f2)"
    if [[ "${resolutions:-0}" -gt 0 && ( "${failures_injected:-0}" -gt 0 || "${latency_applied:-0}" -gt 0 ) ]]; then
      dns_fired=1; dns_evidence="generation $(basename "$f" .patina): $line"
      break
    fi
  fi
done
if [[ "$dns_fired" -eq 1 ]]; then
  echo "    dns non-vacuous: $dns_evidence"
  record "a-dns: PASS ($dns_evidence)"
else
  echo "    FAIL: no generation shows a non-vacuous PATINA_DNS_FAULT_REPORT"
  echo "          (resolutions>0 with a failure or latency effect applied) --"
  echo "          named loudly rather than papered over."
  record "a-dns: FAIL (no generation showed a non-vacuous PATINA_DNS_FAULT_REPORT)"
  fail=1
fi

# ---------------------------------------------------------------------------
# [c] minimize: shrink the catching trace; the minimized trace must still
# reproduce the SAME violation via the replay oracle.
# ---------------------------------------------------------------------------
if [[ -n "$catch_gen" && -f "$OUT/failures/generation-$catch_gen.patina" ]]; then
  oracle="$work/oracle.sh"
  cat > "$oracle" <<'ORACLE'
#!/usr/bin/env bash
# Minimize oracle. `cargo patina minimize` sets PATINA_MINIMIZE_TRACE to the
# candidate trace path. Args: PATINA_BIN WORKQ_BIN [ALLOW...]. Exit nonzero
# (the catching marker is still present) means "keep this candidate, still
# fails"; exit 0 means the candidate lost the failure. Matches either surface
# of the planted bug: a WORKQ_VIOLATION or the recovery-gate's
# `WORKQ_ABORT ... wal corruption` fail-closed abort.
set -uo pipefail
PATINA="$1"; BIN="$2"; shift 2
err="$("$PATINA" patina replay "$BIN" "$PATINA_MINIMIZE_TRACE" "$@" 2>&1 >/dev/null)"
printf '%s' "$err" | grep -qE 'WORKQ_VIOLATION|WORKQ_ABORT final-wal wal corruption' && exit 1
exit 0
ORACLE
  chmod +x "$oracle"

  min_trace="$work/minimized.patina"
  min_out="$work/minimize.out"
  "$PATINA" patina minimize "$OUT/failures/generation-$catch_gen.patina" \
    --output "$min_trace" \
    -- "$oracle" "$PATINA" "$built" ${ALLOW[@]+"${ALLOW[@]}"} \
    >"$min_out" 2>&1
  min_code=$?
  min_line="$(grep -m1 'PATINA_MINIMIZE_COMPLETE' "$min_out" || true)"
  if [[ $min_code -ne 0 || -z "$min_line" || ! -f "$min_trace" ]]; then
    echo "    FAIL: minimize did not complete (exit=$min_code)"
    cat "$min_out"
    record "c-minimize: FAIL (exit=$min_code)"
    fail=1
  else
    echo "    $min_line"
    min_err="$work/min-replay.err"
    replay "$min_trace" ${ALLOW[@]+"${ALLOW[@]}"} >"$work/min-replay.out" 2>"$min_err"
    min_marker="$(grep -m1 -E 'WORKQ_VIOLATION|WORKQ_ABORT final-wal wal corruption' "$min_err" || true)"
    if [[ -z "$min_marker" ]]; then
      echo "    FAIL: minimized trace no longer reproduces the catching marker"
      record "c-minimize: FAIL (minimized trace lost the violation)"
      fail=1
    else
      echo "    minimized trace still reproduces: $min_marker"
      record "c-minimize: PASS ($min_line; still reproduces: $min_marker)"
    fi

    # -----------------------------------------------------------------
    # [d] flag-free replay: NO fault/campaign flags, just the trace --
    # two independent replays must agree byte-for-byte.
    # -----------------------------------------------------------------
    r1_out="$work/ff1.out"; r1_err="$work/ff1.err"
    r2_out="$work/ff2.out"; r2_err="$work/ff2.err"
    replay "$min_trace" ${ALLOW[@]+"${ALLOW[@]}"} >"$r1_out" 2>"$r1_err"
    c1=$?
    replay "$min_trace" ${ALLOW[@]+"${ALLOW[@]}"} >"$r2_out" 2>"$r2_err"
    c2=$?
    if [[ $c1 -ne $c2 ]] || ! diff -q "$r1_out" "$r2_out" >/dev/null || ! diff -q "$r1_err" "$r2_err" >/dev/null; then
      echo "    FAIL: flag-free replay is not byte-identical across two runs (exit $c1 vs $c2)"
      record "d-replay: FAIL (not byte-identical: exit $c1 vs $c2)"
      fail=1
    else
      result="$(grep -m1 'WORKQ_RESULT' "$r1_out" || true)"
      echo "    flag-free replay byte-identical (exit=$c1): $result"
      record "d-replay: PASS (flag-free, byte-identical, exit=$c1: $result)"
    fi
  fi
else
  echo "    SKIP: minimize/replay legs skipped -- no catching generation to minimize"
  record "c-minimize: FAIL (no catching generation)"
  record "d-replay: FAIL (no catching generation)"
  fail=1
fi

echo
echo "==> criteria"
for line in "${CRITERIA_LINES[@]}"; do echo "    $line"; done
echo

if [[ $fail -eq 0 ]]; then
  echo "PASS: unified-fault-knobs arc acceptance -- fs non-vacuous, dns non-vacuous, planted bug caught, minimized, flag-free replay byte-identical"
else
  echo "FAIL: unified-fault-knobs arc acceptance NOT fully met (see criteria above)"
fi
exit $fail
