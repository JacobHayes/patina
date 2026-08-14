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
#   [b]     the planted bug was caught: a `violation` VERDICT in the run
#           envelope (both surfaces of a torn short write report one -- the
#           durability/no-loss audit and the recovery gate's `wal-integrity`),
#           WITH fs shorts_applied>0 in the SAME generation (see the [b]
#           comment below for why the shorts_applied>0 requirement is
#           load-bearing, not incidental)
#   [c]     `cargo patina minimize --generation` reduces the catching
#           generation with NO hand-written oracle and NO --marker -- it
#           targets the verdicts the campaign recorded for that generation --
#           and the minimized trace still reports the violation verdict
#   [d]     flag-free `cargo patina replay` (no fault flags -- the trace is
#           self-contained) reproduces the violation byte-identically,
#           verdict events included
#
# Every criterion above reads the run's `patina.result/v1` envelope -- verdicts
# and the per-plane fault accounting -- rather than workq's printed WORKQ_*
# dialect, and the campaign carries NO `classify.patterns` spec: workq reports
# through the verdict ABI, so the envelope classifies it unaided
# (docs/arcs/outcome-channel.md, Wave C).
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
  non-vacuously, the planted bug was caught, `cargo patina minimize
  --generation` reduces the catching generation against the verdicts the
  campaign recorded for it (no oracle, no --marker) and it still reproduces,
  and a flag-free `cargo patina replay` reproduces the violation
  byte-identically.

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

# Replay a trace and reduce its `patina.result/v1` envelope to the four facts
# every leg below asks for, one per line:
#   1  the `violation` verdicts, as `label detail` (empty when there are none)
#   2  fs shorts_applied     3  dns "resolutions failures_injected latency_applied"
# Everything comes from the envelope's structured fields -- the verdict channel
# and the per-plane fault accounting -- so no leg reads the guest's printed
# WORKQ_* dialect (docs/arcs/outcome-channel.md).
envelope_facts() {
  local trace="$1"; shift
  replay "$trace" --format json "$@" 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print(); print(0); print("0 0 0"); sys.exit(0)
v = [x for x in d.get("verdicts", []) if x.get("kind") == "violation"]
print("; ".join("%s %s" % (x.get("label",""), x.get("detail","")) for x in v))
planes = d.get("fault_reports") or {}
fs = planes.get("fs") or {}
print(fs.get("shorts_applied", 0))
dns = planes.get("dns") or {}
print("%s %s %s" % (dns.get("resolutions", 0), dns.get("failures_injected", 0),
                    dns.get("latency_applied", 0)))
'
}

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

# NO campaign spec: workq reports its outcomes through the verdict ABI, so the
# classifier reads them straight off each generation's structured envelope
# (verdicts, per-plane fault accounting, refusal, guest exit) and needs no
# per-guest `classify.patterns` declaration at all. The spec-declared patterns
# of docs/arcs/outcome-channel.md 4.3 are the LEVEL-1 escape hatch -- for a guest
# that only prints its findings -- and workq is no longer one.
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
# [b] catch: scan VIOLATION-, GUEST_ABORT- and UNCLASSIFIED-classified generations (in
# generation order -- deterministic, gens are a pure function of the spec) for
# the planted bug's SPECIFIC signature: a `violation` VERDICT in the replay's
# envelope (both ways a torn short write surfaces report one -- the
# durability/no-loss audit and the recovery gate's `wal-integrity`, see wal.rs)
# TOGETHER WITH fs `shorts_applied`>0 in the SAME generation's `fault_reports`.
#
# shorts_applied>0 is required, not just a violation, because red-proofing
# this script surfaced an UNRELATED pre-existing workq defect: a plain
# fs-error (shorts_applied=0) can also leave an acked job's Enqueue record
# missing from the durable WAL while the worker still phantom-applies it --
# reproducible even with --bug unset and even without this arc's
# --server-host/--dns-entry changes, so it predates and is independent of both.
# It happens to report the very same `durability` violation verdict at a fixed
# generation in this exact campaign shape, so matching the verdict alone would
# silently accept that unrelated bug's catch as "the planted bug caught". Filed
# as a separate finding for follow-up; not fixed here (out of this unit's scope).
# ---------------------------------------------------------------------------
candidate_gens=()
while IFS= read -r g; do
  [[ -n "$g" ]] && candidate_gens+=("$g")
done < <(python3 -c "
import json
d = json.load(open('$campaign_json'))
gens = sorted(r['generation'] for r in d.get('notable_runs', []) if r['class'] in ('VIOLATION', 'GUEST_ABORT', 'UNCLASSIFIED'))
print('\n'.join(str(g) for g in gens))
")

catch_gen=""
catch_verdict=""
catch_shorts=""
for g in ${candidate_gens[@]+"${candidate_gens[@]}"}; do
  trace="$OUT/failures/generation-$g.patina"
  [[ -f "$trace" ]] || continue
  facts="$(envelope_facts "$trace" ${ALLOW[@]+"${ALLOW[@]}"})"
  verdicts="$(printf '%s\n' "$facts" | sed -n 1p)"
  shorts="$(printf '%s\n' "$facts" | sed -n 2p)"
  [[ -n "$verdicts" ]] || continue
  if [[ "${shorts:-0}" -gt 0 ]]; then
    catch_gen="$g"; catch_verdict="$verdicts"; catch_shorts="$shorts"
    break
  fi
done

if [[ -z "$catch_gen" ]]; then
  echo "    FAIL: no generation reports a violation verdict WITH fs shorts_applied>0 in $GENS generations -- planted bug NOT caught"
  record "b-catch: FAIL (no generation with a violation verdict AND shorts_applied>0 in $GENS gens)"
  fail=1
else
  trace="$OUT/failures/generation-$catch_gen.patina"
  echo "    caught: generation $catch_gen -- violation verdict: $catch_verdict"
  record "b-catch: PASS (generation $catch_gen, violation verdict: $catch_verdict)"

  # -------------------------------------------------------------------
  # [a-fs] non-vacuous fs-fault firing, read off the SAME catching
  # generation's fs plane (shorts_applied>0 already confirmed above).
  # -------------------------------------------------------------------
  echo "    fs non-vacuous: generation $catch_gen -- fault_reports.fs.shorts_applied=$catch_shorts"
  record "a-fs: PASS (generation $catch_gen: fault_reports.fs.shorts_applied=$catch_shorts)"
fi

# ---------------------------------------------------------------------------
# [a-dns] non-vacuous dns-fault firing. Scan every saved failing trace's
# replay for a `fault_reports.dns` plane with a real injected effect (a
# failure OR a latency application -- --faults bands both dns-fail-permille
# and dns-latency-nanos once --dns-entry is supplied, and either is a genuine
# fire, not just the other).
# ---------------------------------------------------------------------------
dns_fired=0
dns_evidence=""
for f in "$OUT"/failures/*.patina; do
  [[ -e "$f" ]] || continue
  dns_line="$(envelope_facts "$f" ${ALLOW[@]+"${ALLOW[@]}"} | sed -n 3p)"
  read -r resolutions failures_injected latency_applied <<<"$dns_line"
  if [[ "${resolutions:-0}" -gt 0 && ( "${failures_injected:-0}" -gt 0 || "${latency_applied:-0}" -gt 0 ) ]]; then
    dns_fired=1
    dns_evidence="generation $(basename "$f" .patina): fault_reports.dns resolutions=$resolutions failures_injected=$failures_injected latency_applied=$latency_applied"
    break
  fi
done
if [[ "$dns_fired" -eq 1 ]]; then
  echo "    dns non-vacuous: $dns_evidence"
  record "a-dns: PASS ($dns_evidence)"
else
  echo "    FAIL: no generation shows a non-vacuous fault_reports.dns plane"
  echo "          (resolutions>0 with a failure or latency effect applied) --"
  echo "          named loudly rather than papered over."
  record "a-dns: FAIL (no generation showed a non-vacuous fault_reports.dns plane)"
  fail=1
fi

# ---------------------------------------------------------------------------
# [c] minimize: reduce the catching GENERATION -- fault knobs first, then a
# trace recorded from the minimal-knob run -- and the result must still
# reproduce the SAME violation.
#
# No oracle is written here, and no --marker is passed. The campaign already
# recognized this generation (it recorded the `violation` verdicts it reported
# in campaign-state.json), so `minimize --generation` targets exactly those
# verdicts by (kind, label) and requires a candidate to still report every one
# of them AND to replay without diverging -- in-process, in parallel, with the
# recorded invocation flags carried along. That is the recognition primitive of
# docs/arcs/outcome-channel.md 4.5: one mechanism, two consumers. The oracle
# this leg used to spell out in shell (reject a diverged replay, reject a run
# patina refused, then look for `PATINA_VERDICT ... kind=violation`) is what
# the built-in target does structurally -- a refusal produces no run envelope
# and therefore no verdicts, and a divergence is rejected before the verdicts
# are even consulted.
# ---------------------------------------------------------------------------
if [[ -n "$catch_gen" && -f "$OUT/failures/generation-$catch_gen.patina" ]]; then
  min_trace="$work/minimized.patina"
  min_out="$work/minimize.out"
  "$PATINA" patina minimize --generation "$catch_gen" --out-dir "$OUT" \
    --output "$min_trace" \
    >"$min_out" 2>&1
  min_code=$?
  min_line="$(grep -m1 'PATINA_MINIMIZE_GENERATION_COMPLETE' "$min_out" || true)"
  if [[ $min_code -ne 0 || -z "$min_line" || ! -f "$min_trace" ]]; then
    echo "    FAIL: minimize did not complete (exit=$min_code)"
    cat "$min_out"
    record "c-minimize: FAIL (exit=$min_code)"
    fail=1
  else
    echo "    $min_line"
    min_verdict="$(envelope_facts "$min_trace" ${ALLOW[@]+"${ALLOW[@]}"} | sed -n 1p)"
    if [[ -z "$min_verdict" ]]; then
      echo "    FAIL: minimized trace no longer reports a violation verdict"
      record "c-minimize: FAIL (minimized trace lost the violation)"
      fail=1
    else
      echo "    minimized trace still reproduces: $min_verdict"
      record "c-minimize: PASS ($min_line; still reproduces: $min_verdict)"
    fi

    # -----------------------------------------------------------------
    # [d] flag-free replay: NO fault/campaign flags, just the trace --
    # two independent replays must agree byte-for-byte. Verdicts are recorded
    # trace events, so the PATINA_VERDICT lines on stderr are PART of the
    # identity being asserted; the count is checked separately so an identical
    # pair of verdict-free streams can never pass this leg vacuously.
    # -----------------------------------------------------------------
    r1_out="$work/ff1.out"; r1_err="$work/ff1.err"
    r2_out="$work/ff2.out"; r2_err="$work/ff2.err"
    replay "$min_trace" ${ALLOW[@]+"${ALLOW[@]}"} >"$r1_out" 2>"$r1_err"
    c1=$?
    replay "$min_trace" ${ALLOW[@]+"${ALLOW[@]}"} >"$r2_out" 2>"$r2_err"
    c2=$?
    v1="$(grep -c '^PATINA_VERDICT ' "$r1_err" || true)"
    if [[ $c1 -ne $c2 ]] || ! diff -q "$r1_out" "$r2_out" >/dev/null || ! diff -q "$r1_err" "$r2_err" >/dev/null; then
      echo "    FAIL: flag-free replay is not byte-identical across two runs (exit $c1 vs $c2)"
      record "d-replay: FAIL (not byte-identical: exit $c1 vs $c2)"
      fail=1
    elif [[ "${v1:-0}" -lt 1 ]]; then
      echo "    FAIL: flag-free replay carried NO verdict events -- the identity check would be vacuous"
      record "d-replay: FAIL (replay reproduced no PATINA_VERDICT events)"
      fail=1
    else
      echo "    flag-free replay byte-identical (exit=$c1, verdict events=$v1): $min_verdict"
      record "d-replay: PASS (flag-free, byte-identical incl. $v1 verdict events, exit=$c1: $min_verdict)"
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
