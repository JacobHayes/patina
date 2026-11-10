#!/usr/bin/env bash
###############################################################################
# python-sdk — a Python guest instrumented with Patina's Python SDK (the
# `patina` package every guest `patina build --python` builds has; its
# source is crates/cargo-patina/python/sdk/patina).
#
# The guest (app/__main__.py) declares its sites at module level: an Always, a
# Sometimes its seeded draws satisfy, a Reachable it reaches and one it never
# reaches, a fault site, a delay site and a knob. It marks its setup boundary,
# reports a pass verdict and, under the run parameter `ops`, wraps two effects
# as custom operations (one with a declared failure). The run parameter
# `violate` (or, under plain Python, the argument) breaks the invariant.
#
# It asserts:
#   [1] the pre-run audit is CLEAN with no allowance;
#   [2] under Patina the SDK is live: the guest sees itself simulated, the SDK
#       report declares every site at its __main__.py line (the never-reached
#       one included) and registers each one it evaluates, the lifecycle
#       markers are emitted and the pass verdict is in the result;
#   [3] two same-seed runs are byte-identical, a record replays
#       byte-identically, and another seed draws another ledger;
#   [4] `--param violate=1` ends the run with a violation verdict naming the
#       Always site and carrying its detail, and its recorded trace replays to
#       the same verdicts;
#   [5] armed buggify after the setup boundary fires the fault and delay
#       sites and perturbs the knob, where an unarmed run fires nothing;
#   [6] custom ops perform on record and not on replay, and a seeded
#       custom-op fault returns the declared failure without performing,
#       which its trace replays;
#   [7] a campaign reports the never-reached site as unmet and fails its
#       coverage gate;
#   [8] plain python3 runs the same application inert: not simulated, and a
#       broken invariant changes nothing; the SDK's inert tests pass.
###############################################################################
set -uo pipefail

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  sed -n '2,/^####*$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
sdk="$repo_root/crates/cargo-patina/python/sdk"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target/testbeds/python-sdk}"
export CARGO_TARGET_DIR="$target_dir"
PATINA="${PATINA_CLI:-$target_dir/release/patina}"
out="$target_dir/patina"
built="$out/python-sdk"

if [[ $(uname -s) != Linux ]]; then
  echo "FATAL: Python guests build on Linux only" >&2; exit 3
fi
if ! command -v python3 >/dev/null; then
  echo "FATAL: no python3 on PATH (the checks and leg [8] run it)" >&2; exit 3
fi
if [[ -z ${PATINA_CLI:-} ]] && ! cargo build --release --quiet -p cargo-patina; then
  echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
fi
if [[ ! -x $PATINA ]]; then
  echo "FATAL: $PATINA is not an executable patina" >&2; exit 3
fi
mkdir -p "$out" || { echo "FATAL: mkdir $out failed" >&2; exit 3; }

fail() { echo "python-sdk: FAIL $*" >&2; exit 1; }

echo "==> building the SDK guest (patina build --python)"
"$PATINA" build "$here/app" --python --output "$built" --release >"$out/build.log" 2>&1 \
  || { cat "$out/build.log" >&2; echo "FATAL: patina build --python of the SDK guest failed" >&2; exit 3; }

echo "==> [1] audit: clean"
"$PATINA" audit "$built" >"$out/audit.txt" 2>&1 \
  || { cat "$out/audit.txt" >&2; fail "[1] audit refused the guest"; }

# The line of __main__.py that declares LABEL.
line_of() { grep -n "\"$1\"" "$here/app/__main__.py" | head -1 | cut -d: -f1; }

# The value of FIELD in the PY_SDK_RESULT line of FILE.
field_of() { sed -n "s/^PY_SDK_RESULT .* $2=\([^ ]*\).*/\1/p" "$1"; }

echo "==> [2] the SDK is live: simulated, every site declared at its line"
"$PATINA" run "$built" --seed 1 --format json >"$out/run1.json" 2>/dev/null \
  || { cat "$out/run1.json" >&2; fail "[2] the run exited nonzero"; }
python3 -c '
import json, sys
verdicts = json.load(open(sys.argv[1]))["verdicts"]
assert [(v["kind"], v["label"]) for v in verdicts] == [("pass", "python-sdk-ledger-settled")], verdicts
' "$out/run1.json" || { cat "$out/run1.json" >&2; fail "[2] the pass verdict is not the run's one verdict"; }
"$PATINA" run "$built" --seed 1 >"$out/run1.out" 2>"$out/run1.err" \
  || { cat "$out/run1.out" "$out/run1.err" >&2; fail "[2] the run exited nonzero"; }
grep -q '^PY_SDK_RESULT simulated=True held=True ' "$out/run1.out" \
  || { cat "$out/run1.out" >&2; fail "[2] unexpected PY_SDK_RESULT"; }
grep -qx 'PATINA_LIFECYCLE setup_complete' "$out/run1.err" \
  && grep -qx 'PATINA_LIFECYCLE_EVENT label=python-sdk-workload' "$out/run1.err" \
  || { cat "$out/run1.err" >&2; fail "[2] the lifecycle markers are missing"; }
report="$(grep '^PATINA_SDK_REPORT ' "$out/run1.err")" || fail "[2] no SDK report"
evaluated="python-sdk-ledger-sorted:always python-sdk-even-draw:sometimes python-sdk-settled:reachable
  python-sdk-drop-draw:fault python-sdk-stall:delay python-sdk-ledger-width:knob"
for site in $evaluated python-sdk-never-reached:reachable; do
  label=${site%%:*} kind=${site#*:}
  [[ " $report " == *" declared_site=$label|$kind|@__main__.py:$(line_of "$label") "* ]] \
    || { echo "$report" >&2; fail "[2] $label is not declared as a $kind at its __main__.py line"; }
done
for site in $evaluated; do
  label=${site%%:*}
  [[ " $report " == *" site=$label|"* ]] || { echo "$report" >&2; fail "[2] $label was not registered"; }
done
[[ " $report " != *" site=python-sdk-never-reached|"* ]] \
  || { echo "$report" >&2; fail "[2] the never-reached site registered"; }

echo "==> [3] same-seed repeat and record → replay are byte-identical; seeds vary"
"$PATINA" run "$built" --seed 1 >"$out/run2.out" 2>"$out/run2.err" || fail "[3] repeat run failed"
"$PATINA" run "$built" --seed 1 --record "$out/sdk.patina" >"$out/record.out" 2>"$out/record.err" \
  || fail "[3] record run failed"
"$PATINA" replay "$built" "$out/sdk.patina" >"$out/replay.out" 2>"$out/replay.err" \
  || { cat "$out/replay.err" >&2; fail "[3] replay failed"; }
for pair in run1:run2 record:replay; do
  for stream in out err; do
    cmp -s "$out/${pair%%:*}.$stream" "$out/${pair#*:}.$stream" \
      || { diff "$out/${pair%%:*}.$stream" "$out/${pair#*:}.$stream" >&2; fail "[3] $pair differ on std$stream"; }
  done
done
"$PATINA" run "$built" --seed 2 >"$out/seed2.out" 2>/dev/null || fail "[3] the seed-2 run failed"
[[ $(field_of "$out/seed2.out" first) != "$(field_of "$out/run1.out" first)" ]] \
  || { cat "$out/run1.out" "$out/seed2.out" >&2; fail "[3] seed 2 drew seed 1's ledger"; }

echo "==> [4] a broken invariant is a violation verdict, and replays to it"
violated() {
  python3 -c '
import json, sys
text = open(sys.argv[1]).read()
envelope = json.loads(text)
verdicts = [v for v in envelope.get("verdicts", []) if v.get("kind") == "violation"]
assert {v["label"] for v in verdicts} == {"python-sdk-ledger-sorted"}, verdicts
# The check detail names the failing ledger in a verdict of its own.
assert any(v["detail"].startswith("ledger=[") for v in verdicts), verdicts
assert envelope["result"] == "violation", envelope["result"]
# A replay that diverged or was refused after reaching the verdict is no
# reproduction of it.
assert "replay_divergence" not in text and "refusal" not in envelope, "diverged or refused"
if len(sys.argv) > 2:
    recorded = json.load(open(sys.argv[2]))
    assert envelope["verdicts"] == recorded["verdicts"], (envelope["verdicts"], recorded["verdicts"])
    assert envelope["guest_exit"] == recorded["guest_exit"], (envelope["guest_exit"], recorded["guest_exit"])
' "$@"
}
"$PATINA" run "$built" --seed 1 --param violate=1 --record "$out/violate.patina" --format json \
  >"$out/violate.json" 2>"$out/violate.err"
violated "$out/violate.json" || { cat "$out/violate.json" >&2; fail "[4] no violation verdict"; }
"$PATINA" replay "$built" "$out/violate.patina" --format json >"$out/violate-replay.json" 2>/dev/null
violated "$out/violate-replay.json" "$out/violate.json" || { cat "$out/violate-replay.json" >&2; fail "[4] the replay lost the verdict"; }

echo "==> [5] armed buggify after setup fires the fault, delay and knob sites"
[[ $(field_of "$out/run1.out" dropped) == 0 && $(field_of "$out/run1.out" width) == 8 ]] \
  || { cat "$out/run1.out" >&2; fail "[5] an unarmed run fired a site"; }
"$PATINA" run "$built" --seed 1 --buggify-after-setup --buggify-activation-permille 1000 \
  >"$out/buggify.out" 2>"$out/buggify.err" \
  || { cat "$out/buggify.out" "$out/buggify.err" >&2; fail "[5] the armed run failed"; }
armed="$(grep '^PATINA_SDK_REPORT ' "$out/buggify.err")" || fail "[5] no SDK report"
for label in python-sdk-drop-draw python-sdk-stall; do
  [[ " $armed " =~ \ site=$label\|[a-z]+\|a1\|e[0-9]+\|f[1-9] ]] \
    || { echo "$armed" >&2; fail "[5] $label did not fire"; }
done
knob="$(sed -n 's/.* site=python-sdk-ledger-width|knob|a1|[^ ]*|k\([0-9]*\)|.*/\1/p' <<<"$armed")"
[[ -n $knob && $knob != 8 && $knob -ge 4 && $knob -le 16 && $knob == $(field_of "$out/buggify.out" width) ]] \
  || { echo "$armed" >&2; cat "$out/buggify.out" >&2; fail "[5] the knob was not perturbed within its bounds"; }
(( $(field_of "$out/buggify.out" dropped) > 0 )) || { cat "$out/buggify.out" >&2; fail "[5] no draw dropped"; }

echo "==> [6] custom ops: performed on record, replayed without, and a seeded fault"
"$PATINA" run "$built" --seed 1 --param ops=1 --record "$out/ops.patina" >"$out/ops.out" 2>"$out/ops.err" \
  || { cat "$out/ops.err" >&2; fail "[6] the custom-op run failed"; }
"$PATINA" replay "$built" "$out/ops.patina" >"$out/ops-replay.out" 2>"$out/ops-replay.err" \
  || { cat "$out/ops-replay.err" >&2; fail "[6] the custom-op replay failed"; }
[[ $(field_of "$out/ops.out" performed) == 2 && $(field_of "$out/ops-replay.out" performed) == 0 ]] \
  && [[ $(field_of "$out/ops-replay.out" fetched) == etag-7 && $(field_of "$out/ops-replay.out" plain) == 7 ]] \
  || { cat "$out/ops.out" "$out/ops-replay.out" >&2; fail "[6] a replay performed, or lost a result"; }
"$PATINA" run "$built" --seed 1 --param ops=1 --custom-op-fail-permille 1000 --record "$out/fault.patina" \
  >"$out/fault.out" 2>"$out/fault.err" || { cat "$out/fault.err" >&2; fail "[6] the faulted run failed"; }
"$PATINA" replay "$built" "$out/fault.patina" >"$out/fault-replay.out" 2>"$out/fault-replay.err" \
  || { cat "$out/fault-replay.err" >&2; fail "[6] the faulted replay failed"; }
# Only the op that declared a failure faults, and it does not perform.
[[ $(field_of "$out/fault.out" performed) == 1 && $(field_of "$out/fault.out" fetched) == UNAVAILABLE ]] \
  && [[ $(field_of "$out/fault.out" plain) == 7 && $(field_of "$out/fault-replay.out" performed) == 0 ]] \
  && [[ $(field_of "$out/fault-replay.out" fetched) == UNAVAILABLE ]] \
  || { cat "$out/fault.out" "$out/fault-replay.out" >&2; fail "[6] the seeded fault did not fire as declared, or replay lost it"; }

echo "==> [7] a campaign fails its gate on the never-reached site"
rm -rf "$out/campaign"
if "$PATINA" campaign "$built" --gens 2 --out-dir "$out/campaign" >"$out/campaign.out" 2>&1; then
  cat "$out/campaign.out" >&2; fail "[7] the campaign passed with a site never reached"
fi
grep -q "UNMET reachable 'python-sdk-never-reached'" "$out/campaign.out" \
  && grep -q '^PATINA_CAMPAIGN_COVERAGE .*unmet=1 gate=fail' "$out/campaign.out" \
  || { cat "$out/campaign.out" >&2; fail "[7] the never-reached site is not the one unmet"; }

echo "==> [8] plain python3 is inert, and the SDK's inert tests pass"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$sdk" python3 -m unittest discover -s "$here" -p 'test_*.py' \
  >"$out/sdk-test.out" 2>&1 || { cat "$out/sdk-test.out" >&2; fail "[8] the SDK's inert tests failed"; }
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$sdk" python3 "$here/app" violate >"$out/plain.out" 2>&1 \
  || { cat "$out/plain.out" >&2; fail "[8] plain python3 stopped on a broken invariant"; }
grep -q '^PY_SDK_RESULT simulated=False held=False ' "$out/plain.out" \
  || { cat "$out/plain.out" >&2; fail "[8] unexpected plain-python result"; }

grep '^PY_SDK_RESULT' "$out/run1.out"
echo "PY_SDK_LEGS_RAN legs=audit-clean,live-sites,seed-replay-identity-variation,violation-verdict,buggify-after-setup,custom-ops,campaign-gate,plain-inert"
