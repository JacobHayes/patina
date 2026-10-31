#!/usr/bin/env bash
###############################################################################
# go-sdk — a Go guest instrumented with Patina's Go SDK (go/patina), built by
# `cargo patina build --go` (Linux).
#
# The guest (main.go) declares four sites at package level: an Always, a
# Sometimes its seeded draws satisfy, a Reachable it reaches and one it never
# reaches. The run parameter `violate` (or, natively, the argument) breaks the
# invariant.
#
# It asserts:
#   [1] the pre-run audit is CLEAN with no allowance;
#   [2] under Patina the SDK is live: the guest sees itself simulated, the SDK
#       report declares all four sites at their main.go lines (the
#       never-reached one included) and registers the three it evaluates;
#   [3] two same-seed runs are byte-identical, and a record replays
#       byte-identically;
#   [4] `--param violate=1` ends the run with a violation verdict naming the
#       Always site, and its recorded trace replays to the same verdict;
#   [5] a campaign reports the never-reached site as unmet and fails its
#       coverage gate;
#   [6] a plain `go build` of the same package is inert: not simulated, and
#       a broken invariant changes nothing; the SDK's own tests (go test,
#       plain build) pass.
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target/testbeds/go-sdk}"
export CARGO_TARGET_DIR="$target_dir"
PATINA="${PATINA_CLI:-$target_dir/release/cargo-patina}"
out="$target_dir/patina"
built="$out/go-sdk"

if [[ $(uname -s) != Linux ]]; then
  echo "FATAL: Go guests build on Linux only" >&2; exit 3
fi
if ! command -v go >/dev/null; then
  echo "FATAL: no go on PATH (any Go >= 1.21 switches to go.mod's toolchain)" >&2; exit 3
fi
pinned="$(sed -n 's/^toolchain //p' "$here/go.mod")"
export GOTOOLCHAIN="$pinned"
if [[ $(go -C "$here" env GOVERSION) != "$pinned" ]]; then
  echo "FATAL: go builds with $(go -C "$here" env GOVERSION), not go.mod's $pinned" >&2; exit 3
fi
if [[ -z ${PATINA_CLI:-} ]] && ! cargo build --release --quiet -p cargo-patina; then
  echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
fi
if [[ ! -x $PATINA ]]; then
  echo "FATAL: $PATINA is not an executable cargo-patina" >&2; exit 3
fi
mkdir -p "$out" || { echo "FATAL: mkdir $out failed" >&2; exit 3; }

fail() { echo "go-sdk: FAIL $*" >&2; exit 1; }

echo "==> building the SDK guest (cargo patina build --go)"
"$PATINA" patina build "$here" --go --output "$built" --release -- -trimpath >/dev/null \
  || { echo "FATAL: patina build --go of the SDK guest failed" >&2; exit 3; }

echo "==> [1] audit: clean"
"$PATINA" patina audit "$built" >"$out/audit.txt" 2>&1 \
  || { cat "$out/audit.txt" >&2; fail "[1] audit refused the guest"; }

# The line of main.go that declares LABEL.
line_of() { grep -n "\"$1\"" "$here/main.go" | cut -d: -f1; }

echo "==> [2] the SDK is live: simulated, every site declared at its line"
"$PATINA" patina run "$built" --seed 1 >"$out/run1.out" 2>"$out/run1.err" \
  || { cat "$out/run1.out" "$out/run1.err" >&2; fail "[2] the run exited nonzero"; }
grep -q '^GO_SDK_RESULT simulated=true held=true ' "$out/run1.out" \
  || { cat "$out/run1.out" >&2; fail "[2] unexpected GO_SDK_RESULT"; }
report="$(grep '^PATINA_SDK_REPORT ' "$out/run1.err")" || fail "[2] no SDK report"
for site in go-sdk-ledger-sorted:always go-sdk-even-draw:sometimes \
  go-sdk-settled:reachable go-sdk-never-reached:reachable; do
  label=${site%%:*} kind=${site#*:}
  [[ " $report " == *" declared_site=$label|$kind|@patina.dev/testbeds/go-sdk/main.go:$(line_of "$label") "* ]] \
    || { echo "$report" >&2; fail "[2] $label is not declared as a $kind at its main.go line"; }
done
for label in go-sdk-ledger-sorted go-sdk-even-draw go-sdk-settled; do
  [[ " $report " == *" site=$label|"* ]] || { echo "$report" >&2; fail "[2] $label was not registered"; }
done
[[ " $report " != *" site=go-sdk-never-reached|"* ]] \
  || { echo "$report" >&2; fail "[2] the never-reached site registered"; }

echo "==> [3] same-seed repeat and record → replay are byte-identical"
"$PATINA" patina run "$built" --seed 1 >"$out/run2.out" 2>"$out/run2.err" || fail "[3] repeat run failed"
"$PATINA" patina run "$built" --seed 1 --record "$out/sdk.patina" >"$out/record.out" 2>"$out/record.err" \
  || fail "[3] record run failed"
"$PATINA" patina replay "$built" "$out/sdk.patina" >"$out/replay.out" 2>"$out/replay.err" \
  || { cat "$out/replay.err" >&2; fail "[3] replay failed"; }
for pair in run1:run2 record:replay; do
  for stream in out err; do
    cmp -s "$out/${pair%%:*}.$stream" "$out/${pair#*:}.$stream" \
      || { diff "$out/${pair%%:*}.$stream" "$out/${pair#*:}.$stream" >&2; fail "[3] $pair differ on std$stream"; }
  done
done

echo "==> [4] a broken invariant is a violation verdict, and replays to it"
violated() {
  python3 -c '
import json, sys
text = open(sys.argv[1]).read()
envelope = json.loads(text)
verdicts = [v for v in envelope.get("verdicts", []) if v.get("kind") == "violation"]
assert [v["label"] for v in verdicts] == ["go-sdk-ledger-sorted"], verdicts
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
"$PATINA" patina run "$built" --seed 1 --param violate=1 --record "$out/violate.patina" --format json \
  >"$out/violate.json" 2>"$out/violate.err"
violated "$out/violate.json" || { cat "$out/violate.json" >&2; fail "[4] no violation verdict"; }
"$PATINA" patina replay "$built" "$out/violate.patina" --format json >"$out/violate-replay.json" 2>/dev/null
violated "$out/violate-replay.json" "$out/violate.json" || { cat "$out/violate-replay.json" >&2; fail "[4] the replay lost the verdict"; }

echo "==> [5] a campaign fails its gate on the never-reached site"
rm -rf "$out/campaign"
if "$PATINA" patina campaign "$built" --gens 2 --out-dir "$out/campaign" >"$out/campaign.out" 2>&1; then
  cat "$out/campaign.out" >&2; fail "[5] the campaign passed with a site never reached"
fi
grep -q "UNMET reachable 'go-sdk-never-reached'" "$out/campaign.out" \
  && grep -q '^PATINA_CAMPAIGN_COVERAGE .*unmet=1 gate=fail' "$out/campaign.out" \
  || { cat "$out/campaign.out" >&2; fail "[5] the never-reached site is not the one unmet"; }

echo "==> [6] a plain go build is inert, and the SDK's own tests pass"
go -C "$repo_root/go/patina" test ./... >"$out/sdk-test.out" 2>&1 \
  || { cat "$out/sdk-test.out" >&2; fail "[6] the SDK's tests failed"; }
go -C "$here" build -o "$out/go-sdk-plain" . || fail "[6] plain go build failed"
"$out/go-sdk-plain" violate >"$out/plain.out" 2>&1 \
  || { cat "$out/plain.out" >&2; fail "[6] the plain build stopped on a broken invariant"; }
grep -q '^GO_SDK_RESULT simulated=false held=false ' "$out/plain.out" \
  || { cat "$out/plain.out" >&2; fail "[6] unexpected plain-build result"; }

grep '^GO_SDK_RESULT' "$out/run1.out"
echo "GO_SDK_LEGS_RAN legs=audit-clean,live-sites,seed-replay-identity,violation-verdict,campaign-gate,plain-inert"
