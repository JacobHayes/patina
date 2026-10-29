# Sourced by the testbed gates: run a guest under `--format json` and split its
# `patina.result/v1` envelope, the run's one machine channel, into files the
# gate greps. `jrun PREFIX ARGS...` runs `cargo patina --format json ARGS...`
# and leaves PREFIX.json (the envelope), PREFIX.verdicts (one
# `<kind> <label> <detail>` line per verdict, in call order) and PREFIX.err (the
# guest's captured stderr, then the CLI's own), returning the run's exit code.
jrun() {
  local prefix="$1" code=0
  shift
  "$PATINA" patina --format json "$@" >"$prefix.json" 2>"$prefix.cli.err" || code=$?
  python3 -B - "$prefix" <<'PY'
import json, sys
prefix = sys.argv[1]
try:
    with open(prefix + ".json") as handle:
        envelope = json.loads(handle.read().strip().splitlines()[-1])
except (OSError, ValueError, IndexError):
    envelope = {}
with open(prefix + ".verdicts", "w") as out:
    for verdict in envelope.get("verdicts", []):
        out.write(f"{verdict['kind']} {verdict['label']} {verdict['detail']}\n")
with open(prefix + ".err", "w") as out:
    out.write(envelope.get("stderr", ""))
PY
  cat "$prefix.cli.err" >>"$prefix.err"
  return "$code"
}

# Whether the envelope PREFIX.json reports the `net` fault plane as applied
# (present and not vacuous).
net_faults_applied() {
  python3 -B - "$1.json" <<'PY'
import json, sys
with open(sys.argv[1]) as handle:
    envelope = json.loads(handle.read().strip().splitlines()[-1])
net = envelope.get("fault_reports", {}).get("net")
sys.exit(0 if net is not None and net.get("vacuous") is False else 1)
PY
}
