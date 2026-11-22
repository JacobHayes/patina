# 14. Only errors Linux can return: under fs-error-permille=1000 the stock Go program that
# runs coreutils through os/exec (pipes) is ok, and no injected error in its boundary log
# names a pipe or a unix socket (those get short transfers and delays only). Linux never
# answers EIO on a pipe read; an injected one deadlocks Go's os/exec.
#@ tier=quick budget=20 slots=0.5
. "$(dirname "$0")/lib/common.inc"
: "${PATINA_WORKLOADS:?}"
o=$RUNS/14/go
rm -rf "${o:?}"; mkdir -p "$(dirname "$o")"
timeout 300 "$PATINA" run --seed 1 --config "$("$PATINA_CFG" cpus=2)" --out "$o" --mount "$PATINA_WORKLOADS/go-static":/guest:copy \
    --fault fs-error-permille=1000 --fault fs-short-permille=300 -- /guest/go-static local >/dev/null 2>&1 \
    || [ -f "$o/result.json" ] || die "go-static: no result.json"
"$PATINA" log dump "$o/boot-1/boundary.log" >"$o.dump"
python3 -I - "$o/result.json" "$o.dump" <<'PY' || exit 1
import json, re, sys
r = json.load(open(sys.argv[1]))
lines = open(sys.argv[2]).read().splitlines()
# an injected record is followed by the name record of its object
kinds = {}
for a, b in zip(lines, lines[1:]):
    if " inject " not in a:
        continue
    kind = int(re.search(r"args=\[(0x[0-9a-f]+)", a).group(1), 16)
    obj = b.split()[4] if " name " in b else "?"
    kinds.setdefault(obj if obj in ("pipe", "unix") else "/work", set()).add(kind)
print("injected kinds by object (1 error, 2 short, 3 delay):", {k: sorted(v) for k, v in kinds.items()})
bad = [k for k in ("pipe", "unix") if kinds.get(k, set()) - {2, 3}]
if bad:
    sys.exit("FAIL: an injected error on %s" % bad)
if 2 not in kinds.get("pipe", set()):
    sys.exit("FAIL: no short transfer on a pipe (the guest's pipes were not exercised)")
print("go-static under fs-error-permille=1000: %s (%s), %d faults injected" % (r["outcome"], r["message"], r["faults"]["injected"]))
if r["outcome"] != "ok":
    sys.exit("FAIL: not ok")
PY
rm -f "$o.dump"
