# PID 1 of the sandbox, as it is when it executes the supervisor, has no capability in any set
# and no_new_privs, as uid 1000. Another view of the sandbox (`Keeper::view`, the part machines
# build on): `patina __sandbox-views` makes a sandbox whose keeper adds two views, n1 and
# n2. Each view has its own mount, UTS and IPC namespace, disk, /tmp and hostname, and
# shares the sandbox's PID, network and guests' user namespaces; its process has no capability
# and no_new_privs, runs as the guest's user, and PID 1 reaps it. What one view writes, no
# other view and not the base sees.
#@ tier=quick budget=10 slots=0.5
. "$(dirname "$0")/lib/common.inc"
out=$RUNS/views
mkdir -p "$out"
st=0
timeout 60 "$PATINA" __sandbox-views >"$out/stdout" 2>"$out/stderr" || st=$?
[ "$st" = 0 ] || die "views: exit $st: $(cat "$out/stderr")"
python3 -I - "$out/stdout" "$(readlink /proc/self/ns/mnt)" "$(hostname)" <<'PY' || die "views: $(cat "$out/stdout" "$out/stderr")"
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1])]
host_mnt, host_name = sys.argv[2], sys.argv[3]
v = {l["view"]: l for l in lines}
assert sorted(v) == ["base", "n1", "n2"] and len(lines) == 3, list(v)
# PID 1 printed last, after reaping both views' processes, each with status 0.
assert lines[-1]["view"] == "base"
reaped = {p: c for p, c in v["base"]["reaped"]}
for n in ("n1", "n2"):
    assert reaped.get(v[n]["pid"]) == 0, (n, v[n]["pid"], reaped)
assert v["base"]["hostname"] != v["n1"]["hostname"] != v["n2"]["hostname"] != v["base"]["hostname"]
assert host_name not in (v["n1"]["hostname"], v["n2"]["hostname"])
assert v["n1"]["hostname"] == "n1" and v["n2"]["hostname"] == "n2"
# Each view's disk and /tmp are its own; the base kept what it wrote.
for n in ("base", "n1", "n2"):
    assert v[n]["work"] == n, (n, v[n]["work"])
assert "mark" not in v["base"]["tmp"] and v["n1"]["tmp"] == ["mark"] and v["n2"]["tmp"] == ["mark"]
for k in ("mnt", "uts", "ipc"):
    assert len({v[n][k] for n in v}) == 3, (k, [v[n][k] for n in v])
assert host_mnt not in {v[n]["mnt"] for n in v}
for k in ("pid_ns", "net", "user"):
    assert len({v[n][k] for n in v}) == 1, (k, [v[n][k] for n in v])
for n in v:
    for k in ("cap_eff", "cap_prm", "cap_inh", "cap_amb", "cap_bnd"):
        assert int(v[n][k], 16) == 0, (n, k, v[n])
    assert v[n]["nnp"] == "1" and v[n]["uid"] == 1000, (n, v[n])
print("views:", ", ".join(f"{n} pid {v[n]['pid']} host {v[n]['hostname']}" for n in ("n1", "n2")),
      "own mount/uts/ipc, shared pid/net/user, no capabilities, reaped by PID 1")
PY
