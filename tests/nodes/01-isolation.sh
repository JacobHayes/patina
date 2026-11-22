# 1. Nodes: isolation and scripted cuts. The driver and node b (tests/guests/nodes/iso.py) each
# see their own work tree, /tmp, /dev/shm, System V shared memory and hostname; b's loopback
# listener is not on its address; b's processes are ESRCH to the driver's kill and absent from
# its /proc, and getsid/getpgid do not find them; b gets EPERM for a control call and cannot
# change its view; each node has its own abstract AF_UNIX names, and names read back carry no
# prefix; UDP between nodes carries the nodes' addresses; b's first process starts with the
# driver's process state; a cut stops a connect and loses a datagram, and a heal lets both
# through; a socket's TCP_SYNCNT and TCP_USER_TIMEOUT set its own limits across a cut. The link faults leave the
# driver's links alone unless net-links says otherwise. A node given with --node whose command
# cannot run ends the run at once, naming the node. Identical under verify --vary cpu,aslr,sandbox,repeat
# (and load in the area tier).
# What is not available yet is refused, naming the feature; without nodes a control call is
# EINVAL, from a shell script too (`patina ctl`, as in a run with nodes). The C, Rust and Go SDKs' control calls answer the driver and give a
# node EPERM (the Rust and Go SDKs' in the area tier).
#@ tier=quick budget=20 slots=0.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/01-isolation; mkdir -p "$o"
# Quick: no load generator. Its two threads spin for the whole verify, most of this
# script's CPU time; on a slow, busy runner the script, which holds half a CPU, was starved past
# its budget.
[ "${CHECK_TIER:-}" != quick ] || VARY=cpu,aslr,sandbox,repeat
conf "$o/iso.toml" b python3 /guest/iso.py node
verify_ok "$o/iso" 1 2 --config "$o/iso.toml" -- python3 /guest/iso.py driver
sed 's/^/    /' "$o/iso/run-0/inc-0/stdout"
r=$o/iso/run-0
[ "$(field "$r/result.json" nodes.list.1.name)" = b ] || die "result.json: node b"
[ "$(field "$r/result.json" nodes.list.1.address)" = 10.0.0.2 ] || die "result.json: b's address"
[ "$(field "$r/result.json" nodes.net.heals)" -ge 1 ] || die "result.json: no heal counted"
[ -f "$r/node/b/inc-0/stdout" ] || die "no stdout for node b"

# The link faults act between nodes other than the driver (net-links=nodes): on the driver's
# links nothing is drawn; with net-links=driver they act there too.
run_ok "$o/links" 1 --config "$o/iso.toml" --fault net-reset-permille=1 -- python3 /guest/iso.py driver
[ "$(field "$o/links/result.json" faults.counts.net-reset.eligible)" = 0 ] || die "net-reset drawn on the driver's links"
run_ok "$o/links-driver" 1 --config "$o/iso.toml" --fault net-reset-permille=1 --fault net-links=driver -- python3 /guest/iso.py driver
e=$(field "$o/links-driver/result.json" faults.counts.net-reset.eligible)
[ "$e" -gt 0 ] || die "net-links=driver: net-reset not drawn on the driver's links"
echo "link faults: none drawn on the driver's links by default, $e reads with net-links=driver"
c=$(run "$o/noexec" 1 --node a=/etc/hostname -- /bin/true)
stop=$(field "$o/noexec/result.json" stop); m=$(field "$o/noexec/result.json" message)
[ "$c" = error ] && [ "$stop" = exec ] && grep -q 'node a' <<<"$m" || die "a node that cannot run: $c ($stop): $m"
echo "--node a=/etc/hostname: $c ($stop): $m"

# Not available yet: each refused before the run, naming what it asked for.
refused() {
    what=$1; shift
    st=0; "$PATINA" run --out "$o/refused" --mount "$PATINA_GUESTS":/guest:copy "$@" -- /bin/true >/dev/null 2>"$o/refused.err" || st=$?
    [ "$st" != 0 ] && [ ! -e "$o/refused" ] || die "$what: not refused"
    grep -q -- "$what" "$o/refused.err" || die "$what: the refusal does not name it: $(cat "$o/refused.err")"
    echo "refused: $what"
}
# Only the disk and memory keys are a node's own; a scope names nodes of the run.
refused net-drop-permille --config "$o/iso.toml" --fault net-drop-permille=10@b
refused "no node nope" --config "$o/iso.toml" --fault fs-error-permille=10@nope
printf '[node.c]\ncmd = ["/bin/true"]\n[node.c.faults]\nnet-drop-permille = 5\n' >"$o/own.toml"
refused node.c.faults --config "$o/own.toml"
printf '[node.c]\ncmd = ["/bin/true"]\nfaults = "net"\n' >"$o/faults.toml"
refused node.c.faults --config "$o/faults.toml"
for taken in driver rest localhost; do
    printf '[node.%s]\ncmd = ["/bin/true"]\n' "$taken" >"$o/taken.toml"
    refused "node.$taken" --config "$o/taken.toml"
done

# Without nodes: no network to act on.
run_ok "$o/none" 1 -- python3 -c '
import errno, sys
sys.path.insert(0, "/guest")
import patina
try:
    patina.control("heal")
except OSError as e:
    print("done" if e.errno == errno.EINVAL else e)'
[ "$(cat "$o/none/inc-0/stdout")" = done ] || die "patina ctl without nodes"
[ "$(field "$o/none/result.json" nodes 2>/dev/null || echo none)" = none ] || die "nodes in a run without them"
echo "without nodes: a control call is refused"

# From a shell script, in a run without nodes and in one with: `patina` is on the PATH and
# `heal` answers as above; and although the host's PATH has a patina too, no hint calls the
# guest's missing (env tries each PATH directory in turn, where a shell looks first).
cat >"$o/ctl.sh" <<'EOF'
st=0; env patina ctl heal 2>/dev/null || st=$?
echo "heal: $st"
EOF
rm -f "$o/one.toml"
conf "$o/one.toml" c sleep 1  # lint-allow: sleep — the guest's, in virtual time
for k in none one; do
    cfg=(); [ $k = none ] || cfg=(--config "$o/one.toml")
    PATH="$(dirname "$PATINA"):$PATH" run_ok "$o/sh-$k" 1 --faults disk "${cfg[@]}" --mount "$o":/s -- sh /s/ctl.sh
    want=2; [ $k = none ] || want=0
    [ "$(cat "$o/sh-$k/inc-0/stdout")" = "heal: $want" ] || die "sh, nodes $k: $(cat "$o/sh-$k/inc-0/stdout")"
    [ "$(jq -r '[.missing[]? | select(.name == "patina")] | length' "$o/sh-$k/result.json")" = 0 ] || die "sh, nodes $k: patina is called missing"
done
echo "from a shell script: patina ctl answers with and without nodes; patina is not called missing"

# The C SDK's control call: answers from the driver and from a node.
conf "$o/ctl.toml" c /guest/ctl node
run_ok "$o/ctl" 1 --config "$o/ctl.toml" -- /guest/ctl
d=$(cat "$o/ctl/inc-0/stdout"); n=$(cat "$o/ctl/node/c/inc-0/stdout")
want="partition driver c: ok
heal --from driver --to c: ok
partition driver nobody: ENOENT
net cut driver c: EINVAL
pause c: ok
pause c: EALREADY
resume c: ok
resume c: EALREADY
pause driver: EINVAL
clock c +1s: ok
clock driver +1s: EINVAL"
[ "$d" = "$want" ] || die "C control from the driver: $d"
[ "$n" = "heal: EPERM" ] || die "C control from a node: $n"
echo "C control: the driver's answered, a node's EPERM"

# The Rust and Go SDKs' control calls: the same answers (errno 2 ENOENT, 1 EPERM).
[ "${CHECK_TIER:-}" != quick ] || exit 0
for sdk in rs go; do
    rm -f "$o/ctl-$sdk.toml"
    conf "$o/ctl-$sdk.toml" c /guest/sdk-$sdk control node
    run_ok "$o/ctl-$sdk" 1 --config "$o/ctl-$sdk.toml" -- /guest/sdk-$sdk control
    d=$(cat "$o/ctl-$sdk/inc-0/stdout"); n=$(cat "$o/ctl-$sdk/node/c/inc-0/stdout")
    [ "$d" = "partition driver c: ok
heal: ok
partition driver nobody: errno 2" ] || die "$sdk control from the driver: $d"
    [ "$n" = "heal: errno 1" ] || die "$sdk control from a node: $n"
done
echo "Rust and Go control: the driver's answered, a node's EPERM"
