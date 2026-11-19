# 1. Nodes: isolation and scripted cuts. The driver and node b (tests/guests/nodes/iso.py) each
# see their own work tree, /tmp, /dev/shm, System V shared memory and hostname; b's loopback
# listener is not on its address; b's processes are ESRCH to the driver's kill and absent from
# its /proc; b gets EPERM for a control call and cannot change its view; abstract AF_UNIX names
# are refused; b's first process starts with the driver's process state; a cut stops a connect
# and a heal lets it through. Identical under verify --vary cpu,load,aslr,sandbox,repeat.
# What is not available yet is refused, naming the feature; without nodes `net` is EINVAL and
# a control mark works. The C SDK's control call answers the driver and gives a node EPERM.
#@ tier=quick budget=20
. "$(dirname "$0")/lib.inc"
o=$RUNS/01-isolation; mkdir -p "$o"
conf "$o/iso.toml" b python3 /guest/iso.py node
verify_ok "$o/iso" 1 3 --config "$o/iso.toml" -- python3 /guest/iso.py driver
sed 's/^/    /' "$o/iso/run-0/inc-0/stdout"
r=$o/iso/run-0
[ "$(field "$r/result.json" nodes.list.1.name)" = b ] || die "result.json: node b"
[ "$(field "$r/result.json" nodes.list.1.address)" = 10.0.0.2 ] || die "result.json: b's address"
[ "$(field "$r/result.json" nodes.net.heals)" -ge 1 ] || die "result.json: no heal counted"
[ -f "$r/node/b/inc-0/stdout" ] || die "no stdout for node b"
grep -q '^unix:abstract-with-nodes$' <(field "$r/result.json" refused | tr -d '[]" ' | tr , '\n') ||
    die "the abstract name is not among the refused"

# Not available yet: each refused before the run, naming what it asked for.
refused() {
    what=$1; shift
    st=0; "$PATINA" run --out "$o/refused" --mount "$PATINA_GUESTS":/guest:copy "$@" -- /bin/true >/dev/null 2>"$o/refused.err" || st=$?
    [ "$st" != 0 ] && [ ! -e "$o/refused" ] || die "$what: not refused"
    grep -q -- "$what" "$o/refused.err" || die "$what: the refusal does not name it: $(cat "$o/refused.err")"
    echo "refused: $what"
}
refused --crash --config "$o/iso.toml" --crash process
refused net-drop-permille --config "$o/iso.toml" --fault net-drop-permille=10
printf '[node.c]\ncmd = ["/bin/true"]\nrestart = true\n' >"$o/restart.toml"
refused restart --config "$o/restart.toml"
for taken in driver rest localhost; do
    printf '[node.%s]\ncmd = ["/bin/true"]\n' "$taken" >"$o/taken.toml"
    refused "node.$taken" --config "$o/taken.toml"
done

# Without nodes: no network to act on; a mark is a mark.
run_ok "$o/none" 1 -- python3 -c '
import errno, sys
sys.path.insert(0, "/guest")
import patina
patina.control("mark here")
try:
    patina.control("net heal")
except OSError as e:
    print("done" if e.errno == errno.EINVAL else e)'
[ "$(cat "$o/none/inc-0/stdout")" = done ] || die "patina ctl without nodes"
[ "$(field "$o/none/result.json" nodes 2>/dev/null || echo none)" = none ] || die "nodes in a run without them"
echo "without nodes: mark ok, net refused"

# The C SDK's control call: answers from the driver and from a node.
conf "$o/ctl.toml" c /guest/ctl node
run_ok "$o/ctl" 1 --config "$o/ctl.toml" -- /guest/ctl
d=$(cat "$o/ctl/inc-0/stdout"); n=$(cat "$o/ctl/node/c/inc-0/stdout")
want="net cut driver c: ok
net heal --from driver --to c: ok
net cut driver nobody: ENOENT
net sever driver c: EINVAL
node kill c: EOPNOTSUPP"
[ "$d" = "$want" ] || die "C control from the driver: $d"
[ "$n" = "net heal: EPERM
mark from-a-node: ok" ] || die "C control from a node: $n"
echo "C control: the driver's answered, a node's EPERM"
