# 1. Nodes: isolation and scripted cuts. The driver and node b (tests/guests/nodes/iso.py) each
# see their own work tree, /tmp, /dev/shm, System V shared memory and hostname; b's loopback
# listener is not on its address; b's processes are ESRCH to the driver's kill and absent from
# its /proc, and getsid/getpgid do not find them; b gets EPERM for a control call and cannot
# change its view; each node has its own abstract AF_UNIX names, and names read back carry no
# prefix; UDP between nodes carries the nodes' addresses; b's first process starts with the
# driver's process state; a cut stops a connect and loses a datagram, and a heal lets both
# through; a socket's TCP_SYNCNT and TCP_USER_TIMEOUT set its own limits across a cut. The link faults leave the
# driver's links alone unless net-links says otherwise. A node given with --node whose command
# cannot run ends the run at once, naming the node. Identical under verify --vary cpu,load,aslr,sandbox,repeat.
# What is not available yet is refused, naming the feature; without nodes `net` is EINVAL and
# a control mark works. The C, Rust and Go SDKs' control calls answer the driver and give a
# node EPERM.
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
refused --crash --config "$o/iso.toml" --crash process
refused fs-error-permille --config "$o/iso.toml" --fault fs-error-permille=10
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

# The Rust and Go SDKs' control calls: the same answers (errno 2 ENOENT, 1 EPERM).
for sdk in rs go; do
    rm -f "$o/ctl-$sdk.toml"
    conf "$o/ctl-$sdk.toml" c /guest/sdk-$sdk control node
    run_ok "$o/ctl-$sdk" 1 --config "$o/ctl-$sdk.toml" -- /guest/sdk-$sdk control
    d=$(cat "$o/ctl-$sdk/inc-0/stdout"); n=$(cat "$o/ctl-$sdk/node/c/inc-0/stdout")
    [ "$d" = "net cut driver c: ok
net heal: ok
net cut driver nobody: errno 2" ] || die "$sdk control from the driver: $d"
    [ "$n" = "net heal: errno 1" ] || die "$sdk control from a node: $n"
done
echo "Rust and Go control: the driver's answered, a node's EPERM"
