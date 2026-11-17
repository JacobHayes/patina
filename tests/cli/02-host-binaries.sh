# 2. `patina run --seed 5 -- PROGRAM ARGS` with no other flag: a static and a dynamic binary
#    given by a relative host path (run from where they are, named by the path as given: the
#    checks' directory is reached through a symlink), and `python3 -c` found on the guest
#    PATH. Each is ok, its stdout as expected, its run directory under ./patina-out.
#@ tier=quick budget=10 arch=x86_64
. "$(dirname "$0")/lib.inc"
d=$RUNS/host
mkdir -p "$d"
cp "$PATINA_GUESTS/hello-static" "$PATINA_GUESTS/hello-dyn" "$d/"
cd "$d"
for g in hello-static hello-dyn; do
    st=0
    timeout 60 "$PATINA" run --seed 5 -- "./$g" one two >"$g.txt" 2>&1 || st=$?
    [ "$st" = 0 ] || die "$g: exit $st ($(tail -2 "$g.txt"))"
    r=patina-out/run-5/result.json
    [ "$(field "$r" outcome)" = ok ] || die "$g: $(field "$r" outcome)"
    head -3 patina-out/run-5/inc-0/stdout | tr '\n' ';' | grep -qx "arg 0 $d/$g;arg 1 one;arg 2 two;" \
        || die "$g: stdout $(head -3 patina-out/run-5/inc-0/stdout)"
    echo "$g: ok, digest $(field "$r" digest)"
done
st=0
timeout 60 "$PATINA" run --seed 5 -- python3 -c 'import sys; print("py", sys.argv[1:])' x >py.txt 2>&1 || st=$?
[ "$st" = 0 ] || die "python3 -c: exit $st ($(tail -2 py.txt))"
grep -q "py \['x'\]" patina-out/run-5/inc-0/stdout || die "python3 -c: stdout $(cat patina-out/run-5/inc-0/stdout)"
echo "python3 -c: ok"
