# 8. Host paths. A program given by a host path runs from there, so the files beside it are
#    there by their own paths (a shell given a script beside it, which runs a program beside
#    itself), also through a symlinked directory and from inside a mount whose symlink leads out
#    of it. A file or program the guest looks for that the sandbox lacks and the host has is named
#    in result.json with a directory to mount, and mounting it makes the run pass; a program
#    run by name is named with where the host's PATH has it.
#@ tier=quick budget=5 arch=x86_64
. "$(dirname "$0")/lib.inc"
d=$RUNS/paths
mkdir -p "$d/real/bin" "$d/proj" "$d/data" "$d/hostbin"
ln -sfn "$d/real" "$d/proj/build"
cp "$PATINA_GUESTS/hello-static" "$d/real/bin/hello"
cp /usr/bin/dash "$d/real/bin/sh"
printf '#!/bin/sh\nexec "$(dirname "$0")/hello" "$@"\n' >"$d/real/bin/run.sh"
printf '#!/bin/sh\necho tool\n' >"$d/hostbin/mytool"
echo data >"$d/data/x"
chmod +x "$d/real/bin/run.sh" "$d/hostbin/mytool"

# The sibling, by the program's own path: given directly, through the symlink, and from a mount
# of the project whose `build` links outside it.
for how in direct link mount; do
    case $how in
        direct) set -- -- "$d/real/bin/sh" "$d/real/bin/run.sh" one ;;
        link) set -- -- "$d/proj/build/bin/sh" "$d/proj/build/bin/run.sh" one ;;
        mount) set -- --mount "$d/proj:$d/proj" -- "$d/proj/build/bin/sh" "$d/proj/build/bin/run.sh" one ;;
    esac
    prun "$d/sib-$how" --seed 1 "$@"
    [ "$st" = 0 ] || die "sibling ($how): exit $st ($(tail -3 "$d/sib-$how.txt"))"
    grep -qx 'arg 1 one' "$d/sib-$how/inc-0/stdout" || die "sibling ($how): $(head -3 "$d/sib-$how/inc-0/stdout")"
done
echo "a program finds its sibling by its own path: given directly, through a symlink, inside a mount"

# A host file the sandbox lacks: named with a directory to mount; mounted, the run passes.
prun "$d/miss" --seed 1 -- /bin/cat "$d/data/x"
[ "$st" = 1 ] || die "missing file: exit $st"
m=$(field "$d/miss/result.json" missing)
mount=$(python3 -I -c 'import json,sys; m=json.loads(sys.argv[1]); print(next(x["mount"] for x in m if x["path"] == sys.argv[2]))' "$m" "$d/data/x") \
    || die "missing file: not named: $m"
prun "$d/found" --seed 1 --mount "$mount:$mount" -- /bin/cat "$d/data/x"
[ "$st" = 0 ] || die "with --mount $mount:$mount: exit $st ($(tail -3 "$d/found.txt"))"
[ "$(field "$d/found/result.json" missing)" = "[]" ] || die "mounted, still missing: $(field "$d/found/result.json" missing)"
echo "a missing host file is named with $mount to mount; mounted, the run passes"

# A program run by name that is not on the guest's PATH: named, with the host's, after the
# guest has looked for many files of the sandbox's own that it lacks (as an interpreter does).
st=0
PATH="$d/hostbin:$PATH" timeout 60 "$PATINA" run --seed 1 --out "$d/named" -- /usr/bin/python3 -c '
import os, subprocess
for i in range(100): os.path.exists(f"/usr/lib/no-such-{i}")
subprocess.run(["mytool"])' >"$d/named.txt" 2>&1 || st=$?
python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1]))["missing"]
sys.exit(0 if any(x.get("name") == "mytool" and x.get("host") == sys.argv[2] for x in m) else 1)' \
    "$d/named/result.json" "$d/hostbin/mytool" || die "a program run by name: $(field "$d/named/result.json" missing)"
echo "a program run by name and missing from the guest's PATH: named, with the host's $d/hostbin/mytool"
