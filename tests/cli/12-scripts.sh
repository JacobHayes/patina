# 12. What the program is. A `#!` script runs as the top-level program as it does under the
#    kernel, and `execve` of each file from inside a guest answers what the native kernel
#    answers: scripts with an argument, nested interpreters down to the kernel's depth and one
#    past it, a CRLF `#!` line, a `#!` line past 255 bytes, an empty file, text without `#!`,
#    no execute permission, a truncated ELF, an ELF for the other architecture, an ELF whose
#    interpreter is a text file. Every file the
#    native kernel refuses ends a top-level run `error`, stop `exec`, naming the kernel's errno;
#    a 32-bit ELF, which the kernel runs and Patina does not, ends `unsupported`, stop `exec`. A script reached through a symlink, a relative path, the guest's PATH,
#    `--disk` and `--mount` runs; one whose interpreter the sandbox lacks is named with the
#    directory to mount, and mounting it makes the run pass. A directory or an unreadable file is
#    refused before the run. None ends `internal`. An interpreter whose symbolic link leads into
#    what Patina keeps from the program is refused as that path is. An image an `execve` inside
#    the guest resolved that the new runtime cannot load again (a memfd) is not blamed on the
#    program.
#@ tier=quick budget=10 slots=0.5
. "$(dirname "$0")/lib.inc"
d=$RUNS/scripts/f
e=$RUNS/scripts/far
r=$RUNS/scripts/runs
rm -rf "${RUNS:?}/scripts"
mkdir -p "$d/dir" "$e" "$r"
mk() { printf "$2" >"$d/$1"; chmod +x "$d/$1"; }
mk ok.sh '#!/bin/sh -e\nprintf "%%s|" "$0" "$@"; echo\n'
mk nl.sh '#!/bin/sh'
mk crlf.sh '#!/bin/sh\r\necho crlf\n'
mk empty ''
mk text 'echo text\n'
mk noint '#!  \n'
mk nameless '#!'
mk long "#!/$(printf 'a%.0s' $(seq 300))\n"
mk longarg "#!/bin/echo $(printf 'b%.0s' $(seq 300))\n"
mk noexec '#!/bin/sh\necho noexec\n'
chmod -x "$d/noexec"
prev=/bin/echo
for i in 1 2 3 4 5 6; do
    mk "n$i" "#!$prev\n"
    prev=$d/n$i
done
cp /bin/true "$d/short" && truncate -s 100 "$d/short"
python3 -I - "$d" <<'EOF'
import sys
d = sys.argv[1]
b = bytearray(open("/bin/true", "rb").read())
other = bytearray(b); other[18:20] = (183 if b[18] == 62 else 62).to_bytes(2, "little")
open(f"{d}/otherarch", "wb").write(other)
b32 = bytearray(b); b32[4] = 1
open(f"{d}/elf32", "wb").write(b32)
# An ELF interpreter (PT_INTERP) that is a text file.
i = b.index(b"/lib")
end = b.index(b"\0", i)
bad = bytearray(b); bad[i:end] = b"/usr/bin/ldd".ljust(end - i, b"\0")
open(f"{d}/badinterp", "wb").write(bad)
EOF
chmod +x "$d/short" "$d/otherarch" "$d/elf32" "$d/badinterp"
ln -s ok.sh "$d/link"
cp /bin/true "$e/interp"
mk far.sh "#!$e/interp\n"
names="ok.sh nl.sh crlf.sh empty text noint nameless long longarg noexec n1 n2 n3 n4 n5 n6 short otherarch badinterp link"

# execve of each from inside a guest, and natively: errno or the output, line by line.
cat >"$d/probe.py" <<'EOF'
import os, sys
d = sys.argv[1]
for n in sys.argv[2:]:
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.dup2(w, 1)
        try:
            os.execv(f"{d}/{n}", [f"{d}/{n}", "x y"])
        except OSError as e:
            os.write(1, f"errno {e.errno}".encode())
            os._exit(0)
    os.close(w)
    out = b""
    while c := os.read(r, 4096):
        out += c
    os.close(r)
    os.waitpid(pid, 0)
    print(f"{n}: {out.decode(errors='replace').strip()}")
EOF
# shellcheck disable=SC2086
python3 -I "$d/probe.py" "$d" $names >"$d/native.txt"
# shellcheck disable=SC2086
prun "$r/probe" --seed 1 --mount "$d:$d" -- /usr/bin/python3 -I "$d/probe.py" "$d" $names
[ "$st" = 0 ] || die "in-guest probe: exit $st ($(tail -3 "$r/probe.txt"))"
diff "$d/native.txt" "$r/probe/boot-1/stdout" || die "execve inside a guest differs from the native kernel"
echo "execve inside a guest answers as the native kernel for $(wc -l <"$d/native.txt") files"

# The same files as the top-level program: what runs prints what it prints natively; what the
# kernel refuses is `error`, stop `exec`, naming its errno.
# One interpreter start per run (most of the script's time is interpreters starting): the
# outcome and stop, the name of the errno the native kernel gave (or -), then the message.
summary() { python3 -I -c 'import errno,json,sys
r = json.load(open(sys.argv[1]))
e = sys.argv[2]
print(r.get("outcome"), r.get("stop"), errno.errorcode[int(e)] if e else "-")
print(r.get("message"))' "$1" "$2"; }
error_exit=$(exit_of error)
nok=0 nerr=0
for n in $names elf32; do
    want=$(sed -n "s|^$n: ||p" "$d/native.txt")
    prun "$r/top-$n" --seed 1 -- "$d/$n" "x y"
    case $want in "errno "*) wn=${want#errno } ;; *) wn= ;; esac
    v=$(summary "$r/top-$n/result.json" "$wn")
    read -r o stop en <<<"${v%%$'\n'*}"
    msg=${v#*$'\n'}
    if [ "$n" = elf32 ]; then
        # The kernel runs it as a 32-bit program; Patina does not.
        [ "$o:$stop" = unsupported:exec ] || die "elf32: want unsupported/exec, got $o: $msg"
        continue
    fi
    case $want in
        "errno "*)
            [ "$o:$stop" = error:exec ] || die "$n: want error/exec ($en), got $o: $msg"
            grep -qw "$en" <<<"$msg" || die "$n: the message does not name $en: $msg"
            [ "$st" = "$error_exit" ] || die "$n: exit $st"
            nerr=$((nerr + 1)) ;;
        *)
            [ "$o" = ok ] || die "$n: $o: $msg"
            [ "$(tr -d '\n' <"$r/top-$n/boot-1/stdout")" = "$want" ] ||
                die "$n: stdout $(cat "$r/top-$n/boot-1/stdout"), natively $want"
            nok=$((nok + 1)) ;;
    esac
done
[ "$nok" -ge 5 ] && [ "$nerr" -ge 10 ] || die "only $nok ran and $nerr were refused"
echo "as the top-level program: $nok run as natively, $nerr end error/exec with the kernel's errno"

# Other ways to name it.
cd "$d"
prun "$r/rel" --seed 1 -- ./ok.sh a
[ "$st" = 0 ] || die "relative path: exit $st"
prun "$r/path" --seed 1 --mount "$d:/guest" -- ok.sh a
[ "$st" = 0 ] && [ "$(cat "$r/path/boot-1/stdout")" = "/guest/ok.sh|a|" ] || die "by name: exit $st: $(cat "$r/path.txt")"
prun "$r/work" --seed 1 --disk . -- ./ok.sh a
[ "$st" = 0 ] || die "--disk: exit $st"
cd - >/dev/null
prun "$r/mnt" --seed 1 --mount "$d:/m" -- /m/ok.sh a
[ "$st" = 0 ] && [ "$(cat "$r/mnt/boot-1/stdout")" = "/m/ok.sh|a|" ] || die "--mount: exit $st: $(cat "$r/mnt.txt")"
echo "a script runs by a relative path, by name on the guest's PATH, beside --disk and inside --mount"

# An interpreter the sandbox lacks: named with its directory; mounted, the run passes.
prun "$r/far" --seed 1 -- "$d/far.sh"
[ "$(field "$r/far/result.json" outcome)" = error ] || die "far interpreter: $(field "$r/far/result.json" outcome)"
python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1]))["missing"]
sys.exit(0 if any(x["path"] == sys.argv[2] and x["mount"] == sys.argv[3] for x in m) else 1)' \
    "$r/far/result.json" "$e/interp" "$e" || die "far interpreter not named: $(field "$r/far/result.json" missing)"
prun "$r/far-m" --seed 1 --mount "$e:$e" -- "$d/far.sh"
[ "$st" = 0 ] || die "with the interpreter mounted: exit $st"
echo "an interpreter outside the sandbox is named with $e to mount; mounted, the script runs"

# Refused before the run: a directory, an unreadable file.
cp "$d/ok.sh" "$d/unreadable" && chmod 0111 "$d/unreadable"
for n in dir unreadable; do
    prun "$r/pre-$n" --seed 1 -- "$d/$n"
    [ "$st" = "$error_exit" ] && [ ! -e "$r/pre-$n/result.json" ] || die "$n: exit $st"
done
echo "a directory and an unreadable file are refused before the run"

# An interpreter reached through a symbolic link into what Patina keeps from the program.
mkdir -p "$r/hid/m" "$r/hid/w"
printf '#!/m/l\n' >"$r/hid/w/s.sh" && chmod +x "$r/hid/w/s.sh"
ln -s /.patina/in/s.sh "$r/hid/m/l"
cd "$r/hid/w"
prun "$r/hid/run" --seed 1 --disk . --mount "$r/hid/m:/m" -- ./s.sh
cd - >/dev/null
[ "$(field "$r/hid/run/result.json" stop)" = exec ] || die "hidden interpreter: $(field "$r/hid/run/result.json" stop)"
python3 -I -c 'import json,sys; sys.exit(0 if "/m/l" in json.load(open(sys.argv[1]))["refused"] else 1)' \
    "$r/hid/run/result.json" || die "hidden interpreter not refused: $(field "$r/hid/run/result.json" message)"
echo "an interpreter linked into what Patina keeps is refused"

# execve of a memfd: whatever the new runtime makes of it, the program is not the one blamed.
printf 'import os\nfd = os.memfd_create("x", 0)\nos.write(fd, open("/bin/true", "rb").read())\nos.execv(f"/proc/self/fd/{fd}", ["t"])\n' >"$d/memfd.py"
prun "$r/memfd" --seed 1 --mount "$d:$d" -- /usr/bin/python3 -I "$d/memfd.py"
ms=$(field "$r/memfd/result.json" stop)
[ "$ms" != exec ] || die "a memfd execve blamed on the program: $(field "$r/memfd/result.json" message)"
echo "a memfd execve is not blamed on the program"
