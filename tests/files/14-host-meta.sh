# 14. A host-provided file shows only its path, type, mode, size, content, inode number and
#     modification time: `stat` of a mounted file, its directory and a host library under one
#     seed has the same digest after the file is read (atime) and given a hard link outside the
#     mount (link count, ctime) and a sibling is touched, and a replay of the first run is
#     identical; every host file reads one link and each of its times as its modification
#     time. A touch of the file itself (its modification time) is a change of the program's
#     inputs: the replay ends inputs-changed.
#@ tier=quick budget=15
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/14-host-meta
rm -rf "${o:?}"
mkdir -p "$o/d" "$o/elsewhere"
printf 'hello\n' >"$o/d/f"
: >"$o/d/sibling"
lib=$(readlink -f /usr/lib/x86_64-linux-gnu/libc.so.6 2>/dev/null || readlink -f /usr/lib/aarch64-linux-gnu/libc.so.6)
look() {
    "$PATINA" run --seed 1 --out "$1" --mount "$o/d:/d" -- /usr/bin/stat -c '%n %s %h %X %Y %Z %W %b %B' /d/f /d "$lib" >/dev/null 2>&1 ||
        die "stat run $1: $(field "$1/result.json" message)"
}
look "$o/a"
touch -a -d '2001-01-01' "$o/d/f"
ln "$o/d/f" "$o/elsewhere/hl"
touch "$o/d/sibling"
look "$o/b"
da=$(field "$o/a/result.json" digest)
db=$(field "$o/b/result.json" digest)
[ "$da" = "$db" ] ||
    die "digest moved by a read, a link and a sibling's touch: $(diff "$o/a/boot-1/stdout" "$o/b/boot-1/stdout")"
"$PATINA" replay "$o/a" >/dev/null 2>&1 || die "replay: $(field "$o/a/replay/result.json" message)"
# One link each; atime, ctime and btime equal to the mtime.
awk '$3 != 1 || $4 != $5 || $6 != $5 || $7 != $5 { exit 1 }' "$o/a/boot-1/stdout" ||
    die "links and times: $(cat "$o/a/boot-1/stdout")"
touch -m -d '2001-01-01' "$o/d/f"
st=0
"$PATINA" replay "$o/a" >/dev/null 2>&1 || st=$?
[ "$(field "$o/a/replay/result.json" stop)" = inputs-changed ] ||
    die "a replay after the file was touched: exit $st, stop $(field "$o/a/replay/result.json" stop)"
echo "host metadata: same digest after a read, a link and a sibling's touch ($(wc -l <"$o/a/boot-1/stdout") files), replay identical; a touch of the file is inputs-changed"
