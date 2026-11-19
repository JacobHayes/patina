# 9. A boundary record hashes an epoll event's fields, never its padding (arm64: bytes 4 to 8,
#    which the kernel neither reads nor writes and the program may leave as anything): the
#    epoll-pad guest's two EPOLL_CTL_MOD calls, whose events differ only there, have one input
#    hash, and its two epoll_wait calls, into buffers prefilled differently, one output hash.
#@ tier=quick budget=10
. "$(dirname "$0")/lib.inc"
case $(uname -m) in x86_64) echo "SKIP: x86_64's struct epoll_event has no padding: the hashes are equal by layout" ;; esac
o=$RUNS/09-epoll-pad
run_ok "$o" 1 -- /guest/epoll-pad
[ "$(cat "$o/inc-0/stdout")" = "ok 1 1" ] || die "guest: $(cat "$o/inc-0/stdout")"
"$PATINA" log dump "$o/inc-0/boundary.log" >"$o/dump.txt"
# epoll_ctl with op 3 (EPOLL_CTL_MOD): the input hashes; epoll_wait or epoll_pwait: the output hashes.
mods=$(awk '$5 == "epoll_ctl" && $8 == "0x3," {print $NF}' "$o/dump.txt")
waits=$(awk '($5 == "epoll_wait" || $5 == "epoll_pwait") && $0 ~ / ret=1 / {print $(NF-1)}' "$o/dump.txt")
[ "$(echo "$mods" | wc -l)" = 2 ] && [ "$(echo "$waits" | wc -l)" = 2 ] || die "records not found: mods '$mods' waits '$waits'"
[ "$(echo "$mods" | sort -u | wc -l)" = 1 ] || die "EPOLL_CTL_MOD input hashes differ with the padding: $mods"
[ "$(echo "$waits" | sort -u | wc -l)" = 1 ] || die "epoll_wait output hashes differ with the padding: $waits"
echo "epoll records: one input hash ($(echo "$mods" | head -1)), one output hash ($(echo "$waits" | head -1))"
