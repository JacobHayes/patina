# 13. (storage reproductions regression) An injected close error applies to regular files only: Linux's
# close of a directory cannot fail with EIO (Rust's std asserts on it). close #1 is a
# directory: never faulted, also not when targeted; close #2 is a file: EIO when targeted.
#@ tier=quick arch=x86_64
. "$(dirname "$0")/lib/common.inc"
d=$RUNS/13
run "$d/dir" 1 --fault fs-error-at=close:1 -- /guest/closedir
grep -qx "dir close 0 ok" "$d/dir/inc-0/stdout" || die "directory close faulted: $(cat "$d/dir/inc-0/stdout")"
run "$d/file" 1 --fault fs-error-at=close:2 -- /guest/closedir
grep -q "^file close -1 " "$d/file/inc-0/stdout" || die "file close not faulted: $(cat "$d/file/inc-0/stdout")"
echo "dir close:1 -> $(head -1 "$d/dir/inc-0/stdout"); file close:2 -> $(tail -1 "$d/file/inc-0/stdout")"
