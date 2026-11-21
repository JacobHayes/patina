# 6. io_uring_setup (Deny) gives ENOSYS and the guest continues; ptrace (Stop) ends the run as unsupported naming it.
#@ tier=quick slots=0.5
. "$(dirname "$0")/lib.inc"
out=$RUNS/06-unlisted
patina_run "$out" 1 unlisted
grep -qx 'io_uring_setup -1 errno 38' "$out/inc-0/stdout" || die "io_uring_setup did not return ENOSYS and continue"
grep -q '^ptrace returned' "$out/inc-0/stdout" && die "the guest continued after ptrace"
[ "$(field "$out/result.json" outcome)" = unsupported ] || die "class $(field "$out/result.json" outcome)"
[ "$(field "$out/result.json" stop)" = syscall ] || die "stop $(field "$out/result.json" stop)"
case $(field "$out/result.json" message) in *ptrace*) ;; *) die "message $(field "$out/result.json" message)" ;; esac
field "$out/result.json" refused | grep -q '"io_uring_setup"' || die "io_uring_setup not in refused"
echo "unlisted: ENOSYS then unsupported(ptrace)"
