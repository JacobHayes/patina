#!/bin/sh
# Exec target as a #!/bin/sh script. It prints what the C target prints, by the
# means a shell has. dash cannot read its own /proc/self/exe without starting a child, and
# another process's /proc/<pid> is outside the /proc policy, so "exe" is what /proc/self/exe
# says in the child it starts (coreutils readlink, a multi-call binary).
echo "exe=$(readlink /proc/self/exe)"
i=0
echo "argv[0]=$0"
for a in "$@"; do i=$((i+1)); echo "argv[$i]=$a"; done
echo "env=${EXEC_SHOW_ENV:-(unset)}"
fds=""
for fd in 0 1 2 3 4 5 6 7 8 9; do
    if { true >&$fd; } 2>/dev/null || { true <&$fd; } 2>/dev/null; then fds="$fds$fd,"; fi
done
echo "fds=$fds"
if [ -e /proc/self/fd/3000 ]; then echo "hidden=visible"; else echo "hidden=-1,Bad file descriptor"; fi
