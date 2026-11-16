#!/bin/bash
# Run a command natively in a bwrap sandbox laid out like patina's (same mounts, generated /etc,
# /work and /tmp tmpfs, /in copied into /work in sorted order), without the runtime.
# usage: [STRACE=1] native.sh OUTDIR [--work DIR] [--env K=V]... -- /guest/prog args...
# stdout and stderr go to OUTDIR/stdout, OUTDIR/stderr; the exit status is the command's.
set -eu
out=$1; shift
root=
envs=()
while [ "$1" != -- ]; do
    case $1 in
        --work) root=$2; shift 2 ;;
        --env) envs+=(--setenv "${2%%=*}" "${2#*=}"); shift 2 ;;
        *) echo "native.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
shift
# STRACE=1: count the command's system calls (strace -f -c) into OUTDIR/strace.
if [ -n "${STRACE:-}" ]; then
    mkdir -p "$out"
    exec 9>"$out/strace"
    set -- /usr/bin/strace -f -c -o /dev/fd/9 "$@"
fi
mkdir -p "$out/etc"
uid=1000; gid=1000 # patina's fixed ids in the user namespace
printf 'root:x:0:0:root:/work:/bin/sh\nuser:x:%s:%s:user:/work:/bin/sh\n' "$uid" "$gid" >"$out/etc/passwd"
printf 'root:x:0:\nuser:x:%s:\n' "$gid" >"$out/etc/group"
printf '127.0.0.1 localhost sim\n::1 localhost\n' >"$out/etc/hosts"
printf 'passwd: files\ngroup: files\nhosts: files\n' >"$out/etc/nsswitch.conf"
size=268435456
b=(--unshare-all --die-with-parent --hostname sim --uid 1000 --gid 1000 --new-session --ro-bind /usr /usr
   --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/sbin /sbin
   --dev /dev --proc /proc --size $size --tmpfs /work --size $size --tmpfs /tmp
   --ro-bind "$PATINA_GUESTS" /guest
   --ro-bind /etc/ld.so.cache /etc/ld.so.cache --symlink /usr/share/zoneinfo/UTC /etc/localtime
   --ro-bind /etc/alternatives /etc/alternatives
   --ro-bind "$out/etc/passwd" /etc/passwd --ro-bind "$out/etc/group" /etc/group
   --ro-bind "$out/etc/hosts" /etc/hosts --ro-bind "$out/etc/nsswitch.conf" /etc/nsswitch.conf
   --clearenv --setenv PATH /guest:/usr/local/bin:/usr/bin:/bin --setenv HOME /work --setenv LANG C.UTF-8 --setenv PATINA 1
   --setenv TZ UTC "${envs[@]}" --chdir /work)
if [ -n "$root" ]; then
    b+=(--ro-bind "$root" /in -- /bin/sh -c 'python3 -I /guest/copytree.py /in /work && exec "$@"' sh)
else
    b+=(--)
fi
exec bwrap "${b[@]}" "$@" >"$out/stdout" 2>"$out/stderr"
