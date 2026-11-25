# 10. install.sh picks the release archive by `uname -m` (a faked uname): Linux x86_64 and
#     aarch64 (and arm64) each install their own archive's binary from a local file:// release
#     and then run its `doctor`; macOS and other systems are refused, installing nothing. The
#     archives hold stand-in binaries that name their target, so no sandbox runs. It installs
#     the same way under dash and busybox sh, where this machine has them. The first line
#     names the release it installs: the latest, or with a release's copy
#     (scripts/stamp-install) that release, fetched from its own download URL (a faked curl).
#@ tier=quick budget=10 slots=0.5
. "$(dirname "$0")/lib.inc"
root=$(cd "$(dirname "$0")/../.." && pwd)
d=$RUNS/install
mkdir -p "$d/dist" "$d/bin"
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    mkdir -p "$d/$t"
    printf '#!/bin/sh\necho "%s $*" >>"%s/calls"\n' "$t" "$d" >"$d/$t/patina"
    chmod 755 "$d/$t/patina"
    tar -czf "$d/dist/patina-$t.tar.gz" -C "$d/$t" patina
done
(cd "$d/dist" && sha256sum patina-*.tar.gz >SHA256SUMS)
# try_install S M: install.sh with `uname -s` S and `uname -m` M, into $d/S-M; sets $st. The
# shell is $ish (default sh).
try_install() {
    printf '#!/bin/sh\ncase "$1" in -s) echo %s ;; -m) echo %s ;; *) exit 1 ;; esac\n' "$1" "$2" >"$d/bin/uname"
    chmod 755 "$d/bin/uname"
    rm -f "$d/calls"
    st=0
    # install.sh runs as users run it: by sh (piped into it), or by $ish
    PATH="$d/bin:$PATH" PATINA_RELEASE_URL="file://$d/dist" ${ish:-sh} "$root/install.sh" --prefix "$d/$1-$2" \
        >"$d/$1-$2.txt" 2>&1 || st=$?
}
# Where this host restricts user namespaces, install.sh also asks the binary for its AppArmor
# profile, between the two.
restricted=0
if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ] && [ -d /etc/apparmor.d ]; then
    restricted=1
fi
for case in x86_64:x86_64-unknown-linux-musl aarch64:aarch64-unknown-linux-musl arm64:aarch64-unknown-linux-musl; do
    m=${case%%:*} t=${case#*:}
    try_install Linux "$m"
    [ "$st" = 0 ] || die "Linux/$m: exit $st: $(cat "$d/Linux-$m.txt")"
    # The installed binary is the archive's: it answered --version, then doctor.
    want=$(printf '%s --version\n' "$t")
    [ "$restricted" = 0 ] || want=$(printf '%s\n%s doctor apparmor' "$want" "$t")
    want=$(printf '%s\n%s doctor' "$want" "$t")
    [ "$(cat "$d/calls")" = "$want" ] ||
        die "Linux/$m: installed the wrong binary or ran the wrong commands: $(cat "$d/calls")"
    echo "Linux/$m: installed patina-$t.tar.gz, then ran its doctor"
done
for sys in Darwin:arm64 Darwin:x86_64 Linux:riscv64 FreeBSD:amd64; do
    try_install "${sys%%:*}" "${sys#*:}"
    [ "$st" = 1 ] || die "$sys: exit $st: $(cat "$d/${sys%%:*}-${sys#*:}.txt")"
    [ ! -e "$d/${sys%%:*}-${sys#*:}" ] && [ ! -e "$d/calls" ] || die "$sys: installed something"
    echo "$sys: refused: $(cat "$d/${sys%%:*}-${sys#*:}.txt")"
done
for ish in dash "busybox sh"; do
    command -v "${ish%% *}" >/dev/null || { echo "$ish: not on this machine, not tried"; continue; }
    rm -rf "${d:?}/Linux-x86_64"
    try_install Linux x86_64
    # busybox sh may run its own uname applet, not the faked one: expect the archive for the
    # machine this shell reports.
    m=$(PATH="$d/bin:$PATH" $ish -c 'uname -m')
    case $m in x86_64) t=x86_64-unknown-linux-musl ;; *) t=aarch64-unknown-linux-musl ;; esac
    first=$(sed -n 1p "$d/calls" 2>/dev/null) || first="(no calls)"
    [ "$st" = 0 ] && [ "$first" = "$t --version" ] ||
        die "$ish (uname -m $m): exit $st, first call '$first': $(cat "$d/Linux-x86_64.txt")"
    echo "$ish: installed patina-$t.tar.gz"
done
# The release a copy installs: the first line names it, and a release's copy fetches its own.
head -n1 "$d/Linux-x86_64.txt" | grep -q '^installing the latest patina release' ||
    die "the first line does not name the release: $(head -n1 "$d/Linux-x86_64.txt")"
"$root/scripts/stamp-install" v9.8.7 >"$d/install-stamped.sh"
chmod 755 "$d/install-stamped.sh"
printf '#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) exit 1 ;; esac\n' >"$d/bin/uname"
printf '#!/bin/sh\nfor a; do last=$a; done\necho "$last" >>"%s/fetched"\nexit 22\n' "$d" >"$d/bin/curl"
chmod 755 "$d/bin/curl"
st=0
PATH="$d/bin:$PATH" "$d/install-stamped.sh" --prefix "$d/stamped" >"$d/stamped.txt" 2>&1 || st=$?
[ "$st" = 1 ] && head -n1 "$d/stamped.txt" | grep -q '^installing patina 9.8.7 from ' &&
    grep -q '/releases/download/v9.8.7/patina-' "$d/fetched" ||
    die "a stamped copy: exit $st, $(cat "$d/stamped.txt"), fetched $(cat "$d/fetched" 2>/dev/null)"
echo "a release's copy: $(head -n1 "$d/stamped.txt")"
