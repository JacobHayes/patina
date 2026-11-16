#!/bin/sh
# mkcap.sh PATINA: print the path of a copy of PATINA that has CAP_PERFMON (counter preemption needs
# it in the initial user namespace). Copies are keyed by content under
# $PATINA_CHECK_DIR/cap/<sha256>/patina, so parallel checks of different trees do not clash; a
# new binary costs one `sudo -n setcap cap_perfmon+ep` on its copy, recorded in
# $PATINA_CHECK_DIR/cap/sudo-log.txt. Fails (exit 1, reason on stderr) when sudo cannot do it.
set -eu
src=$1
d=${PATINA_CHECK_DIR:?}/cap
key=$(sha256sum "$src" | cut -c1-16)
dst=$d/$key/patina
if [ -x "$dst" ] && /usr/sbin/getcap "$dst" 2>/dev/null | grep -q cap_perfmon; then echo "$dst"; exit 0; fi
mkdir -p "$d/$key"
tmp=$(mktemp "$d/$key/patina.XXXXXX")
cp "$src" "$tmp"
chmod 755 "$tmp"
if ! sudo -n setcap cap_perfmon+ep "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    echo "sudo -n setcap cap_perfmon+ep failed" >&2
    exit 1
fi
mv "$tmp" "$dst"
echo "$(date -Iseconds) sudo setcap cap_perfmon+ep $dst (copy of $src)" >>"$d/sudo-log.txt"
echo "$dst"
