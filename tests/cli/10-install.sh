# 10. install.sh picks the release archive by `uname -m` (a faked uname): Linux x86_64 and
#     aarch64 (and arm64) each install their own archive's binary from a local file:// release
#     and then run its `doctor`; macOS and other systems are refused, installing nothing. The
#     archives hold stand-in binaries that name their target, so no sandbox runs.
#@ tier=quick budget=10
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
# try_install S M: install.sh with `uname -s` S and `uname -m` M, into $d/S-M; sets $st.
try_install() {
    printf '#!/bin/sh\ncase "$1" in -s) echo %s ;; -m) echo %s ;; *) exit 1 ;; esac\n' "$1" "$2" >"$d/bin/uname"
    chmod 755 "$d/bin/uname"
    rm -f "$d/calls"
    st=0
    PATH="$d/bin:$PATH" PATINA_RELEASE_URL="file://$d/dist" sh "$root/install.sh" --prefix "$d/$1-$2" \
        >"$d/$1-$2.txt" 2>&1 || st=$?
}
for case in x86_64:x86_64-unknown-linux-musl aarch64:aarch64-unknown-linux-musl arm64:aarch64-unknown-linux-musl; do
    m=${case%%:*} t=${case#*:}
    try_install Linux "$m"
    [ "$st" = 0 ] || die "Linux/$m: exit $st: $(cat "$d/Linux-$m.txt")"
    # The installed binary is the archive's: it answered --version, then doctor.
    [ "$(cat "$d/calls")" = "$(printf '%s --version\n%s doctor' "$t" "$t")" ] ||
        die "Linux/$m: installed the wrong binary or ran the wrong commands: $(cat "$d/calls")"
    echo "Linux/$m: installed patina-$t.tar.gz, then ran its doctor"
done
for sys in Darwin:arm64 Darwin:x86_64 Linux:riscv64 FreeBSD:amd64; do
    try_install "${sys%%:*}" "${sys#*:}"
    [ "$st" = 1 ] || die "$sys: exit $st: $(cat "$d/${sys%%:*}-${sys#*:}.txt")"
    [ ! -e "$d/${sys%%:*}-${sys#*:}" ] && [ ! -e "$d/calls" ] || die "$sys: installed something"
    echo "$sys: refused: $(cat "$d/${sys%%:*}-${sys#*:}.txt")"
done
