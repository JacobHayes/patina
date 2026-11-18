# 11. Install from a local release artifact: this build of patina, packed as this machine's
#     release archive with its SHA256SUMS, installed by install.sh from a file:// release; then
#     scripts/install-smoke.sh with the installed patina (the README's first examples built
#     outside the checkout: found, fixed, replayed).
#@ tier=release budget=30
. "$(dirname "$0")/lib.inc"
root=$(cd "$(dirname "$0")/../.." && pwd)
case $(uname -m) in aarch64) t=aarch64-unknown-linux-musl ;; *) t=x86_64-unknown-linux-musl ;; esac
d=$RUNS/release
mkdir -p "$d/dist"
tar -czf "$d/dist/patina-$t.tar.gz" -C "$(dirname "$PATINA")" patina -C "$root" LICENSE-APACHE
(cd "$d/dist" && sha256sum "patina-$t.tar.gz" >SHA256SUMS)
PATINA_RELEASE_URL="file://$d/dist" sh "$root/install.sh" --prefix "$d/prefix" >"$d/install.txt" 2>&1 ||
    die "install.sh: $(tail -5 "$d/install.txt")"
echo "installed patina-$t.tar.gz: $(grep -m1 . "$d/install.txt")"
# The smoke's projects live outside this checkout, where its toolchain file does not reach.
RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-$(awk -F'"' '/^channel/ {print $2}' "$root/rust-toolchain.toml")}
PATH="$d/prefix/bin:$PATH" RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN sh "$root/scripts/install-smoke.sh" >"$d/smoke.txt" 2>&1 ||
    die "install-smoke: $(tail -5 "$d/smoke.txt")"
tail -1 "$d/smoke.txt"
