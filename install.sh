#!/bin/sh
# Install the patina tool from a GitHub release.
#
#   curl -fsSL https://github.com/JacobHayes/patina/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/JacobHayes/patina/releases/latest/download/install.sh | sh -s -- --version 0.1.0
#
# Downloads the archive for this machine, checks it against the release's
# SHA256SUMS, and installs <prefix>/bin/patina.

set -eu

repository="https://github.com/JacobHayes/patina"

usage() {
  cat <<EOF
usage: install.sh [--version X.Y.Z] [--prefix DIR]

  --version X.Y.Z  the release to install (default: the latest)
  --prefix DIR     install DIR/bin/patina (default: ~/.local)

PATINA_RELEASE_URL names a directory URL that holds the release's files, in
place of the GitHub release (a mirror, or file:// for a local build).
EOF
}

fail() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}

version=latest
prefix=
while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || fail "--version takes a release, such as 0.1.0"; version=$2; shift 2 ;;
    --prefix) [ $# -ge 2 ] || fail "--prefix takes a directory"; prefix=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "unknown argument: $1" ;;
  esac
done
if [ -z "$prefix" ]; then
  [ -n "${HOME:-}" ] || fail "HOME is not set; pass --prefix DIR"
  prefix="$HOME/.local"
fi

system="$(uname -s)/$(uname -m)"
case "$system" in
  Linux/x86_64) target=x86_64-unknown-linux-gnu ;;
  Linux/aarch64 | Linux/arm64) target=aarch64-unknown-linux-gnu ;;
  Darwin/arm64) target=aarch64-apple-darwin ;;
  *) fail "no patina release for $system (released: Linux x86_64, Linux aarch64, macOS arm64)" ;;
esac

if [ -n "${PATINA_RELEASE_URL:-}" ]; then
  base=${PATINA_RELEASE_URL%/}
elif [ "$version" = latest ]; then
  base="$repository/releases/latest/download"
else
  base="$repository/releases/download/v${version#v}"
fi

if command -v sha256sum >/dev/null 2>&1; then
  check="sha256sum -c"
elif command -v shasum >/dev/null 2>&1; then
  check="shasum -a 256 -c"
else
  fail "neither sha256sum nor shasum is installed, so the download cannot be checked"
fi
for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done

archive="patina-$target.tar.gz"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/$archive" "$base/$archive" || fail "could not download $base/$archive"
curl -fsSL -o "$work/SHA256SUMS" "$base/SHA256SUMS" || fail "could not download $base/SHA256SUMS"
grep " $archive\$" "$work/SHA256SUMS" >"$work/expected" \
  || fail "$base/SHA256SUMS does not list $archive"
(cd "$work" && $check expected >/dev/null) || fail "$archive does not match its SHA256SUMS entry"
tar -xzf "$work/$archive" -C "$work" patina || fail "$archive holds no patina binary"

bin="$prefix/bin"
mkdir -p "$bin"
# Into place by rename, so a running patina keeps the file it started from.
cp "$work/patina" "$bin/.patina.$$"
chmod 755 "$bin/.patina.$$"
mv -f "$bin/.patina.$$" "$bin/patina"

installed=$("$bin/patina" --version) || fail "$bin/patina does not run on this machine"
printf 'installed %s\n' "$bin/patina"
printf '%s\n' "$installed" | sed 's/^/  /'

# A GitHub Actions job's later steps find it without another line of setup.
if [ -n "${GITHUB_PATH:-}" ]; then
  printf '%s\n' "$bin" >>"$GITHUB_PATH"
fi
case ":${PATH:-}:" in
  *":$bin:"*) ;;
  *) printf 'add %s to PATH to run it as `patina`\n' "$bin" ;;
esac
