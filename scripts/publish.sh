#!/usr/bin/env bash
# publish.sh — crates.io release gate for the Patina workspace.
#
# The default mode is a DRY RUN and uploads nothing: it prints the packaged file
# list of every publishable member (so a missing license, readme, C source, or
# test fixture is visible before it is missing on crates.io), asserts each
# package carries both license texts, and runs `cargo publish --workspace
# --dry-run`, which packages and verify-builds every member in dependency order.
#
# `--execute` performs the real upload, and only when BOTH hold:
#   * the working tree is clean (git: `git status --porcelain` is empty;
#     a non-colocated jj workspace: the working-copy commit `@` is empty), and
#   * the commit being published carries the git tag `v<workspace version>`
#     (git: a tag pointing at HEAD; jj: a tag on `@-`, the parent of the empty
#     working-copy commit).
# Every unmet precondition is named before refusing. The tag is never created
# here: tag deliberately, then publish.
#
# Exit codes: 0 = success, 1 = refused or a cargo step failed, 2 = bad usage.

set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/publish.sh [--execute]

  (no flag)  Dry run. Prints every publishable crate's packaged file list,
             checks each carries LICENSE-MIT and LICENSE-APACHE, then runs
             `cargo publish --workspace --dry-run`. Nothing is uploaded.
  --execute  Publish the workspace to crates.io. Refuses, naming what is
             missing, unless the working tree is clean and the current commit
             carries the git tag v<workspace version>.
EOF
}

mode=dry-run
case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") ;;
  --execute) mode=execute ;;
  *) printf 'publish.sh: unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
esac
if [ $# -gt 1 ]; then
  printf 'publish.sh: too many arguments\n' >&2; usage >&2; exit 2
fi

cd "$(dirname "$0")/.."

# The workspace version, from cargo's own view of the SDK crate (every member
# inherits `version.workspace`). pkgid ends in `@<version>` (or `#<version>`
# when the package name equals its directory name).
pkgid=$(cargo pkgid -p patina-dst)
version=${pkgid##*[@#]}
if ! [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+].*)?$ ]]; then
  printf 'publish.sh: could not read the workspace version from pkgid %q\n' "$pkgid" >&2
  exit 1
fi
tag="v$version"

# (1) Execute preconditions: refuse unless clean and tagged, before any
# packaging work. Both checks run so a refusal names everything missing at once.
if [ "$mode" = execute ]; then
  missing=()
  if git rev-parse HEAD >/dev/null 2>&1; then
    vcs=git
    dirty=$(git status --porcelain)
    tags_here=$(git tag --points-at HEAD)
    commit=$(git rev-parse HEAD)
  elif jj root >/dev/null 2>&1; then
    vcs=jj
    # A clean jj working copy is an empty `@`; the commit under release is then `@-`.
    dirty=$(jj log -r @ --no-graph -T 'diff.summary()')
    tags_here=$(jj log -r '@- & tags()' --no-graph -T 'tags.map(|t| t.name()).join("\n")')
    commit=$(jj log -r @- --no-graph -T 'commit_id')
  else
    printf 'publish.sh: refusing: neither git nor jj recognises %s as a repository\n' "$PWD" >&2
    exit 1
  fi
  if [ -n "$dirty" ]; then
    missing+=("the working tree is not clean ($vcs):"$'\n'"$(printf '%s\n' "$dirty" | sed 's/^/      /')")
  fi
  if ! printf '%s\n' "$tags_here" | grep -qx "$tag"; then
    if [ -n "$tags_here" ]; then
      missing+=("tag $tag does not point at the current commit $commit (tags there: $(printf '%s' "$tags_here" | tr '\n' ' '))")
    else
      missing+=("tag $tag does not point at the current commit $commit (no tag does; create it deliberately, e.g. git tag -a $tag)")
    fi
  fi
  if [ ${#missing[@]} -gt 0 ]; then
    printf 'publish.sh: REFUSING to publish %s:\n' "$tag" >&2
    for reason in "${missing[@]}"; do
      printf '  - %s\n' "$reason" >&2
    done
    exit 1
  fi
fi

# (2) Package listing audit. Publishable members are the workspace crates whose
# manifest does not opt out with `publish = false`. Cargo does not fail a
# package that lacks its license texts, so that is asserted here: the root
# LICENSE-* files reach each package through per-crate symlinks, which cargo
# dereferences into real files in the .crate.
audit_failures=0
publishable=()
skipped=()
for manifest in crates/*/Cargo.toml; do
  name=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$manifest" | head -1)
  if [ -z "$name" ]; then
    printf 'publish.sh: no package name in %s\n' "$manifest" >&2
    exit 1
  fi
  if grep -q '^publish = false$' "$manifest"; then
    skipped+=("$name")
    continue
  fi
  publishable+=("$name")
  printf '== %s (%s)\n' "$name" "$manifest"
  files=$(cargo package -p "$name" --no-verify --allow-dirty --list)
  printf '%s\n' "$files" | sed 's/^/   /'
  for license in LICENSE-MIT LICENSE-APACHE; do
    if ! printf '%s\n' "$files" | grep -qx "$license"; then
      printf '   MISSING %s (add the symlink: ln -s ../../%s %s/%s)\n' \
        "$license" "$license" "$(dirname "$manifest")" "$license" >&2
      audit_failures=$((audit_failures + 1))
    fi
  done
done
if [ ${#publishable[@]} -eq 0 ]; then
  printf 'publish.sh: found no publishable crates under crates/\n' >&2
  exit 1
fi
printf '== %d publishable crates at version %s' "${#publishable[@]}" "$version"
if [ ${#skipped[@]} -gt 0 ]; then
  printf '; skipped (publish = false): %s' "${skipped[*]}"
fi
printf '\n'
if [ "$audit_failures" -gt 0 ]; then
  printf 'publish.sh: %d package(s) lack a license text; see MISSING lines above\n' "$audit_failures" >&2
  exit 1
fi

# (3) Dry run: package + verify-build every member, upload nothing.
if [ "$mode" = dry-run ]; then
  printf '== cargo publish --workspace --dry-run\n'
  cargo publish --workspace --dry-run --allow-dirty
  printf 'publish.sh: DRY RUN PASSED for %s (%d crates); nothing was uploaded\n' \
    "$tag" "${#publishable[@]}"
  exit 0
fi

printf '== publishing %s (%d crates) from %s commit %s\n' "$tag" "${#publishable[@]}" "$vcs" "$commit"
cargo publish --workspace
printf 'publish.sh: PUBLISHED %s (%d crates)\n' "$tag" "${#publishable[@]}"
