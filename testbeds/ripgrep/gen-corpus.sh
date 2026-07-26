#!/usr/bin/env bash
#
# gen-corpus.sh - build a fully deterministic search corpus for the ripgrep
# testbed. The tree is byte-identical across regenerations: no timestamps, no
# randomness, no hostname/user/env leakage. Content is derived purely from
# integer indices, so `diff -r` of two independent generations is empty.
#
# Usage:
#   ./gen-corpus.sh [TARGET_DIR]   # generate into TARGET_DIR (default: corpus/)
#   ./gen-corpus.sh --verify       # generate twice into temp dirs; diff -r them
#
# The corpus intentionally exercises the axes the native battery searches over:
#   - nested directories (>= 3 levels deep)
#   - ~200 files of mixed content: ASCII prose, Rust-like source, multibyte
#     UTF-8, empty files, very long lines, and a binary file with NUL bytes
#   - ignore files (.gitignore) that exclude a subset (logs, build, a slice of
#     one module) so gitignore-respecting vs -u searches diverge
#   - a relative symlink

set -euo pipefail

# Force the C locale so number formatting and any byte handling stay identical
# regardless of the host's locale. UTF-8 content is emitted as literal bytes
# baked into this script, so LC_ALL=C does not corrupt it.
export LC_ALL=C

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Deterministic content helpers
# ---------------------------------------------------------------------------

# Fixed word bank. Indexing into it with pure arithmetic gives varied-looking
# but fully reproducible prose. Order and contents must never change or existing
# expected/ snapshots would drift.
WORDS=(
  alpha beta gamma delta epsilon function struct impl trait module
  error result option vector buffer parser lexer token stream schedule
  deterministic simulation runtime replay seed corpus ripgrep pattern
  search match ignore binary unicode latency fault crash recover commit
)
WORDS_LEN=${#WORDS[@]}

# emit_prose SEED NLINES
# Print NLINES lines of deterministic prose to stdout. Word choice and per-line
# word count are a pure function of (SEED, line, column).
emit_prose() {
  local seed="$1" nlines="$2"
  local i j wc widx line
  for ((i = 0; i < nlines; i++)); do
    line=""
    wc=$(( 4 + (seed * 7 + i * 5) % 8 ))
    for ((j = 0; j < wc; j++)); do
      widx=$(( (seed * 31 + i * 17 + j * 13) % WORDS_LEN ))
      if [ -z "$line" ]; then
        line="${WORDS[widx]}"
      else
        line="$line ${WORDS[widx]}"
      fi
    done
    printf '%s\n' "$line"
  done
}

# ---------------------------------------------------------------------------
# File group writers. Each writes a whole file body then a single redirect.
# ---------------------------------------------------------------------------

write_docs() {
  local root="$1"
  mkdir -p "$root/docs/guide" "$root/docs/reference/api"
  local n out body
  # docs/guide/chapter_NN.txt and docs/reference/api/section_NN.txt (level 3).
  for ((n = 1; n <= 40; n++)); do
    out=$(printf '%s/docs/guide/chapter_%02d.txt' "$root" "$n")
    body="$(emit_prose "$n" 14)"
    # Inject deterministic markers so literal/word/case searches have known,
    # stable hits. Every 5th chapter carries the marker + a TODO word.
    if (( n % 5 == 0 )); then
      body="$body"$'\n'"PATINA_MARKER present in chapter ${n}"$'\n'"TODO: revisit function boundary"
    fi
    if (( n % 7 == 0 )); then
      body="$body"$'\n'"contact user${n}@example.com for details"
    fi
    printf '%s\n' "$body" > "$out"
  done
  for ((n = 1; n <= 30; n++)); do
    out=$(printf '%s/docs/reference/api/section_%02d.txt' "$root" "$n")
    body="$(emit_prose "$(( n + 100 ))" 10)"
    if (( n % 4 == 0 )); then
      body="$body"$'\n'"see Patina runtime notes"    # mixed-case for -i tests
    fi
    printf '%s\n' "$body" > "$out"
  done
}

write_src() {
  local root="$1"
  mkdir -p "$root/src/module_a" "$root/src/module_b"
  local mod n out body
  # Rust-like source so `-t rust` type filtering is meaningful.
  for mod in module_a module_b; do
    for ((n = 1; n <= 30; n++)); do
      out=$(printf '%s/src/%s/file_%02d.rs' "$root" "$mod" "$n")
      body="// generated source unit ${mod} ${n}"$'\n'
      body="$body"$'\n'"$(emit_prose "$(( n + 200 ))" 6)"$'\n'
      body="$body"$'\n'"pub fn handler_${n}(input: &str) -> Result<usize, Error> {"$'\n'
      body="$body"$'    let count = input.len();'$'\n'
      body="$body"$'    Ok(count)'$'\n'
      body="$body"'}'
      if (( n % 6 == 0 )); then
        body="$body"$'\n'"// TODO: handle function error path"
      fi
      printf '%s\n' "$body" > "$out"
    done
  done
}

write_utf8() {
  local root="$1"
  mkdir -p "$root/data/utf8"
  local n out
  # Multibyte UTF-8: accented Latin, Greek, CJK, and an emoji. Bytes are baked
  # into this script literally, so they reproduce exactly.
  for ((n = 1; n <= 20; n++)); do
    out=$(printf '%s/data/utf8/u_%02d.txt' "$root" "$n")
    {
      printf 'accented: café résumé naïve Grüße\n'
      printf 'greek: αβγδε ΠΑΤΙΝΑ deterministic\n'
      printf 'cjk: 決定的シミュレーション 检索 パティナ\n'
      printf 'emoji: search 🔍 match ✅ file %02d\n' "$n"
      emit_prose "$(( n + 300 ))" 5
    } > "$out"
  done
}

write_long() {
  local root="$1"
  mkdir -p "$root/data/long"
  local n out long
  # Very long single lines with a trailing marker, to exercise long-line
  # handling and matching deep inside a line.
  long=$(printf 'x%.0s' $(seq 1 8000))
  for ((n = 1; n <= 10; n++)); do
    out=$(printf '%s/data/long/long_%02d.txt' "$root" "$n")
    {
      printf 'LONGLINE_START_%02d %s LONGLINE_END_MARKER\n' "$n" "$long"
      printf 'short trailing line function %02d\n' "$n"
    } > "$out"
  done
}

write_empty() {
  local root="$1"
  mkdir -p "$root/data/empty"
  local n out
  for ((n = 1; n <= 20; n++)); do
    out=$(printf '%s/data/empty/empty_%02d.txt' "$root" "$n")
    : > "$out"
  done
}

write_binary() {
  local root="$1"
  mkdir -p "$root/data/binary"
  local out i
  out="$root/data/binary/blob.bin"
  # 256 bytes cycling 0x00..0xFF via octal escapes: guaranteed NUL bytes and no
  # ASCII words that any battery pattern could match.
  {
    for ((i = 0; i < 256; i++)); do
      printf '%b' "$(printf '\\%03o' "$i")"
    done
  } > "$out"
}

write_ignored() {
  local root="$1"
  mkdir -p "$root/logs" "$root/build"
  local n out
  # logs/*.log and build/** are excluded by corpus/.gitignore. They carry the
  # DEBUG marker so gitignore-respecting vs -u searches diverge by a known count.
  for ((n = 1; n <= 20; n++)); do
    out=$(printf '%s/logs/run_%02d.log' "$root" "$n")
    {
      printf 'DEBUG log line for run %02d function trace\n' "$n"
      emit_prose "$(( n + 400 ))" 3
    } > "$out"
  done
  for ((n = 1; n <= 10; n++)); do
    out=$(printf '%s/build/artifact_%02d.txt' "$root" "$n")
    {
      printf 'DEBUG build artifact %02d function output\n' "$n"
      emit_prose "$(( n + 500 ))" 3
    } > "$out"
  done
}

write_ignore_files() {
  local root="$1"
  # Top-level ignore: logs and build directories, plus a per-module slice.
  cat > "$root/.gitignore" <<'EOF'
# Exclude generated logs and build outputs from default (ignore-respecting)
# searches. `rg -u` bypasses these rules.
*.log
/build/
EOF
  # Nested ignore excluding a subset of module_b (file_2*.rs -> 10 files).
  cat > "$root/src/module_b/.gitignore" <<'EOF'
file_2?.rs
EOF
}

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

generate() {
  local root="$1"
  rm -rf -- "$root"
  # Each writer self-provisions its own subdirectories (mkdir -p), so a vanished
  # intermediate dir cannot break generation; only the root is created here.
  mkdir -p "$root"

  printf 'ripgrep testbed corpus root\nfunction index for search\n' > "$root/README"

  write_docs "$root"
  write_src "$root"
  write_utf8 "$root"
  write_long "$root"
  write_empty "$root"
  write_binary "$root"
  write_ignored "$root"
  write_ignore_files "$root"

  # Relative symlink into the tree (rg does not follow symlinks without -L, so
  # this does not perturb default-search output).
  ln -s README "$root/link_to_readme"
}

verify() {
  local a b
  a=$(mktemp -d)
  b=$(mktemp -d)
  # shellcheck disable=SC2064  # expand paths now for the trap
  trap "rm -rf -- '$a' '$b'" EXIT
  generate "$a/corpus"
  generate "$b/corpus"
  if diff -r "$a/corpus" "$b/corpus"; then
    local count
    count=$(find "$a/corpus" -type f | wc -l | tr -d ' ')
    printf 'gen-corpus: OK, two generations byte-identical (%s files)\n' "$count"
  else
    printf 'gen-corpus: FAIL, generations differ\n' >&2
    exit 1
  fi
}

main() {
  case "${1:-}" in
    --verify)
      verify
      ;;
    "")
      generate "$SCRIPT_DIR/corpus"
      printf 'gen-corpus: wrote %s/corpus\n' "$SCRIPT_DIR"
      ;;
    *)
      generate "$1"
      printf 'gen-corpus: wrote %s\n' "$1"
      ;;
  esac
}

main "$@"
