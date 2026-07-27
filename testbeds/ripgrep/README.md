# ripgrep testbed

Native-only test scaffolding for running [ripgrep](https://github.com/BurntSushi/ripgrep)
as the first real-world OSS target under Patina. **This phase is native only** —
it fetches and builds ripgrep normally and exercises it over a deterministic
corpus to establish a reproducible baseline. Running ripgrep *under* Patina is a
later change; `run-patina.sh` is an untested sketch of that future invocation.

## Layout

| Path | Committed? | What |
|------|-----------|------|
| `fetch.sh` | yes | Clone ripgrep at a pinned tag into `upstream/`. |
| `gen-corpus.sh` | yes | Generate the deterministic search corpus. |
| `run-native.sh` | yes | Build ripgrep + run the search battery, snapshot-compared. |
| `run-patina.sh` | yes | **UNTESTED SKETCH** of the future `cargo patina` run. |
| `expected/` | yes | Checked-in stdout + exit-code snapshots for the battery. |
| `upstream/` | no (gitignored) | Fetched ripgrep source. |
| `corpus/` | no (gitignored) | Generated corpus (reproducible from `gen-corpus.sh`). |
| `out/`, `out-patina/` | no (gitignored) | Per-run capture directories. |

## Pin

- Tag: **15.2.0**
- Commit (dereferenced annotated tag): **`e89fff89ac9af12e8d4ce9d5fd07beb408ca730f`**

`fetch.sh` clones `--depth 1 --branch 15.2.0` and then asserts `HEAD` equals the
pinned commit, so a moved or re-pointed upstream tag fails loudly instead of
silently changing what gets built. Re-running `fetch.sh` over an existing
`upstream/` verifies the pin rather than re-cloning.

## Quick start

```sh
./fetch.sh          # clone ripgrep 15.2.0 into upstream/ (idempotent)
./gen-corpus.sh     # write corpus/ (deterministic; safe to re-run)
./run-native.sh     # build rg, run the battery, compare to expected/
```

`run-native.sh` is self-contained: it runs `fetch.sh`, builds ripgrep
(`cargo build --release`, default features), regenerates `corpus/`, then runs
the battery. The first invocation records `expected/` as the baseline; every
later invocation must reproduce those snapshots byte-for-byte or it exits
nonzero.

## Corpus

`gen-corpus.sh` builds a **fully deterministic** tree (no timestamps, no
randomness, no host/user/env leakage — content is a pure function of integer
indices). Two independent generations are byte-identical:

```sh
./gen-corpus.sh --verify    # generate twice into temp dirs; diff -r them
```

Contents (~214 files, ≥3 directory levels):

- **ASCII prose** — `docs/guide/*.txt`, `docs/reference/api/*.txt`
- **Rust-like source** — `src/module_a/*.rs`, `src/module_b/*.rs` (for `-t rust`)
- **Multibyte UTF-8** — `data/utf8/*.txt` (accented Latin, Greek, CJK, emoji)
- **Very long lines** — `data/long/*.txt` (8 000-char lines with a trailing marker)
- **Empty files** — `data/empty/*.txt` (20 zero-byte files)
- **Binary with NUL bytes** — `data/binary/blob.bin` (256 bytes, 0x00–0xFF)
- **Ignore files** — `corpus/.gitignore` (excludes `*.log`, `/build/`) and
  `src/module_b/.gitignore` (excludes `file_2?.rs`), so ignore-respecting vs
  `-u` searches diverge by a known count
- **A relative symlink** — `corpus/link_to_readme -> README`

Deterministic markers are injected at fixed positions so searches have stable,
meaningful hit counts: `PATINA_MARKER` (8 files), whole-word `TODO`, emails
`user<N>@example.com` (5), and `DEBUG` (only inside the ignored `logs/` and
`build/`).

## The battery

All searches run with `cwd = corpus/` and target `.`, so captured paths are
relative (`./…`) and host-independent. Every command carries a fixed flag set
for determinism: `--no-mmap --color never --sort path --no-require-git
--no-ignore-parent`, and `RIPGREP_CONFIG_PATH` is cleared. stdout and the real
exit code are captured per command and diffed against `expected/`.

| Name | Exercises |
|------|-----------|
| `literal_plain` | plain literal, grep-style `path:line:text` |
| `regex_classes` | regex with `[0-9]` class and escaped `\.` |
| `case_insensitive` | `-i` (matches `PATINA`/`Patina`/`patina`) |
| `word_boundary` | `-w` whole-word `TODO` |
| `count_mode` | `-c` per-file counts |
| `files_with_matches` | `-l` file list only |
| `type_filter_rust` | `-t rust` (Rust files only; 50 = 60 `.rs` − 10 nested-ignored) |
| `type_negate` | `-T rust` (exclude Rust files) |
| `ignore_respecting` | ignore rules honored → `DEBUG` **misses** (exit 1) |
| `unrestricted` | `-u` bypasses ignores → `DEBUG` surfaces (30 hits) |
| `fixed_threads` | `-j2` over long-line files |

`--no-mmap` (spec requirement) and `--sort path` (stable order independent of
thread scheduling) apply throughout; `-j2` pins the thread count for the one
dedicated test. Because stdout is captured to a file (not a tty), the output
style flags (`--no-heading --line-number`) are set explicitly so tty detection
never changes the result.

### Why `--no-require-git --no-ignore-parent`

ripgrep only honors `.gitignore` inside a git repository by default, and it
reads ignore files from parent directories. This testbed lives inside the Patina
git repo, so without care the surrounding repo's ignore rules would leak in
(and `corpus/` is itself gitignored by a parent). `--no-require-git` makes the
in-tree `.gitignore` files authoritative regardless of git, and
`--no-ignore-parent` stops ripgrep from reading anything above `corpus/`, so the
battery result is identical no matter where the testbed is checked out.

## Definition of done (native, all verified)

- `fetch.sh` run twice: clean clone, then idempotent pin verify. ✅
- Corpus generated twice → byte-identical (`--verify`, 214 files). ✅
- ripgrep builds with default features on macOS (arm64). ✅
- `run-native.sh` full battery passes twice in a row, identical output. ✅
- Scripts are `set -euo pipefail`, quoted, and shellcheck-clean (0.11.0). ✅

## Risks for the Patina phase

These are why `run-patina.sh` is a sketch, not a working harness:

1. **mmap import even with `--no-mmap`.** ripgrep links `memmap2`; the binary
   imports `mmap`/`madvise` regardless of the runtime flag. `audit` will
   likely flag these — they must be `--allow`ed (or shimmed). Always pass
   `--no-mmap` so the *call path* is avoided even though the *symbols* remain.
2. **CPU feature detection.** ripgrep's regex/SIMD paths probe CPU features at
   runtime (`is_*_feature_detected!`, `getauxval`/`sysctl`). On aarch64 NEON is
   often unconditional; the detection calls may hit syscalls the POSIX shim does
   not yet cover, or introduce host-dependent branches.
3. **Thread-pool sizing.** ripgrep sizes its worker pool from
   `available_parallelism()` (`sysconf`/`sched_getaffinity`). For deterministic
   scheduling under Patina, pin threads explicitly — the sketch uses `-j1`. A
   host-derived pool size would be nondeterministic and stresses the scheduler.
4. **Directory iteration order.** ripgrep walks the tree via `readdir`; raw FS
   order is not guaranteed. `--sort path` (used natively too) is mandatory for
   stable output under the FS shim.
5. **tty detection / output shape.** Under Patina stdout is not a tty, so
   heading/color/line-number defaults differ. Set them explicitly (the sketch
   mirrors the native flags).
6. **Filesystem surface.** Ignore-file reading, symlink handling (`lstat`),
   binary detection (reading NUL bytes), and `stat` all exercise the FS shim;
   symlinks in particular need correct `lstat`/no-follow semantics.
7. **Avoid `--stats`/timing flags.** They fold wall-clock timing into stdout and
   would break snapshotting even under virtual time.
8. **Locale/Unicode.** Keep `LC_ALL=C` (or a pinned locale); ripgrep's Unicode
   handling and case folding should not depend on host locale.
