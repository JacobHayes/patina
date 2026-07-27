# ripgrep under Patina — results

Rung 2 of the Patina-on-testbeds campaign, and its CPU/filesystem-bound
performance yardstick. This records what happens when the **unmodified**
ripgrep 15.2.0 package is built and run under Patina's deterministic native
(linked-shim) runtime over the deterministic corpus, and what it proves.

- **Host:** macOS 26.5.2, arm64. Date: 2026-07-26. rustc 1.96.0.
- **Path exercised:** `cargo patina build` of a real multi-crate Cargo
  workspace binary (far beyond buggy-smoke's single source), then
  `cargo patina run` with the new `--mount` surface streaming the corpus
  into the guest filesystem. The guest is byte-for-byte upstream ripgrep.

## Result: the full 11-case battery passes under Patina

`./run-patina.sh` builds the unmodified ripgrep package under Patina and runs
the **same** battery as `run-native.sh`, comparing against the **same**
`expected/` snapshots. **22/22 pass** (11 cases × {stdout, exit}), byte-identical
to native. `run-patina.sh` exits nonzero on any mismatch.

```
run-patina: 11 cases, 22 passed, 0 failed (compared to native expected/)
```

Two environmental differences are handled, each documented and neither touching
`expected/` or ripgrep:

1. **Guest root vs cwd.** The guest cwd is the virtual root `/` and the
   in-memory filesystem is absolute-path-only, so the search target is `/`
   (the mount root) rather than native's `.`. ripgrep then prints `/docs/…`
   where native prints `./docs/…`. The **only** normalization is rewriting that
   leading `/` back to `./` on stdout (every rg output line begins with a path,
   so a leading `/` is always the path root). The traversal set and `--sort path`
   order are identical; only the root prefix differs.
2. **isatty.** Interposed to a deterministic "not a terminal" (see below), so
   heading/color/line-number defaults are host-tty-independent.

## Build

The whole ripgrep workspace builds under Patina, unmodified:

```sh
cargo patina build testbeds/ripgrep/upstream/Cargo.toml \
  --package ripgrep --bin rg --release --output testbeds/ripgrep/out-patina/rg-patina
# → PATINA_NATIVE_BUILD output=…/rg-patina   (~9 s; all crates incl. memmap2, crossbeam-deque)
```

## Corpus into the guest filesystem (the rung's structural work)

`run` had no way to put host files in front of the guest — the guest
filesystem was an empty `CrashFs`, and the guest is fully interposed so it cannot
read the host itself. Added a minimal, sound mount surface:

- **`patina-fs-mem::FsImage`** — a deterministic, self-describing codec for a
  read-only tree (directories, files, inert **no-follow** symlinks). Entries are
  sorted by path, so the encoded bytes are a pure function of the set and host
  `readdir` order never leaks. `decode` **fails closed**: it rejects a
  non-absolute path, a `.`/`..`/empty component (root escape), and any list that
  is not strictly ascending (unsorted or duplicate). Symlinks are preserved as
  symlinks, matching how a default `rg` walk `lstat`s and skips `link_to_readme`
  (which appears in **no** expected output, native or Patina).
- **`cargo patina run --mount <DIR>`** — the supervisor (which is *not*
  interposed) walks `<DIR>` into a sorted `FsImage`, streams the encoded bytes to
  the guest over an inherited descriptor (fd 4), and folds the image's SHA-256
  into the run fingerprint.
- **Shim `init_from_env`** — reads fd 4 via the existing non-interposed host
  alias and rebuilds the tree as `CrashFs::new(FsImage::decode(…).into_memfs())`.
  `CrashFs::default()` is exactly `CrashFs::new(MemFs::new())`, so a mounted run
  has the **identical** crash policy (default torn-write/durability, seed 0) — a
  mount composes with `--fs-crash-at` unchanged (test:
  `a_mounted_image_is_durable_and_composes_with_crash_injection`: the mounted
  corpus is the durable baseline and survives a crash; unsynced guest writes
  still drop).

The mount lands **read-only at the guest root `/`**; the guest cwd is `/`
(= mount root). Read-only is sufficient this round (the battery only searches).

## Pre-run audit — per-symbol disposition (reachability disproven)

ripgrep's old allow list named 28 symbols framed as "linked but unreachable."
That framing is **wrong**, and we proved it by building the actual call graph of
the linked `rg` (arm64 Mach-O, `otool -Iv` stub map + `objdump -d` BFS). A
**sound** static-reachability audit clears **zero** of them, so the honest fix is
per-symbol *interposition*, not a call-graph pass.

### Why a reachability audit cannot clear them

The subprocess-spawn family is reachable from the Rust entry by **direct calls
alone** — a `bl` chain with every edge a direct branch:

```
rg::main → rg::run → SearchWorker::<W>::search
         → grep_cli::process::CommandReaderBuilder::build
         → std::process::Command::spawn → bl _fork / bl _posix_spawnp
```

Only a **runtime flag** (`--pre`/`-z`, which this battery never sets) selects the
preprocessor at run time, and static analysis cannot prove a flag is never set —
the symbols are *runtime*-dormant, not *statically* unreachable. And a sound
treatment of indirect calls makes it worse: any reachable indirect call may reach
any address-taken function, and in a Rust binary `main` itself is address-taken
(handed to `lang_start`), so the conservative closure swallows the whole live
program. (Full write-up: `crates/patina-target/ESCAPE-CLASSES.md`, "Why
symbol-reachability, not static call-graph reachability".)

### The honest disposition (23 remaining → 0)

| Disposition | Symbols | Mechanism | Where |
|---|---|---|---|
| **Deny-trap interposition** | `fork`, `posix_spawnp`, `posix_spawn_file_actions_{init,adddup2,destroy}`, `posix_spawnattr_{init,destroy,setflags,setpgroup,setsigdefault}`, `execvp`, `waitpid`, `pipe`, `setsid`, `setgid`, `setuid`, `setpgid`, `setgroups`, `chdir`, `chroot` (20) | strong shim C def that **aborts deterministically** if ever reached — the process class is a non-goal, so a real spawn must fail loud + reproducible, never escape silently | shim (pending) |
| **Deterministic-value interposition** | `__NSGetExecutablePath`, `gethostname`, `getpwuid_r` (3) | fixed deterministic returns (isatty/confstr precedent) | shim (pending) |
| **Known-safe (pure compute)** | `memset_pattern4/8/16`, `sigaddset`, `sigemptyset` (+ `sigfillset`/`sigdelset`/`sigismember`) | added to `native_allowlisted_import` — caller-memory-only, no boundary effect | `patina-target` ✅ landed |
| **Control-plane (host-alias)** | `dlsym` | the shim's own `dlsym(RTLD_NEXT,…)` resolution primitive, baked into `shim_control_plane_symbols` — auto-allowed, not an allowance | `patina-target` ✅ (host-alias doctrine) |
| **Already interposed** | `isatty` | strong C def → deterministic non-tty | shim ✅ |

Once the deny-trap + host-state stubs land, `ALLOW_UNSUPPORTED` empties to `""`
and the gate stays **fail-closed for any new import** — strictly better than the
named downgrade on both axes: an **unqualified** audit *and* a **runtime** spawn
guard the old allow list never had. The interim `run-patina.sh` list already
dropped the 5 handled symbols (isatty, memset_pattern16, sigaddset, sigemptyset,
dlsym); the 23 pending ones stay listed by name (never `all`) until the stubs
land.

### Handoff-ready shim stub spec (drop into `c/patina_posix.c`)

**A. Process-spawn deny-traps** (each `{ patina_process_trap("<name>"); }`):

```c
static _Noreturn void patina_process_trap(const char *sym) {
    static const char a[] = "patina: process spawn reached under patina: ";
    write(2, a, sizeof a - 1); write(2, sym, strlen(sym));
    static const char b[] =
        "; the process class is a deterministic-runtime non-goal; failing closed\n";
    write(2, b, sizeof b - 1); abort();
}
```

Trap all 20: `fork`, `posix_spawnp`, `posix_spawn_file_actions_init`,
`posix_spawn_file_actions_adddup2`, `posix_spawn_file_actions_destroy`,
`posix_spawnattr_init`, `posix_spawnattr_destroy`, `posix_spawnattr_setflags`,
`posix_spawnattr_setpgroup`, `posix_spawnattr_setsigdefault`, `execvp`,
`waitpid`, `pipe`, `setsid`, `setgid`, `setuid`, `setpgid`, `setgroups`, `chdir`,
`chroot`. (Trapping the setup fns too gives the earliest, clearest failure — a
guest aborts at `posix_spawn_file_actions_init` before it can spawn.)

**B. Host-state deterministic values:**

- `int gethostname(char *n, size_t l)` → copy the constant `"patina"` (NUL-bounded
  by `l`), return `0`.
- `int getpwuid_r(uid_t, struct passwd*, char*, size_t, struct passwd **res)` →
  `*res = NULL; return 0;` — deterministic "no such user"; the guest environment
  is emptied so `home_dir()` cleanly `None`s, no host user leaks.
- `int __NSGetExecutablePath(char*, uint32_t*)` → `return -1` so
  `current_exe()` is a deterministic `Err`. (A future guest that needs
  `current_exe() → Ok` should get a **fixed virtual path** written into the
  buffer, never the host's real executable path.)

## Determinism

3 cases × 3 seeds × 3 repeats, `--record` traces + normalized stdout hashed
(`testbeds/ripgrep` — reproduce via the determinism harness in the report).
Cases: `threaded_recursive` (`-j4 -e 'fn ' /`), `sort_path` (`--sort path -l -e
Result /`), `utf8_edge` (`-e 'café|αβγδε|決定的' /`, multibyte + walks the binary
blob).

**Every (case, seed): all 3 repeats byte-identical** (one trace hash, one output
hash). **Output identical across all 3 seeds.** Traces **differ across seeds** —
proving the seed genuinely drives execution (non-vacuous), while output stays
stable:

| Case | out hash (all seeds) | trace16 seed 0 | seed 1 | seed 2 |
| --- | --- | --- | --- | --- |
| threaded_recursive | `ee3e78d8f6d74eda` | `4bfaf5bcd8e499ad` | `262537f422ed6e69` | `526777dd34104e04` |
| sort_path | `f6473071038d58d3` | `11d1a54788faeb2b` | `9397b715e80dc459` | `3dfe8ec7b965f871` |
| utf8_edge | `5668d786462e584d` | `4bfaf5bcd8e499ad` | `262537f422ed6e69` | `526777dd34104e04` |

The seed-driven trace variation is **not** thread scheduling — it is seeded
entropy feeding Rust `HashMap` `RandomState` (interposed → seeded RNG), which
reorders internal hashmap iteration and thus the boundary-op sequence, while
`--sort path` keeps the printed output stable. (`threaded_recursive` and
`utf8_edge` share per-seed trace hashes: both walk the whole corpus with the same
I/O + entropy schedule, and the trace records I/O + scheduling, not the regex.)

## The thread pool (first real thread-pool guest)

**`--sort path` forces ripgrep single-threaded** (documented rg behavior: sorting
abandons parallelism). Confirmed: `-j1` and `-j4` produce **identical** traces
under `--sort path`. So the snapshot battery, which needs `--sort` to match
native, does not exercise rg's thread pool.

Running **without `--sort`** (`-j4 -e 'fn ' /`) does. ripgrep spawns a real
managed thread pool and the runtime reports genuine, **non-vacuous** concurrency:

```
PATINA_SCHEDULE_REPORT tasks_spawned=5 max_concurrent=5 total_boundaries=1706 vacuous_threads=0 \
  task1=4y+4p task2=1676y+0p task3=5y+2p task4=5y+3p task5=5y+2p
```

Output is byte-identical across 3 repeats (`6ebd66996d8b43c3`) and across seeds —
a deterministic multi-threaded run with 5 concurrent managed tasks and zero
vacuous threads (contrast buggy-smoke's vacuous-thread canary). Honest caveat:
native `rg -j4` without `--sort` is *also* stable on this small corpus (12/12
runs identical here), so this demonstrates Patina **runs the real pool
deterministically and observably**, not that it rescues an otherwise flaky
program.

## Performance (the campaign's cost-per-test yardstick)

Median of 5, warm (first run discarded), release builds, same `rg-patina` binary.
This rung is CPU/filesystem-bound with **no** sleeps or virtual-clock shortcuts,
so unlike buggy-smoke it isolates honest interposition overhead. Native is
`rg` in `corpus/`; Patina is `run … --mount corpus --record`.

| | Native total | Patina (record) total | Ratio |
| --- | --- | --- | --- |
| 11-case battery | 0.0539 s | 0.1635 s | **3.0×** |

Per-case ratios span **2.5×–3.5×** (median ~3.0×). Replay of one case
(`fixed_threads`): **0.0107 s**, vs record 0.0176 s and native 0.0049 s — replay
is faster than record (no trace write, recorded outcomes returned).

**Trace storage per test:** ~343 KB/case mean (`type_filter_rust` 91 KB — reads
only `.rs`; `unrestricted` 405 KB — reads ignored files too); **~3.7 MB for the
whole 11-case battery**.

So the per-test cost of running a real CPU/fs-bound OSS tool deterministically is
~**3× wall time and ~343 KB of trace**.

## Replay

- **Same corpus:** `replay` of a recorded trace reproduces the run exactly
  (exit 0, identical output).
- **Different corpus → rejected, fail-closed.** Because the image SHA-256 is
  folded into the fingerprint, replaying a trace against a *different* mounted
  corpus is refused (nonzero exit, no valid output) — verified to use the **exact
  same** path as any fingerprint incompatibility (a plain `--fingerprint FP-A`
  recorded, `FP-B` replay produces the identical refusal). Without the hash fold,
  replay would ignore the swapped corpus and replay stale recorded outcomes.
  Caveat: the refusal currently surfaces as the shim's generic init-failure
  (runtime-not-installed → guest aborts) rather than a one-line "fingerprint
  mismatch"; that is pre-existing shim behavior for *all* init-time
  incompatibilities, not specific to `--mount`. Graceful surfacing is a possible
  follow-up.

## Bug found and fixed (in this rung's owned code)

`run` installed each inherited descriptor with `dup2(source, target)` in
order. With **two** inherited descriptors (the new image fd 4 *and* the trace
fd 3, i.e. any `--mount` + `--record`/`replay`), the image temp file could be
allocated on fd 3, so installing the trace at fd 3 first clobbered the image
source before it was duplicated to fd 4 → the guest crashed by signal.
buggy-smoke never hit this (one inherited fd only). Fixed by relocating every
source to a fresh high descriptor (`F_DUPFD` ≥ 10, never aliasing a target)
before installing at the fixed targets, marking the scratch copies close-on-exec.
Record/replay + mount now compose; the determinism and perf runs above exercise
the fixed path.

## Patina changes made by this rung

All additive; the shim edit was greenlit and confined to `init_from_env` (the
frozen `patina_sched_yield` / `patina_shutdown→finish()` APIs are untouched).

- `patina-fs-mem`: new `image` module — `FsImage` codec (encode/decode/
  `into_memfs`), fail-closed decode, 5 new tests (round-trip + order-independence,
  rebuild with inert symlinks, adversarial-image rejection, readdir-order
  determinism).
- `patina-runtime`: `ENV_FS_IMAGE_FD` constant.
- `cargo-patina`: `run --mount <DIR>` (image build, fd-4 streaming,
  fingerprint fold) + the descriptor-install fix above.
- `patina-native-shim`: `fs_image_filesystem` hook in `init_from_env` reading the
  image fd; `isatty` interposed to deterministic false in the POSIX C layer.
- `patina-fs-crash`: `--mount` + `--fs-crash-at` composition test.
- `crates/patina-target/ESCAPE-CLASSES.md`: *Host-state query* (`isatty`) row.
- `testbeds/ripgrep/run-patina.sh`: real self-checking harness (was a sketch).

Gates green: `patina-fs-mem`/`patina-fs-crash`/`patina-runtime`/
`patina-native-shim` unit tests, `cargo-patina` incl. `end_to_end`,
`scripts/validate-native-shim.sh`, and the native battery (`run-native.sh`)
before and after.

## Reproducing

```sh
cd /Users/jacobhayes/src/github.com/JacobHayes/patina
cargo build --release -p cargo-patina
./testbeds/ripgrep/run-native.sh      # native baseline: 22/22
./testbeds/ripgrep/run-patina.sh      # Patina battery:  22/22 (exits nonzero on any mismatch)
```
