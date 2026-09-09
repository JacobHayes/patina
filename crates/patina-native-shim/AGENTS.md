# Native shim agent guidance

Read the root `AGENTS.md`, `ARCHITECTURE.md`, `VALIDATION.md`, and
`crates/patina-target/ESCAPE-CLASSES.md` before changing this crate.

## Doctrine

- The shim's own host access must use private resolved aliases (`host_*` style),
  not public interposable symbols. The guest and shim may use the same native
  primitive only when the shim reaches the real host entry through the alias
  table and guest calls still bind to the interposer.
- A shared symbol allowance is not a fix. If a host effect escapes, first add or
  harden detection so the class fails loudly, then model, interpose, or deny-trap
  the specific surface.
- Dynamic resolution (`dlsym` on Linux) is a second, non-static path into libc:
  the guest never imports the name, so the pre-run audit cannot see it. It
  answers from one curated entropy routing table and NULL otherwise. Adding a
  name to that table is only legitimate when the shim already defines that symbol
  deterministically — the table returns the code the static linker would have
  bound the caller to, never a host entry, and never a public interposable symbol
  (the pointers handed out have internal linkage). Returning NULL is not
  automatically the conservative answer: for a symbol the shim models, NULL sends
  the caller down a *less* modeled fallback (this is exactly how `rand::rng()`
  ended up polling the unmodeled `/dev/random` on Linux).
- Interposer semantics should match the public path they replace. Raw-syscall
  dispatch, SUD handling, and C ABI entry points should route through the same
  runtime behavior as the corresponding POSIX interposer whenever possible.
- Descriptor tables are shared, never per-entry-path. A real guest mixes the two
  doors in one object's lifetime: `cap-std` opens its base directory through std
  (libc → the C interposer) and then does every later operation on it with raw
  syscalls (→ SUD). Anything a descriptor means — its class, its iteration state,
  where it points — therefore lives in ONE runtime table both doors consult
  (`patina_dir_is_dirfd`/`patina_dirpath` for directories), and the validation
  that mints it lives in the shared `patina_*` entry, not in either caller. A
  private fd space on one side is a descriptor the other side cannot resolve.
- A descriptor names a NODE, not a name. The shim keeps only what the filesystem
  cannot answer — which fds are directory descriptors — and asks the filesystem
  where a descriptor's node is now (`patina_dirpath` → `fs_fd_path`). A name
  cached beside a descriptor goes stale exactly where it matters: a rename
  detaches the descriptor, and a symlink planted at the vacated name silently
  captures every later resolution through it, which is the redirect a capability
  handle exists to prevent. Shim-side bookkeeping that shadows namespace state
  is a second filesystem model, and the two will disagree.
- `*at` resolution is a path spelling, not a filesystem model. `(dirfd, path)`
  resolves to an absolute path that is handed to the SAME entry the `AT_FDCWD`
  form uses; normalization (`.`, `//`, and the refusal of `..`) stays in the
  driver's one normalizer so a dirfd-relative spelling and an `AT_FDCWD`
  spelling of the same path get the same judgement.
- Metadata a guest can CHANGE has to be modeled, not synthesized. `st_mode` was a
  per-kind constant until a sandbox's own test suite needed `EACCES` to be
  distinguishable from `NotFound`; permission bits now live on the entry, change
  through interposed `chmod`/`fchmod`/`fchmodat` as recorded boundary operations,
  and are ENFORCED against the one non-root identity the runtime models. A
  fabricated constant is not a neutral default — it is an answer the guest will
  act on. The remaining synthesized fields (owner, device numbers) are the same
  hazard waiting for the guest that reads them.
- An ARGUMENT the guest supplied is not a synthesized field's smaller cousin —
  dropping it is the same bug. Every creating call carries its mode across the
  boundary (`open`'s third argument, `openat`'s, `creat`'s, `mkdir`/`mkdirat`'s,
  `mkfifo`'s), and the driver applies the modeled umask exactly where a kernel
  applies the process umask. Reconstructing a "typical" mode on the far side
  looks right for the `0o666`/`0o777` callers and silently wrong for the caller
  who asked for `0o400` — and permission enforcement then judges every later
  open against the invented value. Read the variadic mode only when the flags
  say the kernel would: `open`'s third argument is UNDEFINED without `O_CREAT`,
  so a non-creating open must record no mode at all rather than whatever
  happened to be in the register.
- A descriptor answers metadata from the FILESYSTEM, not from a copy taken when
  it was opened. `fstat` on a FIFO endpoint — the one descriptor class the
  filesystem does not hold a handle for — asks the driver about the endpoint's
  INODE, so a `chmod` after the open is visible and a hard-linked FIFO reports
  its real link count. A snapshot beside the descriptor is the same stale-cache
  bug as a cached path, one field over. There is no window where a copy answers
  instead: a descriptor is a REFERENCE on the node, so unlinking the last name
  leaves the node fully alive behind it (link count 0, live mode) and `fchmod`
  through the endpoint still reaches it. A reference the filesystem cannot see
  has to be handed to it — `fs_retain_inode` when the pipe channel behind a FIFO
  comes into existence, `fs_release_inode` when it is reclaimed — because "the
  filesystem forgot the node while the guest was still holding it" is
  indistinguishable, from the guest's side, from corruption.
- A FLAG the guest supplied is not free to conflate either. `O_PATH` and
  `O_RDONLY|O_DIRECTORY` are two different opens: the first opens nothing (the
  kernel charges nothing on the entry, and the descriptor resolves `*at` paths
  and answers `fstat` but can never be read), the second opens the directory for
  reading and costs `r`. Collapsing them charged the wrong bit on the hot path of
  every capability guest — `cap-primitives` spends most of its opens on `O_PATH`
  — and pushed the `r` check onto the LISTING, where a `chmod` after the open
  could still reach a walk already under way. Access is charged where the kernel
  charges it: once, at open. That is also why directory iteration takes a
  DESCRIPTOR (`patina_read_dir(fd, …)`) rather than a path, and why the libc
  `opendir` mints its own descriptor first instead of reading a name — the fd is
  what the permission decision was made about, and `dirfd()` on the result is
  then a real descriptor rather than a refusal.
- An entry whose NAME is filesystem state and whose BYTES are not gets ONE model
  for each half, and they stay apart. A FIFO's name lives in the deterministic
  filesystem (created, stat-ed, listed, chmod-ed, renamed, hard-linked, unlinked
  like any other) while its transfer reuses the SAME in-process pipe channel an
  anonymous `pipe`/`socketpair` uses — keyed by the entry's INODE, so two openers
  of one named pipe meet, a rename cannot split them, and a second hard link is
  a second name for the same pipe rather than a second pipe. That last property
  is why the FIFO table is inode-backed like the file table rather than holding
  its own private metadata: an identity two subsystems agree on has to be ONE
  identity, and a link table that cannot see a kind is a link table that refuses
  it. A second pipe implementation
  behind a filesystem descriptor would have to re-derive blocking, EOF and
  `EPIPE`, and the two would drift; conversely, letting the driver hold the bytes
  would make a crash model responsible for data no real FIFO ever persists. The
  seam is the one branch in `patina_open`: the driver judges existence,
  resolution and permissions and then declines to hand back a descriptor, and the
  caller reads the refused entry's kind on the failure path only.
- Model a rendezvous the way the kernel models it, counters and all. A blocking
  FIFO open waits for the PARTNER'S OPEN COUNTER to move, not for a partner to
  still be there (`fs/pipe.c:fifo_open`); waiting on presence loses the writer
  that opens and closes again before the reader is scheduled, which is precisely
  the interleaving a cooperative scheduler makes reachable. The park is the
  ordinary baton park, so the wake is another task's call and a FIFO nobody opens
  for writing is a deadlock report rather than a hang.
- When a syscall has an old and a new form the ecosystem probes in sequence
  (`faccessat`/`faccessat2`, `stat`/`statx`), model BOTH. Denying the newer one
  is technically fail-closed but the deny diagnostic then prints on every call in
  a hot loop, which is its own kind of nondeterminism-shaped noise. Reserve the
  named deny for a form with no modeled fallback (`openat2`, whose `RESOLVE_*`
  guarantees nothing here implements — and whose callers probe for exactly that
  `ENOSYS` before taking their component-wise path).
- Bootstrap and reentrancy paths are load-bearing. Avoid allocations, locks, or
  formatting in early-init/fatal paths unless the path is proven safe under the
  custom allocator and host-collection rules.
- An entry point that can answer WITHOUT reaching `ensure_runtime` must consult
  the stored init-error state. Otherwise a failed initialization is a refusal the
  guest never sees: it runs on fabricated values and exits 0, or spins. Two such
  paths exist. The shim-bootstrap window is the larger one, and it does not close
  when initialization fails — `SHIM_BOOTSTRAP` is cleared only by a successful
  install — so enter it only through `in_shim_bootstrap`, which makes the check
  for you; do not read the flag directly (a source lint enforces both, and pins
  the window's call sites to a named list). Captured stdio is the other: it
  accepts bytes with no context installed, and shutdown then drops them. When
  adding an entry point, ask what it answers with no runtime installed; if it
  answers at all, call `abort_if_init_failed` and give it a leg in the
  cargo-patina e2e that drives each such path through a mismatched
  `--fingerprint` replay.
- Test the reentrancy, not just the answer. Aborting is not free on these paths:
  the diagnostic write flushes captured stdio, which deallocates through the
  guest's global allocator, which can come straight back through an interposed
  lock. A shim-internal call arriving while a shim spinlock is held must never be
  the one that triggers the abort.
- A trap handler must contain a determinism escape without swallowing anything
  else. Both traps (`SIGSYS` for syscall-user-dispatch, `SIGSEGV` for the
  timestamp counter) decode at the faulting IP, act only on encodings they fully
  recognize, and hand every other fault to the disposition they displaced — a
  genuine segmentation fault still kills the process, at the true address. A
  handler that "helpfully" resumes on an unrecognized fault would step the guest
  past an instruction it never executed.
- Installing a signal handler at init changes what Rust std does later. std
  installs its stack-overflow `SIGSEGV`/`SIGBUS` handlers only over `SIG_DFL`
  (`sys::pal::unix::stack_overflow::init`), and the shim arms from
  `__libc_start_main`, i.e. first — so while the timestamp-counter trap is armed
  a stack overflow dies on the default action instead of printing std's message.
  That is the accepted trade (the fault still kills, with the right address and a
  core dump); check this interaction before adding any new handler.
- A trap that the audit cleared a binary against must fail CLOSED at arming
  time. The gate decides "this binary is trap-managed here" from a marker plus a
  live platform probe; if arming then quietly did not happen, a contained escape
  becomes a silent one. Arming failures abort loudly rather than continuing
  unarmed.

## Source bundle and `links`

`cargo-patina` does not build this crate from a source checkout: it embeds the
shim's whole workspace dependency closure (this crate and the eleven runtime
crates beneath it) at its own build time and unpacks it into a per-user cache
when a guest is built, so an installed binary is self-sufficient (see
ARCHITECTURE.md "Native (linked shim)" and `crates/cargo-patina/build.rs`).

- Every closure crate declares `links = "<package-name>"` and carries a build
  script whose only job is `cargo:src_dir=$CARGO_MANIFEST_DIR`. Cargo exposes
  that to the build script of every DIRECT dependent as `DEP_<PKG>_SRC_DIR`,
  which is how `cargo-patina`'s build script learns where each crate's source
  is — the one documented channel for that, and it works the same in-tree, from
  the crates.io registry checkout, and from a git checkout. `cargo-patina`
  depends directly on all twelve crates for this reason alone; do not "clean
  up" the ones it does not otherwise use.
- `links` has a side effect: cargo refuses two versions of a `links` crate in
  one dependency graph. For a runtime with one global context that is the
  desired outcome — two runtimes in one process would be two contexts — so keep
  the declaration; the value is a name, not a native library.
- A crate added to or removed from the closure (`cargo metadata` on
  `patina-dst-native-shim`) must be added to or removed from the `links` set,
  `cargo-patina`'s direct dependencies, and the `SHIM_PACKAGES` table in its
  build script together; the build script fails loudly on a missing
  `DEP_*_SRC_DIR`.
- The embedded manifests are normalized (workspace inheritance resolved,
  closure deps repointed to sibling paths, dev-deps dropped). A new kind of
  workspace-inherited key (`[lints] workspace = true`, say) is refused at build
  time rather than shipped broken; extend the normalizer deliberately.
- The unpacked bundle carries no toolchain pin and no version-manager config,
  so the shim half of a native build resolves the AMBIENT toolchain. A `rustc`
  proxy that resolves per directory and has no default (a mise shim outside the
  tree it is configured for; rustup with no default toolchain) fails the
  identity probe there, and the CLI says so with the remedies. Run the runtime
  batteries through the activated environment (`mise run ...`, `mise exec --
  scripts/validate-native-shim.sh`), not with bare shims on `PATH`.

## Change checklist

- Keep C and Rust ABI signatures in lockstep. Variadic libc functions must be
  declared variadically on the host side; do not hand-declare a fixed argument
  form for a variadic function. A `patina_*` entry point has THREE declarations
  — the Rust definition, `include/patina_native.h`, and the SUD dispatcher's
  `extern` block — and changing an argument list means changing all three; the
  compiler catches two of them and the third is a link-time surprise.
- After editing `c/patina_posix.c` or related embedded C sources, rebuild
  `cargo-patina`; validating with a stale runner is an accidental false green.
- Guest binaries pick a shim change up on their own: the flags `cargo patina
  build` injects carry a hash of the shim link inputs' bytes, so Cargo relinks
  the guest whenever this crate (or the runtime beneath it) is rebuilt. A guest
  still showing the old behavior after a rebuilt `cargo-patina` is a real
  result, not a stale build.
- Run targeted shim tests and `scripts/validate-native-shim.sh` for any native
  interposition change. If the change can affect WASI or cross-target behavior,
  also run `scripts/validate-wasi.sh` and `scripts/smoke-cross-target.sh`.
- OS- or architecture-specific paths must be executed on that OS/arch before
  being described as working; cross-clippy/cross-builds are useful, but not
  execution evidence.
- The shim reads the guest's own environment — `/proc/self/maps` for the SUD
  region, the binary's mapped NAME — so a probe's FILE NAME is part of its
  input. One was named `libc-at-probe` and the legacy-glibc basename match
  (`libc-`) counted it as a second libc segment, which refused the run at
  arming time with a diagnostic about glibc's segments. The match now requires
  the version digit, but when a fresh probe fails in a way its source cannot
  explain, suspect the ambient facts (name, path, size, layout) before the
  code.
