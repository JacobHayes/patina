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

## Change checklist

- Keep C and Rust ABI signatures in lockstep. Variadic libc functions must be
  declared variadically on the host side; do not hand-declare a fixed argument
  form for a variadic function.
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
