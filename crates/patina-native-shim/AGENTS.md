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
- Bootstrap and reentrancy paths are load-bearing. Avoid allocations, locks, or
  formatting in early-init/fatal paths unless the path is proven safe under the
  custom allocator and host-collection rules.
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
