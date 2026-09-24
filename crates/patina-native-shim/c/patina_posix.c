/*
 * The native shim's POSIX interposer layer: one C translation unit assembled
 * from per-family slices under `c/posix/`.
 *
 * The slices are #included here, in this order, rather than compiled as
 * separate objects: the families share static helpers (the errno/deny helpers,
 * the directory-descriptor and `*at` resolution helpers, the host-alias
 * tables), and one object keeps every helper at internal linkage — a separate
 * compilation would have to export them, and every exported name is a symbol
 * the guest binary carries. `cargo patina build` stages this file and the
 * slices side by side and compiles it exactly once (see
 * `crates/cargo-patina/src/lib.rs`, `PATINA_POSIX_OBJECT`);
 * `crates/cargo-patina/tests/common` compiles the embedded source for tests.
 *
 * Ordering rules: `core.c` first (feature macros and headers), then the
 * families a later slice's static helpers depend on (`env.c` before `init.c`,
 * `init.c` before `signal_process.c`, `time.c` before `sched_identity.c`),
 * and `dlsym.c` last (its table names statics from every family).
 * The registry in `src/registry/symbols.rs` lists every public symbol these
 * slices define; the object scan gate fails on an unlisted definition.
 */
#include "posix/core.c"
#include "posix/env.c"
#include "posix/init.c"
#include "posix/time.c"
#include "posix/sched_identity.c"
#include "posix/entropy.c"
#include "posix/fs.c"
#include "posix/fd_io.c"
#include "posix/mem.c"
#include "posix/thread_sync.c"
#include "posix/signal_process.c"
#include "posix/net.c"
#include "posix/readiness.c"
#include "posix/stdio.c"
#include "posix/darwin.c"
#include "posix/dlsym.c"
