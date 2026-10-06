//! Embedded native interposer sources and compile flags.

/// The POSIX interposer C translation unit, exposed as text so out-of-tree
/// tooling (`cargo patina build`) can reproduce the native link recipe from the
/// installed crate without the workspace source tree. It lives here — the crate
/// that owns `c/patina_posix.c` — so the shim's C and any embedded copy can
/// never drift, and so both this crate and `cargo-patina` package cleanly for
/// publish (each is self-contained; neither reaches across crate boundaries).
///
/// The unit is an umbrella: it `#include`s the per-family slices in
/// [`POSIX_C_FAMILY_SOURCES`], which must be staged beside it (at their
/// relative paths) before it is compiled.
pub const POSIX_C_SOURCE: &str = include_str!("../c/patina_posix.c");
/// Code-generation flags shared by the shipped POSIX object and its tests.
/// Unwind tables let glibc's forced pthread unwind cross C shim frames.
pub const POSIX_C_FLAGS: &[&str] = &[
    "-std=c11",
    "-D_POSIX_C_SOURCE=200809L",
    "-fno-stack-protector",
    "-fasynchronous-unwind-tables",
    "-Wall",
    "-Wextra",
    "-Werror",
];
/// The per-family slices `c/patina_posix.c` includes, as `(path relative to the
/// umbrella, source)`. One entry per file under `c/posix/`; the umbrella names
/// each by that relative path, so a slice added there must be added here (the
/// `posix_umbrella_includes_every_family_slice` test pins the two together).
pub const POSIX_C_FAMILY_SOURCES: &[(&str, &str)] = &[
    ("posix/core.c", include_str!("../c/posix/core.c")),
    ("posix/env.c", include_str!("../c/posix/env.c")),
    ("posix/init.c", include_str!("../c/posix/init.c")),
    ("posix/time.c", include_str!("../c/posix/time.c")),
    (
        "posix/sched_identity.c",
        include_str!("../c/posix/sched_identity.c"),
    ),
    ("posix/entropy.c", include_str!("../c/posix/entropy.c")),
    ("posix/fs.c", include_str!("../c/posix/fs.c")),
    ("posix/fd_io.c", include_str!("../c/posix/fd_io.c")),
    ("posix/mem.c", include_str!("../c/posix/mem.c")),
    (
        "posix/thread_sync.c",
        include_str!("../c/posix/thread_sync.c"),
    ),
    (
        "posix/signal_process.c",
        include_str!("../c/posix/signal_process.c"),
    ),
    (
        "posix/privileged.c",
        include_str!("../c/posix/privileged.c"),
    ),
    ("posix/net.c", include_str!("../c/posix/net.c")),
    ("posix/readiness.c", include_str!("../c/posix/readiness.c")),
    ("posix/stdio.c", include_str!("../c/posix/stdio.c")),
    ("posix/darwin.c", include_str!("../c/posix/darwin.c")),
    ("posix/dlsym.c", include_str!("../c/posix/dlsym.c")),
];
/// The companion C header for [`POSIX_C_SOURCE`] (`include/patina_native.h`).
pub const NATIVE_HEADER: &str = include_str!("../include/patina_native.h");
