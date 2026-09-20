//! Runtime registry facade. Kernel identity and support metadata are shared,
//! while the libc symbol surface remains separate from raw syscall identities.
pub use patina_dst_syscalls::*;
