//! The asynchronous I/O family: Linux native AIO and io_uring, the
//! submission/completion interfaces the io_uring arc models over the
//! readiness reactor (docs/arcs/syscall-conformance.md §7).

pub mod aio;
pub mod io_uring;
