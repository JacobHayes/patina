//! The asynchronous I/O family: Linux native AIO and io_uring, the
//! submission/completion interfaces the io_uring arc models over the
//! readiness reactor.

pub mod aio;
pub mod io_uring;
