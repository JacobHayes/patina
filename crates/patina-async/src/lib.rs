//! Deterministic async for [Patina]: a single-threaded futures executor over the
//! explicit [`Context`] boundary, with virtual-time timers and simulated TCP/UDP.
//!
//! [`block_on`] drives a future to completion against a `patina-dst-runtime`
//! [`Context`], so every await point — task wakeups, [`sleep`]s, [`timeout`]s,
//! socket readiness — resolves through the deterministic scheduler and virtual
//! clock and is a pure function of the run seed. [`spawn`] adds cooperatively
//! scheduled tasks; [`TcpListener`]/[`TcpStream`]/[`UdpSocket`] provide async
//! I/O over the simulated network. Timers cost no wall-clock time, and a given
//! seed replays the same interleaving every run.
//!
//! ```
//! use patina_dst_async::{block_on, sleep, spawn};
//! use patina_dst_runtime::{run, RuntimeError};
//!
//! let value = run(|ctx| {
//!     block_on(ctx, async {
//!         let worker = spawn("worker", async {
//!             sleep(1_000_000_000).await.unwrap(); // 1s of virtual time, instantly
//!             41
//!         })
//!         .unwrap();
//!         worker.await.unwrap() + 1
//!     })
//! })?;
//! assert_eq!(value, 42);
//! # Ok::<(), RuntimeError>(())
//! ```
//!
//! # Where this crate sits
//!
//! This is the async layer of *usage mode 3* ([USAGE-MODES.md]): simulator-shaped
//! code that owns its world and performs effects through an explicit [`Context`].
//! It controls only futures built from this crate's primitives. It does **not**
//! interpose foreign async runtimes, host OS I/O, real threads, or third-party
//! futures that wait on non-Patina reactors — to run *stock tokio* unmodified,
//! use `cargo patina run`, which interposes the kqueue/epoll reactors below an
//! unchanged binary instead (see the [README]).
//!
//! # Determinism model
//!
//! Leaf futures in this crate never park or wake scheduler tasks directly. They
//! perform existing recorded boundary operations, register interests/deadlines in
//! the current poll scope, and return `Pending`; the executor emits exactly one
//! recorded scheduling operation for each pending poll. Task selection is the
//! deterministic scheduler's choice, so record/replay reproduces the exact poll
//! order, and the executor fails closed on misuse (nested [`block_on`], leaf
//! futures polled outside it, a task still live when the main future completes).
//!
//! [Patina]: https://github.com/JacobHayes/patina
//! [README]: https://github.com/JacobHayes/patina/blob/main/README.md
//! [USAGE-MODES.md]: https://github.com/JacobHayes/patina/blob/main/USAGE-MODES.md

#[cfg(doc)]
use patina_dst_runtime::Context;

mod executor;
mod tcp;
mod time;
mod udp;

pub use executor::{JoinHandle, YieldNow, block_on, spawn, yield_now};
pub use tcp::{
    AcceptFuture, ConnectFuture, ListenFuture, ReadFuture, ShutdownFuture, TcpListener, TcpStream,
    WriteAllFuture,
};
pub use time::{Sleep, Timeout, sleep, sleep_for, sleep_until, timeout};
pub use udp::{UdpBindFuture, UdpRecvFuture, UdpSendToFuture, UdpSocket};

#[cfg(test)]
mod tests;
