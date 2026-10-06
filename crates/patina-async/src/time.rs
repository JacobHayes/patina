//! Virtual-time sleep and timeout futures.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use patina_dst_abi::ClockKind;
use patina_dst_runtime::RuntimeError;

use crate::executor::with_scope;

const REASON_ASYNC_SLEEP: &str = "async-sleep";
const REASON_ASYNC_TIMEOUT: &str = "async-timeout";

/// Sleep for a monotonic duration in nanoseconds of *virtual* time.
///
/// The deadline registers on the virtual clock, so an hour-long sleep resolves
/// as soon as the scheduler advances time there — no wall-clock time passes,
/// and the wake order relative to other timers is deterministic. Alias of
/// [`sleep_for`].
pub fn sleep(duration_nanos: u64) -> Sleep {
    sleep_for(duration_nanos)
}

/// Sleep for a monotonic duration in nanoseconds of virtual time. See [`sleep`].
pub fn sleep_for(duration_nanos: u64) -> Sleep {
    Sleep {
        kind: SleepKind::For(duration_nanos),
        deadline: None,
        reason: REASON_ASYNC_SLEEP,
    }
}

/// Sleep until an absolute deadline in the selected clock domain.
pub fn sleep_until(clock: ClockKind, deadline_nanos: u64) -> Sleep {
    Sleep {
        kind: SleepKind::Until(clock, deadline_nanos),
        deadline: None,
        reason: REASON_ASYNC_SLEEP,
    }
}

/// Run a future with a deterministic virtual-time timeout.
///
/// `Ok(None)` means the timeout elapsed before the inner future completed. If the
/// inner future and timeout are both ready in the same poll, the inner future wins.
/// Because the deadline lives on the virtual clock, whether a timeout fires is a
/// deterministic property of the seed — never of host scheduling luck:
///
/// ```
/// use patina_dst_async::{block_on, sleep, timeout};
/// use patina_dst_runtime::{run, RuntimeError};
///
/// let outcome = run(|ctx| {
///     block_on(ctx, async {
///         // A 5s sleep under a 1s budget: elapses in virtual time, instantly.
///         timeout(1_000_000_000, sleep(5_000_000_000)).await.unwrap()
///     })
/// })?;
/// assert!(outcome.is_none(), "the timeout deterministically fires first");
/// # Ok::<(), RuntimeError>(())
/// ```
pub fn timeout<F: Future>(duration_nanos: u64, future: F) -> Timeout<F> {
    Timeout {
        inner: Box::pin(future),
        sleep: Sleep {
            kind: SleepKind::For(duration_nanos),
            deadline: None,
            reason: REASON_ASYNC_TIMEOUT,
        },
    }
}

enum SleepKind {
    For(u64),
    Until(ClockKind, u64),
}

/// Future returned by [`sleep`], [`sleep_for`], and [`sleep_until`].
pub struct Sleep {
    kind: SleepKind,
    deadline: Option<u64>,
    reason: &'static str,
}

impl Sleep {
    fn poll_sleep(self: Pin<&mut Self>) -> Poll<Result<(), RuntimeError>> {
        let this = self.get_mut();
        let result = with_scope(|scope| {
            let deadline = if let Some(deadline) = this.deadline {
                deadline
            } else {
                // SAFETY: the scope is live for this poll on the executor thread.
                let context = unsafe { scope.context_mut() };
                let resolved = match this.kind {
                    SleepKind::For(duration) => {
                        let now = context.now(ClockKind::Monotonic)?;
                        now.saturating_add(duration)
                    }
                    SleepKind::Until(ClockKind::Monotonic, deadline) => deadline,
                    SleepKind::Until(ClockKind::Realtime, deadline) => {
                        let realtime = context.now(ClockKind::Realtime)?;
                        let monotonic = context.now(ClockKind::Monotonic)?;
                        let epoch = realtime.saturating_sub(monotonic);
                        deadline.saturating_sub(epoch)
                    }
                };
                this.deadline = Some(resolved);
                resolved
            };
            // SAFETY: the scope is live for this poll on the executor thread.
            let now = unsafe { scope.context_mut() }.now(ClockKind::Monotonic)?;
            if now >= deadline {
                Ok(true)
            } else {
                scope.register_deadline(deadline, this.reason);
                Ok(false)
            }
        });
        match result {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl Future for Sleep {
    type Output = Result<(), RuntimeError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        self.poll_sleep()
    }
}

/// Future returned by [`timeout`].
pub struct Timeout<F: Future> {
    inner: Pin<Box<F>>,
    sleep: Sleep,
}

impl<F: Future> Future for Timeout<F> {
    type Output = Result<Option<F::Output>, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if let Poll::Ready(value) = self.inner.as_mut().poll(cx) {
            return Poll::Ready(Ok(Some(value)));
        }
        match Pin::new(&mut self.sleep).poll_sleep() {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests;
