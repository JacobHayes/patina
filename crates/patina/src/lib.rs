//! Public facade for the explicit Rust-level Patina boundary.
//!
//! The current implementation controls effects performed through [`Context`].
//! It does not yet intercept ordinary `std` APIs.

pub use patina_abi::{
    ClockKind, Datagram, EffectError, ErrorCode, Fd, FsDirectoryEntry, FsEntryKind, FsMetadata,
    OpenFlags, SeekWhence, SendDisposition, SendReport, ShutdownHow, SocketId, TaskId,
};
pub use patina_async::block_on;
pub use patina_runtime::{Context, ExecutionMode, RuntimeBuilder, RuntimeConfig, RuntimeError};

/// Deterministic async executor and network futures over the explicit boundary.
pub mod rt {
    pub use patina_abi::{Datagram, SendReport, ShutdownHow};
    pub use patina_async::{
        JoinHandle, TcpListener, TcpStream, UdpSocket, block_on, sleep, sleep_until, spawn,
        timeout, yield_now,
    };
}

/// Run a closure with deterministic default drivers configured from `PATINA_*`.
///
/// The context is always finalized. If both the closure and finalization fail,
/// the returned error retains both failures.
pub fn run<T>(
    operation: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    run_with(|builder| builder, operation)
}

/// Run with deterministic defaults after allowing typed driver replacement.
pub fn run_with<T>(
    configure: impl FnOnce(RuntimeBuilder) -> RuntimeBuilder,
    operation: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    let builder = RuntimeBuilder::new(RuntimeConfig::from_env()?).with_default_drivers();
    run_with_context(configure(builder).build()?, operation)
}

fn run_with_context<T>(
    mut context: Context,
    operation: impl FnOnce(&mut Context) -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    let run_result = operation(&mut context);
    let finish_result = context.finish();
    match (run_result, finish_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(run), Err(finalize)) => Err(RuntimeError::RunAndFinalize {
            run: Box::new(run),
            finalize: Box::new(finalize),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_reexports_explicit_configuration() {
        let mut context = Context::from_config(RuntimeConfig::seeded(5)).unwrap();
        assert_eq!(context.entropy_bytes(4).unwrap().len(), 4);
        context.finish().unwrap();
    }

    #[test]
    fn finalizes_recording_when_the_application_returns_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let trace = directory.path().join("failed-run.patina");
        let context = Context::from_config(RuntimeConfig::record(5, &trace, "fixture-v1")).unwrap();
        let result = run_with_context(context, |_| {
            Err::<(), _>(EffectError::new(ErrorCode::Denied, "application failed").into())
        });
        assert!(matches!(result, Err(RuntimeError::Effect(_))));
        assert!(trace.is_file());
    }
}
