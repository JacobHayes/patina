//! Native trace capture and unsupported sidecars.

use super::*;

/// The one sentence a run prints when its trace CHANNEL failed — the scratch
/// file could not be opened, read, or renamed. It is a fixed prefix on purpose:
/// the envelope's refusal table keys on it, so every generation that loses its
/// trace channel carries the same class and collapses onto ONE signature,
/// instead of one novel finding per scratch path. The `guest_exit_code=` that
/// follows is the status the guest itself reached, which stays the run's answer.
pub(crate) const TRACE_CHANNEL_UNAVAILABLE: &str = "patina: recorded trace channel unavailable";

/// Why a recorded trace never reached its final path.
pub(super) enum TraceCommitFailure {
    /// The recorder deliberately abandoned the trace and left an
    /// abandoned-trace marker naming why (today: the run outgrew
    /// `MAX_TRACE_BYTES`). It writes that marker only from finalization, which
    /// runs after the guest has already exited, so the run's verdict is final
    /// and stands on its own — only the replay artifact is lost. The run is
    /// reported, not failed.
    Abandoned(String),
    /// The trace CHANNEL failed: the recorder's own scratch file could not be
    /// opened, read, or renamed — it vanished under the run, its directory did,
    /// or the filesystem refused. That is an operational condition of the host,
    /// exactly like a wall-clock timeout or an OOM kill, and it says nothing
    /// about the system under test: the guest ran, and its verdict is whatever
    /// it reached. Kept apart from [`Self::Broken`] because a truncated bundle
    /// left behind by a guest that DIED mid-record is a consequence of the run
    /// and must keep failing it.
    Unavailable(String),
    /// Anything else: an empty, truncated, or corrupt trace. Nothing said why
    /// the bundle is missing, so the run cannot be trusted and fails.
    Broken(String),
}

impl TraceCommitFailure {
    pub(crate) fn reason(&self) -> &str {
        match self {
            Self::Abandoned(reason) | Self::Broken(reason) | Self::Unavailable(reason) => reason,
        }
    }
}

pub(super) struct NativeTraceSink {
    final_path: PathBuf,
    temp_path: PathBuf,
    file: Option<fs::File>,
}

impl NativeTraceSink {
    pub(super) fn create(final_path: &Path) -> Result<Self, CliError> {
        if final_path.exists() && TraceBundle::load(final_path).is_err() {
            fs::remove_file(final_path).map_err(|error| {
                CliError(format!(
                    "failed to remove incomplete existing trace {} before recording: {error}",
                    final_path.display()
                ))
            })?;
        }
        if let Some(parent) = final_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| {
                CliError(format!(
                    "failed to create trace directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        remove_dead_scratch(final_path);
        let (temp_path, file) = create_scratch(final_path).map_err(|error| {
            CliError(format!(
                "failed to create temporary trace beside {}: {error}",
                final_path.display()
            ))
        })?;
        Ok(Self {
            final_path: final_path.to_path_buf(),
            temp_path,
            file: Some(file),
        })
    }

    #[cfg(unix)]
    pub(super) fn file(&self) -> &fs::File {
        self.file.as_ref().expect("trace sink is live until commit")
    }

    /// Write a trace the supervisor assembled itself (a crash-restart run's
    /// joined incarnations) into the channel a guest otherwise writes.
    pub(super) fn write_all(&mut self, bytes: &[u8]) -> Result<(), CliError> {
        use std::io::Write;

        self.file
            .as_mut()
            .expect("trace sink is live until commit")
            .write_all(bytes)
            .map_err(|error| {
                CliError(format!(
                    "failed to write temporary trace {}: {error}",
                    self.temp_path.display()
                ))
            })
    }

    pub(super) fn commit(mut self) -> Result<PathBuf, TraceCommitFailure> {
        // Held, and with it the scratch file's lock, until the rename is done.
        let _file = self.file.take();
        if let Err(error) = TraceBundle::load(&self.temp_path) {
            // Tell "the recorder gave up, and said so" apart from "the trace
            // is simply not there". Both leave no bundle at the temp path, but
            // only the first is accompanied by an abandoned-trace marker the
            // recorder wrote deliberately AFTER the guest had already finished.
            // A guest that died mid-run leaves an empty or truncated file and
            // no marker, and that must keep failing the run.
            let abandoned = fs::read(&self.temp_path)
                .ok()
                .and_then(|bytes| parse_abandoned_trace_marker(&bytes));
            let _ = fs::remove_file(&self.temp_path);
            return Err(match abandoned {
                Some(_) => TraceCommitFailure::Abandoned(error.to_string()),
                // The scratch file could not be OPENED at all — it is gone, or
                // its directory is. The guest still ran, so this is the channel
                // failing under the run rather than the run failing.
                None if matches!(error, TraceError::Io { .. }) => {
                    TraceCommitFailure::Unavailable(error.to_string())
                }
                None => TraceCommitFailure::Broken(error.to_string()),
            });
        }
        fs::rename(&self.temp_path, &self.final_path).map_err(|error| {
            let _ = fs::remove_file(&self.temp_path);
            TraceCommitFailure::Unavailable(format!(
                "failed to atomically rename temporary trace {} to {}: {error}",
                self.temp_path.display(),
                self.final_path.display()
            ))
        })?;
        Ok(self.final_path.clone())
    }
}

impl Drop for NativeTraceSink {
    fn drop(&mut self) {
        if self.file.is_some() {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

/// Record the downgraded-symbol caveat next to a recorded trace so a later
/// reader of the artifact sees that the run was not an unconditional
/// determinism claim.
pub(super) fn write_unsupported_sidecar(
    trace: &Path,
    downgraded: &[NativeEscape],
) -> Result<(), CliError> {
    if downgraded.is_empty() {
        return Ok(());
    }
    let sidecar = {
        let mut name = trace.as_os_str().to_owned();
        name.push(".unsupported-symbols");
        PathBuf::from(name)
    };
    let mut contents = String::from(
        "# This trace was recorded with --allow-unsupported-symbols. The symbols\n\
# below are NOT interposed by the deterministic runtime; the run's determinism\n\
# is qualified. Symbol (category), followed by provenance when recoverable:\n",
    );
    for escape in downgraded {
        contents.push_str(&format!("{}\n", native_escape_summary(escape)));
        push_native_escape_provenance_lines(&mut contents, escape, "  ");
    }
    fs::write(&sidecar, contents).map_err(|error| {
        CliError(format!(
            "failed to write unsupported-symbols sidecar {}: {error}",
            sidecar.display()
        ))
    })
}

#[cfg(test)]
mod tests;
