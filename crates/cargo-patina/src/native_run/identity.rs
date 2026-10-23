//! The native build identity: what a native recording can be replayed against.

use super::*;
use crate::run_cache::Image;
use crate::shim_build::embedded_shim_bundle_sha256;
use crate::supervisor_identity::supervisor_sha256;
use patina_dst_trace::{NativeIdentityRecord, Sha256Digest};

/// The build identity of running `image`, the guest executable, under this
/// `cargo-patina`.
///
/// The executable is hashed as the bytes the run maps, so the digest names
/// exactly the bytes the guest executes; the supervisor is named by its own
/// digest. The rest are facts of this `cargo-patina`.
pub(super) fn native_identity(image: &Image) -> Result<NativeIdentityRecord, CliError> {
    let bundle = embedded_shim_bundle_sha256();
    Ok(NativeIdentityRecord {
        executable_sha256: image.sha256(),
        supervisor_sha256: supervisor_sha256()?,
        patina_version: env!("CARGO_PKG_VERSION").to_string(),
        shim_bundle_sha256: Sha256Digest::parse(&format!("sha256:{bundle}")).map_err(|error| {
            CliError(format!(
                "the embedded shim bundle address is malformed: {error}"
            ))
        })?,
        target: env!("PATINA_BUILD_TARGET").to_string(),
    })
}

/// Why `trace` must not replay against the build `current` describes, or
/// `None` when it may. A trace without a native identity is refused as well:
/// nothing in it says which build it belongs to.
pub(super) fn native_identity_refusal(
    trace: &Path,
    recorded: Option<&NativeIdentityRecord>,
    current: &NativeIdentityRecord,
) -> Option<String> {
    let Some(recorded) = recorded else {
        return Some(format!(
            "native fingerprint mismatch: trace {} carries no native build identity, so nothing \
             says which build it replays against. Only `cargo patina run --record` of a native \
             binary records one; this trace was recorded some other way, by a patina that \
             predates build identities, or by another family. Re-record it.",
            trace.display()
        ));
    };
    let differences = recorded.differences(current);
    if differences.is_empty() {
        return None;
    }
    let differing = differences
        .iter()
        .map(|difference| {
            format!(
                "{} (trace {}, this run {})",
                difference.component, difference.recorded, difference.current
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    Some(format!(
        "native fingerprint mismatch: trace {} was recorded against a different build; differs \
         in: {differing}. The trace was recorded by \
         cargo-patina {} for {} with shim bundle {}; this run is cargo-patina {} for {} with shim \
         bundle {}. Replay it with the binary and the cargo-patina it was recorded with, or re-record it.",
        trace.display(),
        recorded.patina_version,
        recorded.target,
        recorded.shim_bundle_sha256,
        current.patina_version,
        current.target,
        current.shim_bundle_sha256,
    ))
}

/// The trace a replaying guest reads: the recording with its build identity
/// withheld. The supervisor has already checked the identity, and the
/// recorder linked into the guest refuses fields it does not know, so a guest
/// linked against a shim that predates the field would refuse its own
/// recording.
pub(super) fn withhold_native_identity(mut bundle: TraceBundle) -> TraceBundle {
    bundle.metadata.native = None;
    bundle
}

/// An anonymous file holding `bundle`, the trace channel a replaying guest
/// reads.
#[cfg(unix)]
pub(super) fn guest_trace_channel(bundle: &TraceBundle) -> Result<fs::File, CliError> {
    let bytes = bundle
        .to_bytes()
        .map_err(|error| CliError(format!("failed to encode the replay trace: {error}")))?;
    crate::crash_restart::scratch_file("replay trace channel", &bytes)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use patina_dst_trace::RunMetadata;
    use std::io::Read;

    #[test]
    fn the_guest_reads_the_trace_without_its_build_identity() {
        let mut recorded =
            TraceBundle::new(RunMetadata::new(7, "fp-test", 0, "patina"), Vec::new());
        recorded.metadata.native = Some(NativeIdentityRecord {
            executable_sha256: Sha256Digest([1; 32]),
            supervisor_sha256: Sha256Digest([2; 32]),
            patina_version: "1.0.0".into(),
            shim_bundle_sha256: Sha256Digest([3; 32]),
            target: "x86_64-unknown-linux-gnu".into(),
        });
        let mut channel = guest_trace_channel(&withhold_native_identity(recorded.clone())).unwrap();
        let mut bytes = Vec::new();
        channel.read_to_end(&mut bytes).unwrap();
        let handed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            handed["metadata"].get("native").is_none(),
            "a guest whose recorder predates the field must not be handed it"
        );
        let mut expected = recorded;
        expected.metadata.native = None;
        assert_eq!(TraceBundle::from_slice(&bytes).unwrap(), expected);
    }
}
