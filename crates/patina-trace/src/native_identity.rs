//! What a native recording can be replayed against.

use serde::{Deserialize, Serialize};

use crate::Sha256Digest;

/// The build a native recording belongs to, stored as
/// [`RunMetadata::native`](crate::RunMetadata::native).
///
/// The supervisor (`cargo patina run --record`) computes it and stamps it into
/// the trace when it commits the recording, so it does not depend on what the
/// recorder linked into the guest knows. `cargo patina replay` recomputes it for
/// the binary it is about to run and refuses, before the guest starts, a trace
/// whose identity differs, naming every component that does. The compatibility fingerprint string stays
/// what it was: the operator's `--fingerprint` label and the policy suffixes.
///
/// Some fields are identity, compared on replay; the rest are context, recorded
/// so a refusal and `trace info` can say what the recording was made with, and
/// never compared. [`NativeIdentityRecord::differences`] destructures every
/// field, so a field added here cannot compile until it is classified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeIdentityRecord {
    /// Identity. The SHA-256 of the executable file the run executed. The shim,
    /// the runtime, the guest's crate graph and the compiler's output are all
    /// linked into it, so any byte that differs may change what the guest does.
    pub executable_sha256: Sha256Digest,
    /// Identity. The SHA-256 of the `cargo-patina` executable that launched the
    /// guest. The supervisor builds the guest's initial state (its stack,
    /// environment block, inherited descriptors and filesystem image) and
    /// decides the host traps it arms, none of which is inside the guest's
    /// executable. Its own digest names the build exactly: the package version
    /// stays the same across development builds that behave differently.
    pub supervisor_sha256: Sha256Digest,
    /// Context. The package version of the recording `cargo-patina`, which says
    /// which release a refused trace came from.
    pub patina_version: String,
    /// Context. The content address of the shim source bundle the recording
    /// `cargo-patina` links into the binaries it builds. A binary carries the
    /// shim it was linked with, so a shim that differs already shows as a
    /// different executable; comparing this too would refuse an unchanged
    /// prebuilt binary replayed by a `cargo-patina` that embeds another bundle.
    pub shim_bundle_sha256: Sha256Digest,
    /// Context. The target triple the recording `cargo-patina` was built for:
    /// the platform the guest ran on. An executable targets one platform, so it
    /// cannot differ while the executable digest matches.
    pub target: String,
}

/// One identity component that differs between a recording and a replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeIdentityDifference {
    /// The component's name as a refusal states it.
    pub component: &'static str,
    /// The trace's value.
    pub recorded: String,
    /// The replaying build's value.
    pub current: String,
}

impl NativeIdentityRecord {
    /// The identity components in which `current` differs from this recording,
    /// in a fixed order. Empty means the replay may proceed; context fields are
    /// never compared.
    pub fn differences(&self, current: &Self) -> Vec<NativeIdentityDifference> {
        let Self {
            executable_sha256,
            supervisor_sha256,
            patina_version: _,
            shim_bundle_sha256: _,
            target: _,
        } = self;
        let mut differences = Vec::new();
        if *executable_sha256 != current.executable_sha256 {
            differences.push(NativeIdentityDifference {
                component: "executable",
                recorded: executable_sha256.to_string(),
                current: current.executable_sha256.to_string(),
            });
        }
        if *supervisor_sha256 != current.supervisor_sha256 {
            differences.push(NativeIdentityDifference {
                component: "supervisor",
                recorded: supervisor_sha256.to_string(),
                current: current.supervisor_sha256.to_string(),
            });
        }
        differences
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> NativeIdentityRecord {
        NativeIdentityRecord {
            executable_sha256: Sha256Digest([1; 32]),
            supervisor_sha256: Sha256Digest([5; 32]),
            patina_version: "1.0.0".into(),
            shim_bundle_sha256: Sha256Digest([2; 32]),
            target: "x86_64-unknown-linux-gnu".into(),
        }
    }

    #[test]
    fn an_identical_build_has_no_differences() {
        assert!(identity().differences(&identity()).is_empty());
    }

    #[test]
    fn every_identity_component_is_compared_and_named() {
        let mut current = identity();
        current.executable_sha256 = Sha256Digest([3; 32]);
        current.supervisor_sha256 = Sha256Digest([6; 32]);
        let differences = identity().differences(&current);
        let named: Vec<_> = differences.iter().map(|d| d.component).collect();
        assert_eq!(named, ["executable", "supervisor"]);
        assert_eq!(
            differences[0].recorded,
            identity().executable_sha256.to_string()
        );
        assert_eq!(
            differences[0].current,
            current.executable_sha256.to_string()
        );
    }

    #[test]
    fn context_fields_are_never_compared() {
        let mut current = identity();
        current.patina_version = "1.0.1".into();
        current.shim_bundle_sha256 = Sha256Digest([4; 32]);
        current.target = "aarch64-apple-darwin".into();
        assert!(identity().differences(&current).is_empty());
    }
}
