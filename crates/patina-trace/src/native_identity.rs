//! What a native recording can be replayed against.

use serde::{Deserialize, Serialize};

use crate::Sha256Digest;

/// The build a native recording belongs to, stored as
/// [`RunMetadata::native`](crate::RunMetadata::native).
///
/// The supervisor (`patina run --record`) computes it and stamps it into
/// the trace when it commits the recording, so it does not depend on what the
/// recorder linked into the guest knows. `patina replay` recomputes it for
/// the binary it is about to run and refuses, before the guest starts, a trace
/// whose identity differs, naming every component that does. The compatibility fingerprint string stays
/// what it was: the base label and the policy suffixes.
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
    /// Identity. Every library the loader mapped beside the executable, in
    /// its search order, by the SHA-256 of the bytes the pre-run audit judged:
    /// the guest runs their code too, and binds its references by what they
    /// define, so a replay against another libc is another program.
    pub libraries: Vec<NativeLibraryIdentity>,
    /// Identity. Every program besides itself the guest could spawn (the
    /// admission table), by the path the guest names it and the SHA-256 of
    /// the artifact the run pinned: a spawned program runs its code too. A replay pins the
    /// recorded artifacts again and refuses one whose bytes changed.
    pub admitted: Vec<NativeAdmittedProgram>,
    /// Identity. The SHA-256 of the `patina` executable that launched the
    /// guest. The supervisor builds the guest's initial state (its stack,
    /// environment block, inherited descriptors and filesystem image) and
    /// decides the host traps it arms, none of which is inside the guest's
    /// executable. Its own digest names the build exactly: the package version
    /// stays the same across development builds that behave differently.
    pub supervisor_sha256: Sha256Digest,
    /// Context. The package version of the recording `patina`, which says
    /// which release a refused trace came from.
    pub patina_version: String,
    /// Context. The content address of the shim source bundle the recording
    /// `patina` links into the binaries it builds. A binary carries the
    /// shim it was linked with, so a shim that differs already shows as a
    /// different executable; comparing this too would refuse an unchanged
    /// prebuilt binary replayed by a `patina` that embeds another bundle.
    pub shim_bundle_sha256: Sha256Digest,
    /// Context. The target triple the recording `patina` was built for:
    /// the platform the guest ran on. An executable targets one platform, so it
    /// cannot differ while the executable digest matches.
    pub target: String,
}

/// One library a native recording ran with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLibraryIdentity {
    /// The dependency name the loader mapped it under (`libc.so.6`).
    pub name: String,
    pub sha256: Sha256Digest,
}

/// One program a native recording could spawn, and whether it was admitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAdmittedProgram {
    /// The path the guest names the program by: where Cargo installs a
    /// package's binary (`CARGO_BIN_EXE_*`). The guest itself is admitted
    /// too, but by where its binary sits, which no recording names.
    pub program: String,
    /// Context. The host artifact that stands in for it, which a replay
    /// pins again; never compared.
    pub artifact: String,
    /// The artifact's digest; `None` when no artifact was built.
    pub sha256: Option<Sha256Digest>,
    /// Why it was refused admission (a failed build, the pre-run audit);
    /// `None` when admitted. Whether it was refused is compared; the reason
    /// is context.
    pub refused: Option<String>,
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
            libraries,
            admitted,
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
        if *libraries != current.libraries {
            let render = |libraries: &[NativeLibraryIdentity]| {
                libraries
                    .iter()
                    .map(|library| format!("{} {}", library.name, library.sha256))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            differences.push(NativeIdentityDifference {
                component: "libraries",
                recorded: render(libraries),
                current: render(&current.libraries),
            });
        }
        let programs = |admitted: &[NativeAdmittedProgram]| {
            admitted
                .iter()
                .map(|program| {
                    let digest = program
                        .sha256
                        .as_ref()
                        .map_or("unbuilt".to_string(), ToString::to_string);
                    let verdict = if program.refused.is_some() {
                        "refused"
                    } else {
                        "admitted"
                    };
                    format!("{} {digest} {verdict}", program.program)
                })
                .collect::<Vec<_>>()
        };
        if programs(admitted) != programs(&current.admitted) {
            differences.push(NativeIdentityDifference {
                component: "admitted programs",
                recorded: programs(admitted).join(", "),
                current: programs(&current.admitted).join(", "),
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
            libraries: vec![NativeLibraryIdentity {
                name: "libc.so.6".into(),
                sha256: Sha256Digest([7; 32]),
            }],
            admitted: vec![NativeAdmittedProgram {
                program: "/target/debug/server".into(),
                artifact: "/target/patina/dst/server".into(),
                sha256: Some(Sha256Digest([9; 32])),
                refused: Some("audit".into()),
            }],
            supervisor_sha256: Sha256Digest([5; 32]),
            patina_version: "1.0.0".into(),
            shim_bundle_sha256: Sha256Digest([2; 32]),
            target: "x86_64-unknown-linux-gnu".into(),
        }
    }

    /// The executable, library, admitted-program and supervisor digests, and
    /// each program's admission, are compared and named; the version, shim
    /// bundle, target and an admitted program's artifact path and refusal
    /// reason are context and never compared.
    #[test]
    fn identity_components_are_compared_and_named_and_context_is_not() {
        assert!(identity().differences(&identity()).is_empty());
        let mut current = identity();
        current.patina_version = "1.0.1".into();
        current.shim_bundle_sha256 = Sha256Digest([4; 32]);
        current.target = "aarch64-apple-darwin".into();
        current.admitted[0].artifact = "/elsewhere/server".into();
        current.admitted[0].refused = Some("another reason".into());
        assert!(identity().differences(&current).is_empty());

        // Whether a program is admitted is compared like its digest.
        current.admitted[0].refused = None;
        let named: Vec<_> = identity()
            .differences(&current)
            .iter()
            .map(|d| d.component)
            .collect();
        assert_eq!(named, ["admitted programs"]);

        current.executable_sha256 = Sha256Digest([3; 32]);
        current.libraries[0].sha256 = Sha256Digest([8; 32]);
        current.admitted[0].sha256 = Some(Sha256Digest([10; 32]));
        current.supervisor_sha256 = Sha256Digest([6; 32]);
        let differences = identity().differences(&current);
        let named: Vec<_> = differences.iter().map(|d| d.component).collect();
        assert_eq!(
            named,
            ["executable", "libraries", "admitted programs", "supervisor"]
        );
        assert_eq!(
            differences[0].recorded,
            identity().executable_sha256.to_string()
        );
        assert_eq!(
            differences[0].current,
            current.executable_sha256.to_string()
        );
    }
}
