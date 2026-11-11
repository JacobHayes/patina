//! The programs a guest may spawn: the admission table.
//!
//! A guest is admitted to spawn itself and the shim-linked builds of its
//! package's own binaries. `patina test` builds and stages those, audits each
//! once ([`judge`]), and hands every test's `patina run` the verdicts in
//! [`ENV_ADMIT_REQUEST`], keyed by the paths Cargo installs the binaries at
//! (what `CARGO_BIN_EXE_*` names). The guest itself is keyed by the path the
//! run was given for it and its canonical path: the guest observes no path of
//! its own (`argv[0]` is fixed, `/proc/self/exe` is absent), so those are the
//! paths it can have been handed. A guest built on the fly lives in a scratch
//! directory no one can hand it, and is not keyed at all.
//!
//! The supervisor holds the table ([`admit`]): it keeps each admitted
//! artifact open for the run, and confirms that the open file's bytes are the
//! audited ones (staging replaces an artifact by rename, never in place, so
//! the open file keeps them) and judges each again with the pre-run gate
//! (the request is an input, not a proof). The guest learns only what each path is
//! ([`patina_dst_runtime::ENV_ADMIT`]): admitted, with an artifact id,
//! refused, with the reason, or, on a replay, missing. A recording names every program but the guest
//! by its path, its artifact's digest and whether it was admitted
//! ([`NativeAdmittedProgram`]); the guest's own keys say only where the
//! binary sits, which a recording never depends on. A replay takes the
//! programs from the recording, so their keys cannot differ, and judges each
//! artifact again under its own `--allow`: a changed digest or verdict refuses
//! the replay. An artifact that is gone refuses nothing up front; a replay
//! that spawns it stops there.

use super::*;
use patina_dst_trace::NativeAdmittedProgram;

/// `patina test` to its `patina run` children: the JSON list of
/// [`NativeAdmittedProgram`] verdicts it reached for the package's binaries.
/// Read only by a new run; the guest never sees it.
pub(crate) const ENV_ADMIT_REQUEST: &str = "PATINA_RT_ADMIT_REQUEST";

/// `artifact`, opened and mapped: the file stays open for as long as it is
/// held.
fn open(artifact: &str) -> io::Result<(fs::File, Image)> {
    let file = fs::File::open(artifact)?;
    let image = Image::map(&file)?;
    Ok((file, image))
}

/// Why the pre-run gate refuses `image`, the artifact at `path`, if it does.
fn gate_refusal(
    path: &Path,
    image: &Image,
    allow: &BTreeSet<String>,
    policy: &UnsupportedPolicy,
) -> Option<String> {
    match crate::load_set::discover(path, image.bytes())
        .map_err(gate::GateRefusal::Error)
        .and_then(|load_set| native_prerun_gate(path, image, &load_set, allow, policy))
    {
        Ok(_) => None,
        Err(gate::GateRefusal::Unsupported(message)) => Some(message),
        Err(gate::GateRefusal::Error(error)) => Some(error.to_string()),
    }
}

/// `patina test`'s verdict on the binary at `program`: its staged artifact
/// judged by the pre-run gate as a test's run judges its guest (no
/// `--allow`), or refused for why it has none.
pub(crate) fn judge(program: String, artifact: Result<PathBuf, String>) -> NativeAdmittedProgram {
    let refused = |artifact: String, sha256, reason: String| NativeAdmittedProgram {
        program: program.clone(),
        artifact,
        sha256,
        refused: Some(reason),
    };
    let artifact = match artifact {
        Ok(artifact) => artifact.to_string_lossy().into_owned(),
        Err(reason) => return refused(String::new(), None, reason),
    };
    let (_, image) = match open(&artifact) {
        Ok(opened) => opened,
        Err(error) => return refused(artifact, None, format!("cannot read it: {error}")),
    };
    let sha256 = Some(image.sha256());
    match gate_refusal(
        Path::new(&artifact),
        &image,
        &BTreeSet::new(),
        &UnsupportedPolicy::Deny,
    ) {
        Some(reason) => refused(artifact, sha256, reason),
        None => NativeAdmittedProgram {
            program: program.clone(),
            artifact,
            sha256,
            refused: None,
        },
    }
}

/// Where a run's programs come from.
pub(super) enum Source<'a> {
    /// A new run: `patina test`'s verdicts ([`ENV_ADMIT_REQUEST`]), if any.
    Request,
    /// A replay: the recording's, judged again.
    Recorded(&'a [NativeAdmittedProgram]),
}

/// What one path is to the guest.
enum Entry {
    Admitted(usize),
    Refused(String),
    Missing(String),
}

/// A run's admission table.
pub(super) struct Admission {
    /// The programs as the recording names them.
    pub(super) programs: Vec<NativeAdmittedProgram>,
    /// Each admitted program's artifact, open for the run, by id.
    held: BTreeMap<usize, fs::File>,
    /// Every path the guest may name, the guest's own included.
    table: BTreeMap<String, Entry>,
}

/// The run's admission table: the programs `source` names, each held open
/// and, on a replay, judged again under `allow` and `policy`, and the guest
/// itself (`binary`, canonical) by the path the run was `given` and its
/// canonical path, when it was given one.
pub(super) fn admit(
    source: Source<'_>,
    given: Option<&Path>,
    binary: &Path,
    allow: &BTreeSet<String>,
    policy: &UnsupportedPolicy,
) -> Result<Admission, CliError> {
    let (programs, replay): (Vec<NativeAdmittedProgram>, bool) = match source {
        Source::Request => match env::var(ENV_ADMIT_REQUEST) {
            Ok(json) => (
                serde_json::from_str(&json).map_err(|error| {
                    CliError(format!(
                        "{ENV_ADMIT_REQUEST} is not a list of programs: {error}"
                    ))
                })?,
                false,
            ),
            Err(env::VarError::NotPresent) => (Vec::new(), false),
            Err(env::VarError::NotUnicode(_)) => {
                return Err(CliError(format!("{ENV_ADMIT_REQUEST} is not UTF-8")));
            }
        },
        Source::Recorded(programs) => (programs.to_vec(), true),
    };
    let mut admission = Admission {
        programs: Vec::with_capacity(programs.len()),
        held: BTreeMap::new(),
        table: BTreeMap::new(),
    };
    for mut program in programs {
        // Id 0 is the guest; a program's is its place in the list, plus one.
        let id = admission.programs.len() + 1;
        let opened = if program.refused.is_some() && !replay {
            None
        } else {
            Some(open(&program.artifact))
        };
        let entry = match opened {
            None => Entry::Refused(program.refused.clone().unwrap_or_default()),
            Some(Err(error)) if replay => match &program.refused {
                Some(reason) => Entry::Refused(reason.clone()),
                None => Entry::Missing(format!(
                    "the recording's artifact {} cannot be read: {error}; replay beside the \
                     artifacts it was recorded with",
                    program.artifact
                )),
            },
            Some(Err(error)) => {
                let reason = format!("cannot read {}: {error}", program.artifact);
                program.refused = Some(reason.clone());
                Entry::Refused(reason)
            }
            Some(Ok((file, image))) => {
                let sha256 = image.sha256();
                let refusal = if replay {
                    // Judged again, as the replay judges its guest.
                    program.sha256 = Some(sha256);
                    gate_refusal(Path::new(&program.artifact), &image, allow, policy)
                } else if program.sha256 != Some(sha256) {
                    Some(format!(
                        "{} changed after `patina test` audited it",
                        program.artifact
                    ))
                } else {
                    // The request is the run's input, not its proof: the
                    // gate judges the held bytes again, as `patina test`
                    // did.
                    gate_refusal(Path::new(&program.artifact), &image, allow, policy)
                };
                program.refused = refusal.clone();
                match refusal {
                    Some(reason) => Entry::Refused(reason),
                    None => {
                        admission.held.insert(id, file);
                        Entry::Admitted(id)
                    }
                }
            }
        };
        admission.table.insert(program.program.clone(), entry);
        admission.programs.push(program);
    }
    if let Some(given) = given {
        let given = std::path::absolute(given).map_err(|error| {
            CliError(format!(
                "failed to resolve native program {}: {error}",
                given.display()
            ))
        })?;
        for path in [given.as_path(), binary] {
            admission
                .table
                .insert(path.to_string_lossy().into_owned(), Entry::Admitted(0));
        }
    }
    Ok(admission)
}

impl Admission {
    /// Every admitted artifact as a descriptor of its held file, by id, with
    /// `guest`, the guest's own executable, as id 0: what a spawn of an
    /// admitted program runs, the very bytes audited for it.
    #[cfg(target_os = "linux")]
    pub(super) fn artifacts(
        &self,
        guest: &fs::File,
    ) -> io::Result<BTreeMap<usize, std::os::fd::OwnedFd>> {
        let mut artifacts = BTreeMap::new();
        artifacts.insert(0, guest.try_clone()?.into());
        for (id, file) in &self.held {
            artifacts.insert(*id, file.try_clone()?.into());
        }
        Ok(artifacts)
    }

    /// The control-plane entry that carries the table to the guest, if it
    /// names anything.
    pub(super) fn env_value(&self) -> Option<String> {
        if self.table.is_empty() {
            return None;
        }
        let table: serde_json::Map<String, serde_json::Value> = self
            .table
            .iter()
            .map(|(path, entry)| {
                let value = match entry {
                    Entry::Admitted(id) => serde_json::json!({ "admitted": id }),
                    Entry::Refused(reason) => serde_json::json!({ "refused": reason }),
                    Entry::Missing(reason) => serde_json::json!({ "missing": reason }),
                };
                (path.clone(), value)
            })
            .collect();
        Some(serde_json::Value::Object(table).to_string())
    }
}
