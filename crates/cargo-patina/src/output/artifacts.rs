//! Likely artifacts: facts about a run that did not end clean which point at
//! the simulated world rather than the program under test. They sit beside
//! the run's class and never change it, its attribution or the exit status.

use crate::mount::Mount;
use serde_json::{Value, json};
use std::path::Path;

/// `kind` of a likely artifact: the guest looked for an absolute path the
/// simulated filesystem does not hold and the host does.
pub const MISSING_HOST_PATH: &str = "missing_host_path";
/// `kind` of a likely artifact: the run stopped on a bound of Patina's own.
pub const PATINA_LIMIT: &str = "patina_limit";

/// The stop reasons that are Patina's own bounds rather than anything the
/// guest reported: the step budget, the host-time compute watchdog, and
/// `patina test`'s wall-clock backstop.
const LIMIT_STOPS: [&str; 3] = ["step_budget", "compute_bound", "wall_clock_backstop"];

/// Host trees never flagged: the pseudo filesystems are modeled, and the
/// system trees are what libc probes on its own (resolver and locale files),
/// where mounting the host's copy is the wrong advice.
const PSEUDO_FILESYSTEMS: [&str; 5] = ["/proc", "/sys", "/dev", "/etc", "/usr"];

/// The likely artifacts of a run that did not end clean, judged by the
/// supervisor after the run from the run's own facts. `missing_paths` are the
/// absolute paths the guest opened or stat'ed and found missing; each one the
/// host has, outside the pseudo filesystems, and that `mount` did not already
/// provide is flagged, with the `--mount` that would provide it. Only the
/// supervisor reads the host here: the guest never learns what it holds.
pub fn likely_artifacts(
    stop_reason: Option<&str>,
    facts: Option<&Value>,
    mount: Option<&Mount>,
) -> Vec<Value> {
    let mut artifacts = Vec::new();
    let missing = facts
        .and_then(|facts| facts.get("missing_paths"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    for path in missing {
        if let Some(directory) = missing_host_path(path, mount) {
            let shown = directory.to_string_lossy();
            artifacts.push(json!({
                "kind": MISSING_HOST_PATH,
                "path": path,
                "mount": format!("{shown}:{shown}"),
            }));
        }
    }
    if let Some(limit) = stop_reason.filter(|reason| LIMIT_STOPS.contains(reason)) {
        artifacts.push(limit_artifact(limit));
    }
    artifacts
}

/// The likely artifact of a run stopped on Patina's bound `limit`.
pub fn limit_artifact(limit: &str) -> Value {
    json!({"kind": PATINA_LIMIT, "limit": limit})
}

/// The host directory a `--mount` at its own path would need to provide
/// `path`, when the host has `path` and the run could not see it.
fn missing_host_path<'a>(path: &'a str, mount: Option<&Mount>) -> Option<&'a Path> {
    let host = Path::new(path);
    let pseudo = PSEUDO_FILESYSTEMS.iter().any(|root| host.starts_with(root));
    // What the mount maps there was captured: missing in the guest, it is
    // the guest's own doing (it removed it), not a file it was never given.
    let mounted = mount
        .and_then(|mount| mount.host_path_of(path))
        .is_some_and(|captured| captured.symlink_metadata().is_ok());
    if pseudo || mounted {
        return None;
    }
    let metadata = host.metadata().ok()?;
    if metadata.is_dir() {
        Some(host)
    } else {
        host.parent()
    }
}

/// One line for a reader, from the artifact's own fields.
pub fn describe(artifact: &Value) -> Option<String> {
    let field = |key: &str| artifact.get(key).and_then(Value::as_str);
    match field("kind")? {
        MISSING_HOST_PATH => Some(format!(
            "the guest looked for {}, which the host has and the simulated filesystem was not \
             given; --mount {} provides it",
            field("path")?,
            field("mount")?,
        )),
        PATINA_LIMIT => Some(format!(
            "the run stopped on Patina's own {} bound, not on a check the program made",
            field("limit")?.replace('_', " "),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(artifacts: &[Value]) -> Vec<&str> {
        artifacts
            .iter()
            .map(|artifact| artifact["kind"].as_str().unwrap())
            .collect()
    }

    /// A path is flagged when the host has it and the run was not given it;
    /// one the host lacks, one a mount captured, and one under a pseudo
    /// filesystem are not.
    #[test]
    fn only_host_paths_the_run_was_not_given_are_flagged() {
        let host = tempfile::tempdir().unwrap();
        let fixture = host.path().join("fixtures/data.bin");
        std::fs::create_dir_all(fixture.parent().unwrap()).unwrap();
        std::fs::write(&fixture, b"x").unwrap();
        let fixture = fixture.to_str().unwrap();
        let absent = host.path().join("absent");
        let facts = json!({"missing_paths": [fixture, absent.to_str().unwrap(), "/proc/self/exe"]});

        let artifacts = likely_artifacts(None, Some(&facts), None);
        assert_eq!(kinds(&artifacts), [MISSING_HOST_PATH]);
        assert_eq!(artifacts[0]["path"], fixture);
        let directory = host.path().join("fixtures");
        let directory = directory.to_str().unwrap();
        assert_eq!(artifacts[0]["mount"], format!("{directory}:{directory}"));
        assert!(describe(&artifacts[0]).is_some());

        // Mounted at its own path, the fixture was captured: a guest that
        // still found it missing removed it itself.
        let own = Mount::parse(format!("{directory}:{directory}").as_ref()).unwrap();
        assert!(likely_artifacts(None, Some(&facts), Some(&own)).is_empty());
        // Mounted at `/`, the guest sees it elsewhere: its absolute host path
        // is still one the run was not given.
        let root = Mount::parse(directory.as_ref()).unwrap();
        assert_eq!(
            kinds(&likely_artifacts(None, Some(&facts), Some(&root))),
            [MISSING_HOST_PATH]
        );
    }

    #[test]
    fn patina_limits_are_flagged_and_guest_stops_are_not() {
        for limit in LIMIT_STOPS {
            let artifacts = likely_artifacts(Some(limit), None, None);
            assert_eq!(kinds(&artifacts), [PATINA_LIMIT]);
            assert_eq!(artifacts[0]["limit"], limit);
            assert!(describe(&artifacts[0]).is_some());
        }
        for reason in ["rust_panic", "signal", "liveness", "violation_verdict"] {
            assert!(likely_artifacts(Some(reason), None, None).is_empty());
        }
    }
}
