//! The SDK a package guest links must be from this tool's release line.
//!
//! The tool and the SDK are released together: the tool embeds the shim the
//! guest links, and the SDK (`patina-dst`) calls that shim's entries. A guest
//! that pins another release line's SDK would otherwise fail at the link, or
//! run against entries that mean something else. Cargo already names the SDK
//! it resolved in the build's own artifact messages, so the check reads those
//! and costs no extra resolution.

use crate::CliError;

const SDK_PACKAGE: &str = "patina-dst";
const SDK_LIB: &str = "patina_dst";

/// Refuse a package build whose resolved `patina-dst` this tool cannot drive.
/// `messages` is the build's `--message-format=json` stdout. Call it before
/// reporting the build's own failure: the SDK compiles before the guest links,
/// so a mismatch that breaks the link is still named here.
pub(super) fn check_guest_sdk(messages: &[u8]) -> Result<(), CliError> {
    let tool = env!("CARGO_PKG_VERSION");
    for sdk in resolved_sdk_versions(messages) {
        if !same_release_line(tool, &sdk) {
            return Err(CliError(mismatch_message(tool, &sdk)));
        }
    }
    Ok(())
}

/// The version of every `patina-dst` the build compiled.
fn resolved_sdk_versions(messages: &[u8]) -> Vec<String> {
    let mut versions = Vec::new();
    for line in messages.split(|byte| *byte == b'\n') {
        let Ok(message) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if message.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let target = message
            .get("target")
            .and_then(|target| target.get("name"))
            .and_then(serde_json::Value::as_str);
        if target != Some(SDK_LIB) {
            continue;
        }
        if let Some(version) = message
            .get("package_id")
            .and_then(serde_json::Value::as_str)
            .and_then(sdk_version_of)
            && !versions.contains(&version)
        {
            versions.push(version);
        }
    }
    versions
}

/// The version in a package ID spec, when the spec names the SDK package:
/// `<source>#patina-dst@<version>`, or `<source>#<version>` when the source's
/// last path segment is the package name.
fn sdk_version_of(package_id: &str) -> Option<String> {
    let (source, fragment) = package_id.rsplit_once('#')?;
    let (name, version) = match fragment.split_once('@') {
        Some((name, version)) => (name, version),
        None => {
            let path = source.split_once('?').map_or(source, |(path, _)| path);
            (path.rsplit('/').next()?, fragment)
        }
    };
    (name == SDK_PACKAGE).then(|| version.to_owned())
}

/// Cargo's own compatibility rule: the same major version, and before 1.0
/// the same minor version too.
fn same_release_line(tool: &str, sdk: &str) -> bool {
    match (release_line(tool), release_line(sdk)) {
        (Some(tool), Some(sdk)) => tool == sdk,
        _ => false,
    }
}

fn release_line(version: &str) -> Option<(u64, u64)> {
    let mut parts = version.split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    Some(if major == 0 { (0, minor) } else { (major, 0) })
}

fn mismatch_message(tool: &str, sdk: &str) -> String {
    let repository = env!("CARGO_PKG_REPOSITORY");
    format!(
        "this package builds against patina-dst {sdk}, which patina {tool} cannot drive: the \
         tool and the SDK must come from the same release line\n  \
         install the matching tool:\n    \
         curl -fsSL {repository}/releases/latest/download/install.sh | sh -s -- --version {sdk}\n  \
         or depend on the matching SDK:\n    \
         patina-dst = {{ git = \"{repository}\", tag = \"v{tool}\" }}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(target: &str, package_id: &str) -> String {
        serde_json::json!({
            "reason": "compiler-artifact",
            "package_id": package_id,
            "target": {"name": target},
        })
        .to_string()
    }

    #[test]
    fn the_sdk_version_is_read_from_every_source_kind() {
        for (package_id, expected) in [
            (
                "git+https://github.com/JacobHayes/patina?tag=v0.3.1#patina-dst@0.3.1",
                Some("0.3.1"),
            ),
            (
                "registry+https://github.com/rust-lang/crates.io-index#patina-dst@1.2.0",
                Some("1.2.0"),
            ),
            (
                "path+file:///src/crates/patina#patina-dst@0.1.0",
                Some("0.1.0"),
            ),
            ("path+file:///vendor/patina-dst#0.4.0", Some("0.4.0")),
            // Another package whose library happens to share the name.
            ("path+file:///elsewhere/lookalike#0.4.0", None),
            ("registry+https://example.test/index#other@0.4.0", None),
        ] {
            assert_eq!(
                sdk_version_of(package_id).as_deref(),
                expected,
                "{package_id}"
            );
        }
    }

    #[test]
    fn only_the_sdk_library_of_another_release_line_is_refused() {
        let tool = env!("CARGO_PKG_VERSION");
        let (major, minor) = release_line(tool).unwrap();
        let same = artifact(SDK_LIB, &format!("path+file:///sdk#patina-dst@{tool}"));
        let other_line = if major == 0 {
            format!("0.{}.0", minor + 1)
        } else {
            format!("{}.0.0", major + 1)
        };
        let other = artifact(
            SDK_LIB,
            &format!("path+file:///sdk#patina-dst@{other_line}"),
        );
        let unrelated = artifact("serde", "registry+https://example.test/index#serde@9.0.0");

        assert!(check_guest_sdk(format!("{unrelated}\n{same}\n").as_bytes()).is_ok());
        assert!(check_guest_sdk(format!("{unrelated}\nnot json\n").as_bytes()).is_ok());
        assert!(check_guest_sdk(format!("{same}\n{other}\n").as_bytes()).is_err());
    }

    #[test]
    fn a_release_line_is_the_major_version_or_before_one_the_minor() {
        assert!(same_release_line("0.1.0", "0.1.7"));
        assert!(!same_release_line("0.1.0", "0.2.0"));
        assert!(same_release_line("1.4.0", "1.0.2"));
        assert!(!same_release_line("1.4.0", "2.0.0"));
        assert!(!same_release_line("0.1.0", "unparsable"));
    }
}
