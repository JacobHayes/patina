//! Product recognition of SDK macro invocations in guest source fixtures.

use super::*;

// Class pairing: the SDK declaration generates macros and metadata together.
// This fixture exercises the actual recognizer for every row, including a
// newly declared name and import alias.
#[test]
fn every_declared_sdk_site_macro_is_recognized() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("lib.rs");
    let guest = SDK_SITE_MACROS
        .iter()
        .enumerate()
        .map(|(index, site)| {
            let args = site.fixture.strip_prefix(site.name).unwrap();
            format!(
                "use patina_dst::{} as site_{index};\nfn guest_{index}() {{ let _ = site_{index}{args}; }}\n",
                site.name,
            )
        })
        .collect::<String>();
    fs::write(&source, guest).unwrap();
    let scan = scan_packages(
        directory.path().to_path_buf(),
        vec![ScanPackage {
            name: "fixture".to_string(),
            root: directory.path().to_path_buf(),
            targets: vec![TargetHint {
                src_path: source,
                name: "fixture".to_string(),
                context: ContextKind::Src,
            }],
        }],
        false,
    )
    .unwrap();
    assert_eq!(scan.files_unparsed, 0);
    for metadata in SDK_SITE_MACROS {
        let label = format!("registry-{}", metadata.name);
        let found = scan
            .sites
            .iter()
            .find(|site| site.label.as_deref() == Some(&label))
            .unwrap_or_else(|| panic!("exported SDK macro {} was not recognized", metadata.name));
        assert_eq!(found.kind, metadata.kind);
        assert_eq!(found.runtime, metadata.runtime);
    }
    assert_eq!(scan.sites.len(), SDK_SITE_MACROS.len());
}

#[test]
fn sdk_site_invocations_and_import_aliases_are_recognized() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("lib.rs");
    // These are guest invocations, the data consumed by `sites`, rather than
    // implementation text used to infer what the SDK exports.
    fs::write(
        &source,
        r#"
use patina_dst::{buggify as fault, buggify_with_prob as probability,
    buggify_delay as delay, buggify_knob as knob, always as invariant,
    sometimes as coverage, reachable as reached};
fn guest() {
    let _ = fault!("plain");
    let _ = probability!("probability", 1.0);
    let _ = delay!("delay");
    let _ = knob!("knob", 3, 1, 5);
    invariant!(true, "always");
    coverage!(true, "sometimes");
    reached!("reachable");
}
"#,
    )
    .unwrap();
    let scan = scan_packages(
        directory.path().to_path_buf(),
        vec![ScanPackage {
            name: "fixture".to_string(),
            root: directory.path().to_path_buf(),
            targets: vec![TargetHint {
                src_path: source,
                name: "fixture".to_string(),
                context: ContextKind::Src,
            }],
        }],
        false,
    )
    .unwrap();
    assert_eq!(scan.files_unparsed, 0);
    let sites: BTreeMap<_, _> = scan
        .sites
        .iter()
        .map(|site| {
            (
                site.label.as_deref().unwrap(),
                (site.kind.as_str(), site.runtime.as_str()),
            )
        })
        .collect();
    assert_eq!(
        sites,
        BTreeMap::from([
            ("plain", ("fault", "driven")),
            ("probability", ("fault", "driven")),
            ("delay", ("delay", "driven")),
            ("knob", ("knob", "driven")),
            ("always", ("always", "observed")),
            ("sometimes", ("sometimes", "observed")),
            ("reachable", ("reachable", "observed")),
        ]),
    );
}
