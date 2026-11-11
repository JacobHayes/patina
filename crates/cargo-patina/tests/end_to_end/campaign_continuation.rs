//! Campaign extension, interruption recovery, and continuation refusals.

use super::*;

/// The campaign's coverage store, file by file: present exactly when its guest
/// is an instrumented build, the only kind with edge coverage.
fn campaign_coverage_file_hashes(
    out_dir: &Path,
    instrumented: bool,
) -> Option<BTreeMap<String, String>> {
    let coverage_dir = out_dir.join("coverage");
    assert_eq!(
        coverage_dir.is_dir(),
        instrumented,
        "campaign coverage store at {} (instrumented guest: {instrumented})",
        coverage_dir.display()
    );
    if !instrumented {
        return None;
    }
    let mut hashes = BTreeMap::new();
    collect_file_hashes(&coverage_dir, &coverage_dir, &mut hashes);
    assert!(
        hashes.contains_key("meta.json")
            && hashes.contains_key("union.bits")
            && hashes.contains_key("hits.u64le")
            && hashes.contains_key("sites.i64le"),
        "coverage store did not contain every checkpoint file: {hashes:?}"
    );
    Some(hashes)
}

fn collect_file_hashes(root: &Path, dir: &Path, hashes: &mut BTreeMap<String, String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_file_hashes(root, &path, hashes);
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&path).unwrap();
        let digest = Sha256::digest(&bytes);
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        hashes.insert(rel, hex);
    }
}

#[cfg(test)]
#[path = "campaign_continuation/tests.rs"]
mod tests;
