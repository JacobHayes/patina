//! Campaign extension, interruption recovery, and continuation refusals.

use super::*;

fn campaign_json_without_invocations(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    value.as_object_mut().unwrap().remove("invocations");
    value
}

fn campaign_coverage_file_hashes(out_dir: &Path) -> BTreeMap<String, String> {
    let coverage_dir = out_dir.join("coverage");
    assert!(
        coverage_dir.is_dir(),
        "campaign coverage store is missing at {}",
        coverage_dir.display()
    );
    let mut hashes = BTreeMap::new();
    collect_file_hashes(&coverage_dir, &coverage_dir, &mut hashes);
    assert!(
        hashes.contains_key("meta.json")
            && hashes.contains_key("union.bits")
            && hashes.contains_key("hits.u64le")
            && hashes.contains_key("sites.i64le"),
        "coverage store did not contain every checkpoint file: {hashes:?}"
    );
    hashes
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
