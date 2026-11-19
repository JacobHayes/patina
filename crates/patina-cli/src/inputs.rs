//! What the run's `--mount` sources held when it ran, so that a replay that differs can tell a
//! change of the program's inputs from a Patina bug. A source's fingerprint covers what the
//! guest can see of each entry (relative path, type, permission bits, size, a symlink's
//! target, the modification time, which stands for the content); files are not read. A source
//! with more than `CAP` entries is not fingerprinted (null), nor is one that cannot be read.

use crate::config::Config;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const CAP: usize = 20_000;

/// `[{"dst": guest path, "fp": hex or null}]`, one per mount, in the order given.
pub fn fingerprints(cfg: &Config) -> Value {
    // A node's starting tree is an input as a mount is (named `node.NAME work`).
    let nodes = cfg.nodes.iter().filter_map(|n| {
        n.work
            .as_ref()
            .map(|w| json!({"dst": format!("node.{} work", n.name), "fp": of(w)}))
    });
    Value::Array(
        cfg.mounts
            .iter()
            .map(|m| json!({"dst": m.dst, "fp": of(&m.src)}))
            .chain(nodes)
            .collect(),
    )
}

fn of(src: &Path) -> Option<String> {
    let mut h = Sha256::new();
    let mut n = 0usize;
    walk(src, Path::new(""), &mut h, &mut n)
        .then(|| h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Hash `root/rel` and, for a directory, its entries in name order. False when over the cap or
/// unreadable.
fn walk(root: &Path, rel: &Path, h: &mut Sha256, n: &mut usize) -> bool {
    *n += 1;
    if *n > CAP {
        return false;
    }
    let p = root.join(rel);
    let Ok(m) = std::fs::symlink_metadata(&p) else {
        return false;
    };
    h.update(rel.as_os_str().as_encoded_bytes());
    h.update([0]);
    h.update(m.mode().to_le_bytes());
    let ft = m.file_type();
    if ft.is_symlink() {
        if let Ok(t) = std::fs::read_link(&p) {
            h.update(t.as_os_str().as_encoded_bytes());
        }
    } else {
        if !ft.is_dir() {
            h.update(m.size().to_le_bytes());
        }
        h.update(m.mtime().to_le_bytes());
        h.update(m.mtime_nsec().to_le_bytes());
    }
    h.update([0xff]);
    if ft.is_dir() {
        let Ok(rd) = std::fs::read_dir(&p) else {
            return false;
        };
        let mut names: Vec<_> = rd.flatten().map(|e| e.file_name()).collect();
        names.sort();
        for name in names {
            if !walk(root, &rel.join(name), h, n) {
                return false;
            }
        }
    }
    true
}

/// The mounts (guest paths) whose fingerprint recorded in `run` differs from theirs now.
pub fn changed(run: &Value, cfg: &Config) -> Vec<String> {
    let Some(was) = run["inputs"].as_array() else {
        return Vec::new();
    };
    let now = fingerprints(cfg);
    let now = now.as_array().map(Vec::as_slice).unwrap_or(&[]);
    was.iter()
        .zip(now)
        .filter(|(a, b)| a["dst"] == b["dst"] && a["fp"].is_string() && a["fp"] != b["fp"])
        .filter_map(|(a, _)| a["dst"].as_str().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("patina-inputs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_link_made_elsewhere_is_no_change_and_a_new_file_is() {
        let d = tmp("a");
        std::fs::write(d.join("m.py"), "print(1)\n").unwrap();
        let before = of(&d).unwrap();
        let other = tmp("a-other");
        std::fs::hard_link(d.join("m.py"), other.join("hl")).unwrap();
        assert_eq!(of(&d).unwrap(), before);
        std::fs::write(d.join("sibling"), "").unwrap();
        assert_ne!(of(&d).unwrap(), before);
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&other);
    }
}
