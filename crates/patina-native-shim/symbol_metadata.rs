//! Consume the versioned generated inventory, never Rust source text.
use std::collections::BTreeSet;
use std::path::Path;

pub struct Symbol {
    pub name: String,
    pub linux: bool,
    pub routed: bool,
    pub deny_class: Option<String>,
    pub only_x86: bool,
}

pub fn read(path: &Path) -> Vec<Symbol> {
    let metadata = std::fs::read_to_string(path).expect("generated symbol metadata is readable");
    let mut lines = metadata.lines();
    assert_eq!(
        lines.next(),
        Some("patina.symbols/v1"),
        "unknown symbol metadata schema"
    );
    let mut names = BTreeSet::new();
    let symbols: Vec<_> = lines
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            let [name, platform, status, architecture] = fields.as_slice() else {
                panic!("symbol metadata row must contain exactly four fields");
            };
            assert!(names.insert(*name), "duplicate symbol metadata row: {name}");
            let linux = match *platform {
                "linux" | "both" => true,
                "darwin" => false,
                _ => panic!("unknown symbol metadata platform: {platform}"),
            };
            // Darwin's exported linker spellings include $DARWIN_EXTSN;
            // Linux C routing names remain ordinary identifiers.
            assert!(
                name.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_')
                    && name
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || (!linux && ch == '$')),
                "invalid native symbol metadata name"
            );
            let (routed, deny_class) = match *status {
                "modeled" | "partial" => (true, None),
                "absent" | "control-plane" => (false, None),
                "deny(process)" => (false, Some("process".to_owned())),
                "deny(host-introspection)" => (false, Some("host-introspection".to_owned())),
                "deny(macos-framework)" => (false, Some("macos-framework".to_owned())),
                _ => panic!("unknown symbol metadata status: {status}"),
            };
            let only_x86 = match *architecture {
                "all" => false,
                "x86_64" => true,
                _ => panic!("unknown symbol metadata architecture: {architecture}"),
            };
            Symbol {
                name: (*name).to_owned(),
                linux,
                routed,
                deny_class,
                only_x86,
            }
        })
        .collect();
    assert!(!symbols.is_empty(), "symbol metadata must not be empty");
    symbols
}
