//! Native Darwin symbol associations must resolve to generated entry variants.
use crate::{DarwinEntry, Platform, Serves, SymbolRow};

const fn same_name(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut i = 0;
    while i < left.len() {
        if left[i] != right[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn known_entry(name: &str, entries: &[DarwinEntry]) -> bool {
    let mut i = 0;
    while i < entries.len() {
        let variants = entries[i].variants;
        let mut j = 0;
        while j < variants.len() {
            if same_name(name, variants[j].entry) {
                return true;
            }
            j += 1;
        }
        i += 1;
    }
    false
}

pub(crate) const fn validate_associations(symbols: &[SymbolRow], entries: &[DarwinEntry]) {
    let mut i = 0;
    while i < symbols.len() {
        let symbol = &symbols[i];
        if let Serves::Darwin(names) = symbol.serves {
            assert!(matches!(symbol.platform, Platform::Darwin));
            assert!(!names.is_empty(), "empty Darwin symbol association");
            let mut j = 0;
            while j < names.len() {
                assert!(
                    known_entry(names[j], entries),
                    "unknown Darwin symbol association"
                );
                j += 1;
            }
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ENTRIES, SYMBOLS};

    #[test]
    fn every_darwin_symbol_association_resolves() {
        assert!(
            SYMBOLS
                .iter()
                .any(|s| matches!(s.serves, Serves::Darwin(_)))
        );
        validate_associations(SYMBOLS, ENTRIES);
    }

    // Class pairing: the compile-contract mutation tests the same exhaustive
    // validator against a typo in the real symbol table.
    #[test]
    fn association_validator_rejects_unknown_names() {
        let mut symbol = *SYMBOLS
            .iter()
            .find(|s| matches!(s.serves, Serves::Darwin(_)))
            .unwrap();
        validate_associations(std::slice::from_ref(&symbol), ENTRIES);
        symbol.serves = Serves::Darwin(&["mach_wait_until_trap_typo"]);
        assert!(
            std::panic::catch_unwind(|| {
                validate_associations(std::slice::from_ref(&symbol), ENTRIES);
            })
            .is_err()
        );
    }
}
