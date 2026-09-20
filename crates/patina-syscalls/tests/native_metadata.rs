//! Native metadata shape; independent source translation detectors live in Python.
use patina_dst_syscalls::{ENTRIES, Os, generated::SOURCES};

#[test]
fn provenance_contains_only_the_compiled_target_sources() {
    assert!(!SOURCES.is_empty());
    for source in SOURCES {
        assert_eq!(source.0, Os::host().name());
        assert_eq!(source.2.len(), 40);
        assert_eq!(source.5.len(), 64);
        assert!(source.4.contains(source.2));
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert!(!source.3.contains("arm64") && source.3 != "scripts/syscall.tbl");
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        assert!(!source.3.contains("x86"));
    }
}

#[test]
fn every_native_identity_has_its_own_total_number() {
    assert!(!ENTRIES.is_empty());
    for entry in ENTRIES {
        assert_eq!(entry.id.number(), entry.nr);
    }
    #[cfg(target_os = "linux")]
    {
        use patina_dst_syscalls::Syscall;
        assert_eq!(Syscall::ALL.len(), ENTRIES.len());
        for entry in ENTRIES {
            assert_eq!(entry.id.name(), entry.name);
            assert_eq!(Syscall::from_nr(entry.nr), Some(entry.id));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let mut identities = std::collections::BTreeSet::new();
        for entry in ENTRIES {
            assert!(identities.insert((entry.namespace, entry.nr, entry.subcode)));
            assert!(!entry.variants.is_empty());
            assert_eq!(entry.id.entry(), entry);
        }
        for namespace in ["bsd", "mach", "arm-special", "arm-platform"] {
            assert!(ENTRIES.iter().any(|e| e.namespace == namespace));
        }
        assert!(ENTRIES.iter().any(|e| e.subcode.is_some()));
        assert!(ENTRIES.iter().any(|e| e.variants.len() > 1));
    }
}
