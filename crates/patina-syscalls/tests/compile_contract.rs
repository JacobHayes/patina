//! Class detectors for foreign identities and missing reviewed classification.
//! Compile scratch copies: production sources are never mutated by tests.
use std::{fs, path::Path, process::Command};

fn compile(source: &Path, output: &Path) -> std::process::Output {
    Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args([
            "--edition=2024",
            "--crate-type=lib",
            "--crate-name=registry_contract",
        ])
        .arg(source)
        .arg("--out-dir")
        .arg(output)
        .output()
        .expect("invoke rustc")
}

#[test]
fn foreign_identity_and_missing_classification_fail_compilation() {
    let dir = std::env::temp_dir().join(format!("patina-registry-contract-{}", std::process::id()));
    fs::create_dir(&dir).expect("unique scratch directory");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for name in [
        "lib.rs",
        "cancellation.rs",
        "generated.rs",
        "linux.rs",
        "darwin.rs",
        "symbols.rs",
    ] {
        fs::copy(src.join(name), dir.join(name)).unwrap();
    }
    let result = compile(&dir.join("lib.rs"), &dir);
    assert!(
        result.status.success(),
        "control: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original = fs::read_to_string(dir.join("lib.rs")).unwrap();
    // On Linux, Darwin has no module at all; on Darwin, Linux has no module.
    let foreign = if cfg!(target_os = "linux") {
        "generated::darwin_aarch64::Syscall::Bsd0_nosys"
    } else {
        "generated::linux_x86_64::Syscall::N_read"
    };
    fs::write(
        dir.join("lib.rs"),
        format!("{original}\nconst _: () = {{ let _ = {foreign}; }};\n"),
    )
    .unwrap();
    let result = compile(&dir.join("lib.rs"), &dir);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("could not find"));
    #[cfg(target_os = "linux")]
    {
        let foreign = if cfg!(target_arch = "x86_64") {
            "generated::linux_aarch64::Syscall::N_read"
        } else {
            "Syscall::N_open"
        };
        fs::write(
            dir.join("lib.rs"),
            format!("{original}\nconst _: () = {{ let _ = {foreign}; }};\n"),
        )
        .unwrap();
        let result = compile(&dir.join("lib.rs"), &dir);
        assert!(
            !result.status.success(),
            "foreign architecture identity compiled"
        );
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(
            error.contains("could not find") || error.contains("no variant"),
            "{error}"
        );
    }
    fs::write(dir.join("lib.rs"), &original).unwrap();

    #[cfg(target_os = "linux")]
    {
        let generated = fs::read_to_string(dir.join("generated.rs")).unwrap();
        let module = if cfg!(target_arch = "x86_64") {
            "linux_x86_64"
        } else {
            "linux_aarch64"
        };
        let start = generated.find(&format!("pub mod {module}")).unwrap();
        let mut mutated = generated[..start].to_owned();
        mutated.push_str(
            &generated[start..]
                .replacen(
                    "pub enum Syscall {",
                    "pub enum Syscall { N_planted_unclassified = 9999,",
                    1,
                )
                .replacen(
                    "match self {",
                    "match self { Self::N_planted_unclassified => \"planted_unclassified\",",
                    1,
                ),
        );
        fs::write(dir.join("generated.rs"), mutated).unwrap();
        let result = compile(&dir.join("lib.rs"), &dir);
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(!result.status.success());
        assert!(
            error.contains("non-exhaustive patterns")
                && error.contains("N_planted_unclassified")
                && error.contains("linux.rs"),
            "{error}"
        );
    }
    #[cfg(target_os = "macos")]
    {
        let symbols = fs::read_to_string(dir.join("symbols.rs")).unwrap();
        assert_eq!(symbols.matches("\"mach_wait_until_trap\"").count(), 1);
        fs::write(
            dir.join("symbols.rs"),
            symbols.replace("\"mach_wait_until_trap\"", "\"mach_wait_until_trap_typo\""),
        )
        .unwrap();
        let result = compile(&dir.join("lib.rs"), &dir);
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(!result.status.success(), "unknown association compiled");
        assert!(
            error.contains("unknown Darwin symbol association"),
            "{error}"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}
