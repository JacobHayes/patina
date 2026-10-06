//! WASI target builds and source-first execution.

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn build_target_wasi_compiles_and_composes_with_audit_and_run() {
        if !wasm32_wasip1_installed() {
            eprintln!(
                "skipping build_target_wasi_compiles_and_composes_with_audit_and_run: \
wasm32-wasip1 target not installed"
            );
            return;
        }
        let directory = tempdir().unwrap();
        let package = directory.path().join("wasi-hello");
        fs::create_dir_all(package.join("src")).unwrap();
        fs::write(
        package.join("Cargo.toml"),
        "[package]\nname = \"wasi-hello\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"wasi-hello\"\npath = \"src/main.rs\"\n",
    )
    .unwrap();
        fs::write(
            package.join("src/main.rs"),
            "fn main() { println!(\"WASI_HELLO\"); }\n",
        )
        .unwrap();

        let workspace = native_workspace();
        let built = invoke(
            workspace,
            &["build", package.to_str().unwrap(), "--target", "wasi"],
        );
        assert!(
            built.status.success(),
            "build --target wasi failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&built.stdout),
            String::from_utf8_lossy(&built.stderr)
        );
        let module = fixture_target_directory(&package).join("wasm32-wasip1/debug/wasi-hello.wasm");
        assert!(
            module.is_file(),
            "missing wasm artifact at {}",
            module.display()
        );

        // `audit` infers the WASI path from the `\0asm` magic and lists imports.
        invoke(workspace, &["audit", module.to_str().unwrap()]);
        // `run` infers the WASI runner and executes `_start` deterministically.
        let ran = invoke(workspace, &["run", module.to_str().unwrap(), "--seed", "1"]);
        assert!(
            String::from_utf8_lossy(&ran.stdout).contains("WASI_HELLO"),
            "unexpected wasi run output:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
    }

    // `run <pkg> --target wasi` builds the package for wasip1 on the fly and runs the
    // produced module, inferred by the shared resolution step.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn run_source_package_target_wasi_on_the_fly() {
        if !wasm32_wasip1_installed() {
            eprintln!(
                "skipping run_source_package_target_wasi_on_the_fly: wasm32-wasip1 not installed"
            );
            return;
        }
        let directory = tempdir().unwrap();
        let package = directory.path().join("wasi-run-pkg");
        fs::create_dir_all(package.join("src")).unwrap();
        fs::write(
        package.join("Cargo.toml"),
        "[package]\nname = \"wasi-run-pkg\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"wasi-run-pkg\"\npath = \"src/main.rs\"\n",
    )
    .unwrap();
        fs::write(
            package.join("src/main.rs"),
            "fn main() { println!(\"WASI_ON_THE_FLY\"); }\n",
        )
        .unwrap();

        let workspace = native_workspace();
        let ran = invoke(
            workspace,
            &[
                "run",
                package.to_str().unwrap(),
                "--target",
                "wasi",
                "--seed",
                "1",
            ],
        );
        assert!(
            ran.status.success(),
            "run --target wasi on the fly failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
        assert!(String::from_utf8_lossy(&ran.stdout).contains("WASI_ON_THE_FLY"));
        let note = stdout_line_with(&ran, "PATINA_BUILD_ON_RUN");
        assert!(
            note.contains("target=wasi"),
            "missing wasi identity note:\n{note}"
        );
    }
}
