//! WASI target builds and source-first execution.

#[cfg(test)]
mod tests {
    use super::super::*;

    // One package, built for wasip1 three ways. `build --target wasi` puts the
    // module in Cargo's target directory, and `audit` and `run` both infer the WASI
    // path from its `\0asm` magic. A WASI `--output` whose directory does not exist
    // yet is created, as the native build does. `run <pkg> --target wasi` builds on
    // the fly and runs the produced module, inferred by the shared resolution step.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn build_target_wasi_composes_with_audit_run_output_and_source_first_run() {
        if !wasm32_wasip1_installed() {
            eprintln!(
                "skipping build_target_wasi_composes_with_audit_run_output_and_source_first_run: \
wasm32-wasip1 target not installed"
            );
            return;
        }
        let directory = tempdir().unwrap();
        let package = directory.path().join("wasi-hello");
        write_plain_package(
            &package,
            "wasi-hello",
            "fn main() { println!(\"WASI_HELLO\"); }\n",
        );
        let workspace = native_workspace();
        let assert_hello = |ran: &Output, how: &str| {
            assert!(
                ran.status.success() && String::from_utf8_lossy(&ran.stdout).contains("WASI_HELLO"),
                "{how}: unexpected wasi run output:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&ran.stdout),
                String::from_utf8_lossy(&ran.stderr)
            );
        };

        invoke(
            workspace,
            &["build", package.to_str().unwrap(), "--target", "wasi"],
        );
        let module = fixture_target_directory(&package).join("wasm32-wasip1/debug/wasi-hello.wasm");
        assert!(
            module.is_file(),
            "missing wasm artifact at {}",
            module.display()
        );
        invoke(workspace, &["audit", module.to_str().unwrap()]);
        assert_hello(
            &invoke(workspace, &["run", module.to_str().unwrap(), "--seed", "1"]),
            "the built module",
        );

        let nested = directory.path().join("out/deeper/nested.wasm");
        invoke(
            workspace,
            &[
                "build",
                package.to_str().unwrap(),
                "--target",
                "wasi",
                "--output",
                nested.to_str().unwrap(),
            ],
        );
        assert_hello(
            &invoke(workspace, &["run", nested.to_str().unwrap(), "--seed", "1"]),
            "the module built into a new directory",
        );

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
        assert_hello(&ran, "run --target wasi on the fly");
        let note = stdout_line_with(&ran, "PATINA_BUILD_ON_RUN");
        assert!(
            note.contains("target=wasi"),
            "missing wasi identity note:\n{note}"
        );
    }
}
