//! Host orchestration and return-value handling for DST test attributes.

#[cfg(feature = "macros")]
pub use orchestration::{DstTest, DstTestReturn, assert_test_return, orchestrate, test_record};

mod orchestration {
    /// The bytes of one `#[patina_dst::test(...)]` record in the test
    /// binary's `patina_tests` section: the test's path, then each `patina
    /// test` word its arguments stand for, every one NUL-terminated, and an
    /// empty word to end it. `patina test` reads the section to give each
    /// test the faults its attribute names.
    #[cfg(feature = "macros")]
    #[doc(hidden)]
    pub const fn test_record<const N: usize>(text: &str) -> [u8; N] {
        let bytes = text.as_bytes();
        assert!(bytes.len() == N, "a test record is its text");
        let mut record = [0; N];
        let mut index = 0;
        while index < N {
            record[index] = bytes[index];
            index += 1;
        }
        record
    }

    /// Runtime data emitted by `#[patina_dst::test]`.
    #[cfg(feature = "macros")]
    #[doc(hidden)]
    pub struct DstTest {
        pub manifest_dir: &'static str,
        pub package: &'static str,
        /// The test's crate: the library's, or the target's own.
        pub crate_name: &'static str,
        /// Set when the test is in a binary target.
        pub bin_name: Option<&'static str>,
        /// Whether the test is in an integration test target.
        pub integration_test: bool,
        pub test_path: &'static str,
        pub cli_args: &'static [&'static str],
    }

    /// Return types accepted by `#[patina_dst::test]` bodies.
    #[cfg(feature = "macros")]
    #[doc(hidden)]
    pub trait DstTestReturn {
        fn assert_ok(self);
    }

    #[cfg(feature = "macros")]
    impl DstTestReturn for () {
        fn assert_ok(self) {}
    }

    #[cfg(feature = "macros")]
    impl<E: core::fmt::Debug> DstTestReturn for Result<(), E> {
        fn assert_ok(self) {
            if let Err(error) = self {
                panic!("patina dst test body returned error: {error:?}");
            }
        }
    }

    /// Assert a guest-side `#[patina_dst::test]` body return value.
    #[cfg(feature = "macros")]
    #[doc(hidden)]
    pub fn assert_test_return<T: DstTestReturn>(value: T) {
        value.assert_ok();
    }

    /// Orchestrate a point-solution DST test from a plain `cargo test` process.
    ///
    /// The shim-linked guest calls the same wrapper, but `is_simulated()` is true
    /// there, so only the body executes. This function is therefore host-side
    /// only: discover the `patina` tool, ask it to run this one test of this
    /// one target (`patina test DIR -p PACKAGE --lib|--bin|--test NAME --exact`),
    /// and panic loudly on any failure.
    #[cfg(feature = "macros")]
    #[doc(hidden)]
    #[track_caller]
    pub fn orchestrate(test: &DstTest) {
        if let Err(message) = orchestrate_inner(test) {
            panic!("{message}");
        }
    }

    #[cfg(feature = "macros")]
    fn orchestrate_inner(test: &DstTest) -> Result<(), String> {
        let cli = resolve_cli(test)?;
        let exact = libtest_exact_name(test);
        let mut command = std::process::Command::new(&cli);
        command
            .arg("test")
            .arg(test.manifest_dir)
            .arg("--package")
            .arg(test.package)
            .args(target_selection(test))
            .arg(&exact)
            .arg("--exact")
            // The test is asked for by name, `#[ignore]` or not.
            .arg("--include-ignored")
            // The arguments are this test's own: any faults they name are
            // the ones it expects.
            .arg("--fault-all-tests")
            .args(test.cli_args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let rendered = render_command(&cli, command.get_args());
        let output = command.output().map_err(|error| {
            format!(
                "patina dst test could not launch patina for {}: {error}\n  command: {rendered}",
                test.test_path
            )
        })?;
        if output.status.success() {
            return Ok(());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Exit 1 is a finding: the summary on stdout names the seed, why,
        // and the rerun and replay commands, and is the whole report.
        if output.status.code() == Some(1) {
            return Err(format!(
                "patina dst test failed: {}\n{}",
                test.test_path,
                stdout.trim_matches('\n')
            ));
        }
        let exit = match output.status.code() {
            Some(code) => code.to_string(),
            None => "terminated by signal".to_string(),
        };
        let mut message = format!(
            "patina dst test could not run: {}\n  command: {rendered}\n  exit: {exit}",
            test.test_path
        );
        if !stdout.trim().is_empty() {
            message.push_str("\n  stdout:\n");
            message.push_str(&indent_block(stdout.trim_matches('\n')));
        }
        if !stderr.trim().is_empty() {
            message.push_str("\n  stderr:\n");
            message.push_str(&indent_block(&stderr));
        }
        Err(message)
    }

    /// The `patina test` flags that select the test's own target. A compiled
    /// test knows its target's crate name (`-` read as `_`), which `patina
    /// test` matches against the target's name.
    #[cfg(feature = "macros")]
    fn target_selection(test: &DstTest) -> Vec<&'static str> {
        match test.bin_name {
            Some(bin) => vec!["--bin", bin],
            None if test.integration_test => vec!["--test", test.crate_name],
            None => vec!["--lib"],
        }
    }

    #[cfg(feature = "macros")]
    fn libtest_exact_name(test: &DstTest) -> String {
        if let Some(rest) = test.test_path.strip_prefix(test.crate_name)
            && let Some(rest) = rest.strip_prefix("::")
            && !rest.is_empty()
        {
            return rest.to_string();
        }
        test.test_path.to_string()
    }

    #[cfg(feature = "macros")]
    fn resolve_cli(test: &DstTest) -> Result<std::path::PathBuf, String> {
        if let Some(raw) = std::env::var_os("PATINA_CLI") {
            if raw.as_os_str().is_empty() {
                return Err(missing_cli_message(test, "PATINA_CLI is set but empty"));
            }
            let path = std::path::PathBuf::from(raw);
            if !path.is_absolute() {
                return Err(missing_cli_message(
                    test,
                    &format!(
                        "PATINA_CLI must be an absolute path to patina, got {}",
                        path.display()
                    ),
                ));
            }
            if !is_executable(&path) {
                return Err(missing_cli_message(
                    test,
                    &format!(
                        "PATINA_CLI points at {}, but it is not an executable file",
                        path.display()
                    ),
                ));
            }
            return Ok(path);
        }

        let path = std::env::var_os("PATH").unwrap_or_default();
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(executable_name("patina"));
            if is_executable(&candidate) {
                return Ok(candidate);
            }
        }
        Err(missing_cli_message(
            test,
            "PATINA_CLI is not set and patina was not found on PATH",
        ))
    }

    #[cfg(feature = "macros")]
    fn missing_cli_message(test: &DstTest, reason: &str) -> String {
        format!(
            "patina dst test could not find the patina tool for {}\n  reason: {reason}\n  install it (to ~/.local/bin):\n    curl -fsSL {}/releases/latest/download/install.sh | sh -s -- --version {}\n  or set PATINA_CLI to the absolute path of a patina binary\n  DST tests never skip when the tool is missing; absence is a test failure.",
            test.test_path,
            env!("CARGO_PKG_REPOSITORY"),
            env!("CARGO_PKG_VERSION"),
        )
    }

    #[cfg(all(feature = "macros", windows))]
    fn executable_name(name: &str) -> String {
        format!("{name}.exe")
    }

    #[cfg(all(feature = "macros", not(windows)))]
    fn executable_name(name: &str) -> &str {
        name
    }

    #[cfg(all(feature = "macros", unix))]
    fn is_executable(path: &std::path::Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            Err(_) => false,
        }
    }

    #[cfg(all(feature = "macros", windows))]
    fn is_executable(path: &std::path::Path) -> bool {
        std::fs::metadata(path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    }

    #[cfg(all(feature = "macros", not(any(unix, windows))))]
    fn is_executable(path: &std::path::Path) -> bool {
        std::fs::metadata(path)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    }

    #[cfg(feature = "macros")]
    fn render_command<'a>(
        program: &std::path::Path,
        args: impl Iterator<Item = &'a std::ffi::OsStr>,
    ) -> String {
        let mut rendered = shell_quote(program.as_os_str());
        for arg in args {
            rendered.push(' ');
            rendered.push_str(&shell_quote(arg));
        }
        rendered
    }

    #[cfg(feature = "macros")]
    fn shell_quote(value: &std::ffi::OsStr) -> String {
        let text = value.to_string_lossy();
        if !text.is_empty()
            && text.chars().all(|ch| {
                ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':' | '=')
            })
        {
            return text.into_owned();
        }
        let mut quoted = String::from("'");
        for ch in text.chars() {
            if ch == '\'' {
                quoted.push_str("'\\''");
            } else {
                quoted.push(ch);
            }
        }
        quoted.push('\'');
        quoted
    }

    #[cfg(feature = "macros")]
    fn indent_block(text: &str) -> String {
        text.lines()
            .map(|line| format!("    {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[cfg(all(test, feature = "macros"))]
    mod tests {
        use super::*;

        const TEST: DstTest = DstTest {
            manifest_dir: "/repo/crate",
            package: "macro-adopter",
            crate_name: "macro_adopter",
            bin_name: None,
            integration_test: true,
            test_path: "macro_adopter::nested::case",
            cli_args: &[],
        };

        #[test]
        fn rerun_commands_name_the_libtest_case_and_quote_for_the_shell() {
            assert_eq!(libtest_exact_name(&TEST), "nested::case");
            assert_eq!(target_selection(&TEST), ["--test", "macro_adopter"]);
            assert_eq!(
                shell_quote(std::ffi::OsStr::new("simple/path")),
                "simple/path"
            );
            assert_eq!(
                shell_quote(std::ffi::OsStr::new("two words")),
                "'two words'"
            );
        }
    }
}
