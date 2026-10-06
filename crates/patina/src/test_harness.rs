//! Host orchestration and return-value handling for DST test attributes.

#[cfg(feature = "macros")]
pub use orchestration::{DstTest, DstTestReturn, assert_test_return, orchestrate};

mod orchestration {
    /// Runtime data emitted by `#[patina_dst::test]`.
    #[cfg(feature = "macros")]
    #[doc(hidden)]
    pub struct DstTest {
        pub manifest_dir: &'static str,
        pub harness_target: &'static str,
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
    /// only: discover `cargo-patina`, ask it to rebuild the same libtest target
    /// under the native shim, and panic loudly on any failure.
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
        let cli = resolve_cargo_patina(test)?;
        let exact = libtest_exact_name(test);
        let mut command = std::process::Command::new(&cli);
        command
            .arg("test")
            .arg(test.manifest_dir)
            .arg("--harness-target")
            .arg(test.harness_target)
            .arg("--exact")
            .arg(&exact)
            .args(test.cli_args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let rendered = render_command(&cli, command.get_args());
        let output = command.output().map_err(|error| {
            format!(
                "patina dst test could not launch cargo-patina for {}: {error}\n  command: {rendered}",
                test.test_path
            )
        })?;
        if output.status.success() {
            return Ok(());
        }
        let exit = match output.status.code() {
            Some(code) => code.to_string(),
            None => "terminated by signal".to_string(),
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut message = format!(
            "patina dst test orchestration failed: {}\n  command: {rendered}\n  exit: {exit}",
            test.test_path
        );
        if !stdout.trim().is_empty() {
            message.push_str("\n  stdout:\n");
            message.push_str(&indent_block(&stdout));
        }
        if !stderr.trim().is_empty() {
            message.push_str("\n  stderr:\n");
            message.push_str(&indent_block(&stderr));
        }
        Err(message)
    }

    #[cfg(feature = "macros")]
    fn libtest_exact_name(test: &DstTest) -> String {
        if let Some(rest) = test.test_path.strip_prefix(test.harness_target)
            && let Some(rest) = rest.strip_prefix("::")
            && !rest.is_empty()
        {
            return rest.to_string();
        }
        test.test_path.to_string()
    }

    #[cfg(feature = "macros")]
    fn resolve_cargo_patina(test: &DstTest) -> Result<std::path::PathBuf, String> {
        if let Some(raw) = std::env::var_os("PATINA_CLI") {
            if raw.as_os_str().is_empty() {
                return Err(missing_cli_message(test, "PATINA_CLI is set but empty"));
            }
            let path = std::path::PathBuf::from(raw);
            if !path.is_absolute() {
                return Err(missing_cli_message(
                    test,
                    &format!(
                        "PATINA_CLI must be an absolute path to cargo-patina, got {}",
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
            let candidate = dir.join(executable_name("cargo-patina"));
            if is_executable(&candidate) {
                return Ok(candidate);
            }
        }
        Err(missing_cli_message(
            test,
            "PATINA_CLI is not set and cargo-patina was not found on PATH",
        ))
    }

    #[cfg(feature = "macros")]
    fn missing_cli_message(test: &DstTest, reason: &str) -> String {
        format!(
            "patina dst test could not find cargo-patina for {}\n  reason: {reason}\n  remedies:\n    set PATINA_CLI to the absolute path of a cargo-patina binary\n    or put cargo-patina on PATH\n  DST tests never skip when the CLI is missing; absence is a test failure.",
            test.test_path
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
            harness_target: "macro_adopter",
            test_path: "macro_adopter::nested::case",
            cli_args: &[],
        };

        #[test]
        fn libtest_exact_strips_the_harness_crate_segment() {
            assert_eq!(libtest_exact_name(&TEST), "nested::case");
        }

        #[test]
        fn missing_cli_message_is_a_loud_failure_not_a_skip() {
            let message = missing_cli_message(
                &TEST,
                "PATINA_CLI is not set and cargo-patina was not found on PATH",
            );
            assert!(message.contains("could not find cargo-patina"));
            assert!(message.contains("set PATINA_CLI"));
            assert!(message.contains("put cargo-patina on PATH"));
            assert!(message.contains("never skip"));
        }

        #[test]
        fn shell_quote_preserves_copy_pasteable_commands() {
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
