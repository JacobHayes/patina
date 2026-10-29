//! Regression tests for output.

use super::*;

#[test]
fn extract_pulls_flags_and_leaves_program_args() {
    let args: Vec<OsString> = [
        "replay",
        "bin",
        "t.patina",
        "--render",
        "out.html",
        "--format",
        "json",
        "--",
        "--render",
        "guestflag",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let (opts, rest) = extract(args).unwrap();
    assert_eq!(opts.format, OutputFormat::Json);
    assert_eq!(opts.render, Some(PathBuf::from("out.html")));
    // The post-`--` `--render` is a guest flag and must survive.
    let rest: Vec<String> = rest
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        rest,
        vec!["replay", "bin", "t.patina", "--", "--render", "guestflag"]
    );
    // `--output` is the build/minimize artifact-path flag and is never swallowed by the format
    // selector.
    {
        // Regression: `--output` is the build/minimize artifact-path flag and must
        // never be swallowed by the format selector.
        let args: Vec<OsString> = ["build", "demo.rs", "--output", "demo"]
            .iter()
            .map(OsString::from)
            .collect();
        let (opts, rest) = extract(args).unwrap();
        assert_eq!(opts.format, OutputFormat::Human);
        let rest: Vec<String> = rest
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(rest, vec!["build", "demo.rs", "--output", "demo"]);
    }
}
