//! Native cooperative SDK fixtures, site reporting, and buggify behavior.

use super::*;

/// The SDK guest's source. Its buggify sites all activate and always fire under
/// `--buggify=1000 --buggify-activation-permille 1000`, so the outcome is
/// deterministic without hunting for a firing seed. Every declared SDK site
/// macro sits behind a branch no run takes: invisible to lazy registration,
/// visible through the linked table. The `no-setup` argument skips
/// `setup_complete`, a declared-but-never-called harness bug under
/// `--buggify-after-setup`. The `naps` run parameter sets how many sleeps the
/// run makes; five or more fail it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sdk_main() -> String {
    let registry = patina_dst::SDK_SITE_MACROS
        .iter()
        .map(|site| format!("let _ = patina_dst::{};\n", site.fixture))
        .collect::<String>();
    format!(
        r#"fn main() {{
    if std::env::args().nth(1).as_deref() != Some("no-setup") {{
        patina_dst::lifecycle::setup_complete();
    }}
    if std::hint::black_box(false) {{
{registry}    }}
    let mut fired = 0u32;
    let knob = patina_dst::buggify_knob!("batch", 10_i64, 1, 100);
    for i in 0..8 {{
        patina_dst::reachable!("loop-body");
        if patina_dst::buggify!("early-return") {{
            fired += 1;
        }}
        patina_dst::sometimes!(i == 3, "index-is-three");
    }}
    patina_dst::always!(fired <= 8, "fired-in-bounds");
    // A run parameter that decides how many boundary operations the run makes,
    // so a replay that lost it would diverge from its recording.
    let naps = patina_dst::param("naps");
    let count = naps.as_deref().map_or(0, |naps| naps.parse::<u32>().unwrap_or(0));
    for _ in 0..count {{
        std::thread::sleep(std::time::Duration::from_nanos(1));
    }}
    // The bug parameter minimization hunts: five naps or more fail the run.
    if count >= 5 {{
        eprintln!("too many naps");
        std::process::exit(7);
    }}
    println!("RESULT knob={{knob}} fired={{fired}} rng={{}} naps={{naps:?}}", patina_dst::rng());
}}
"#
    )
}

/// The Cargo target directory the SDK guest builds into, shared with the
/// fixture that checks a build never picks up another package's binary.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn shared_sdk_target() -> PathBuf {
    common::guest_target_dir("sdk-shared-target")
}

/// The SDK guest's package directory and binary, built once per run.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sdk_guest() -> (PathBuf, PathBuf) {
    let binary = super::run_facts::shared_guest("native-sdk-guest", |directory| {
        let package = directory.join("pkg");
        write_sdk_fixture(&package, &sdk_main());
        let manifest = package.join("Cargo.toml");
        let mut contents = fs::read_to_string(&manifest).unwrap();
        contents.push_str("\n[workspace]\n");
        fs::write(&manifest, contents).unwrap();
        let binary = directory.join("sdk-guest");
        invoke_in_with_env(
            native_workspace(),
            &[
                "build",
                package.to_str().unwrap(),
                "--output",
                binary.to_str().unwrap(),
            ],
            &[("CARGO_TARGET_DIR", shared_sdk_target().to_str().unwrap())],
        );
        binary
    });
    let package = binary.parent().unwrap().join("pkg");
    (package, binary)
}

#[cfg(test)]
#[path = "native_sdk/tests.rs"]
mod tests;
