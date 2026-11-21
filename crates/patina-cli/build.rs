//! Build the in-guest runtime (`patina-rt`, its own workspace, the bare target of the
//! architecture `patina` is built for, release profile) and hand its path to `include_bytes!` in `launch.rs`, so `patina` is one
//! self-contained binary. `PATINA_TEST_RT=path` at run time overrides the embedded runtime.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let rt = manifest.join("../patina-rt");
    let proto = manifest.join("../patina-proto");
    for p in [
        "src",
        "Cargo.toml",
        "build.rs",
        "link.ld",
        ".cargo/config.toml",
    ] {
        println!("cargo:rerun-if-changed={}", rt.join(p).display());
    }
    for p in ["src", "Cargo.toml"] {
        println!("cargo:rerun-if-changed={}", proto.join(p).display());
    }
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let target_dir = out.join("rt-target");
    let rt_target = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86_64-unknown-none",
        Ok("aarch64") => "aarch64-unknown-none-softfloat",
        a => panic!("patina has no runtime for the architecture {a:?}"),
    };
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    // The outer build's settings are for the host target; none of them may reach the runtime's.
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy();
        if (k.starts_with("CARGO_") && k != "CARGO_HOME")
            || k.starts_with("RUSTC")
            || k == "RUSTFLAGS"
            || k == "RUSTDOCFLAGS"
        {
            cmd.env_remove(&*k);
        }
    }
    let status = cmd
        .current_dir(&rt)
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            rt_target,
            "--target-dir",
        ])
        .arg(&target_dir)
        .status()
        .expect("run cargo for patina-rt");
    assert!(status.success(), "building patina-rt failed");
    let bin = target_dir.join(rt_target).join("release/patina-rt");
    println!("cargo:rustc-env=PATINA_RT_EMBED={}", bin.display());
    // The runtime file's name (`launch::rt_file`), worked out here rather than on every run.
    let data = std::fs::read(&bin).expect("read patina-rt");
    println!("cargo:rustc-env=PATINA_RT_ID={:016x}", rt_id(&data));
}

/// `proto::rec::hash_bytes(0x7274, data)` (`launch` tests that the two agree).
fn rt_id(data: &[u8]) -> u64 {
    fn mix64(mut z: u64) -> u64 {
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    let mut h = mix64(
        0x7274 ^ 0x243f_6a88_85a3_08d3 ^ (data.len() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15),
    );
    let (chunks, rest) = data.as_chunks::<8>();
    for c in chunks {
        h = mix64(h ^ u64::from_le_bytes(*c))
            .rotate_left(23)
            .wrapping_add(0x9e37_79b9_7f4a_7c15);
    }
    if !rest.is_empty() {
        let mut b = [0u8; 8];
        b[..rest.len()].copy_from_slice(rest);
        h = mix64(h ^ u64::from_le_bytes(b) ^ 0xff);
    }
    mix64(h)
}
