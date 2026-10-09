use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=fixtures.c");
    println!("cargo:rerun-if-changed=forkwait.cxx");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CXX");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let fixtures = [
        "forkwait-c",
        "sigchld",
        "failed-exec-enoent",
        "failed-exec-eacces",
        "failed-exec-e2big",
        "early-death",
        "atfork-lock",
        "fd-sharing",
        "last-writer-eof",
        "epipe-sigpipe",
        "queued-signals",
        "shared-futex",
    ];
    for bin in fixtures {
        let object = out.join(format!("{bin}.o"));
        let status = Command::new(env::var_os("CC").unwrap_or_else(|| "cc".into()))
            .args([
                "-std=c11",
                "-D_GNU_SOURCE",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-O2",
                "-fPIC",
                "-pthread",
                "-c",
                "fixtures.c",
            ])
            .arg(format!(
                "-DPATINA_MP_FIXTURE_{}",
                bin.replace('-', "_").to_ascii_uppercase()
            ))
            .arg("-o")
            .arg(&object)
            .status()
            .expect("C compiler runs");
        assert!(status.success(), "C fixture {bin} failed to compile");
        println!("cargo:rustc-link-arg-bin={bin}={}", object.display());
    }
    let object = out.join("forkwait-cxx.o");
    let status = Command::new(env::var_os("CXX").unwrap_or_else(|| "c++".into()))
        .args([
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            "-fPIC",
            "-c",
            "forkwait.cxx",
        ])
        .arg("-o")
        .arg(&object)
        .status()
        .expect("C++ compiler runs");
    assert!(status.success(), "C++ fixture failed to compile");
    println!("cargo:rustc-link-arg-bin=forkwait-cxx={}", object.display());
    let cxx_lib = if env::var("CARGO_CFG_TARGET_OS").unwrap() == "macos" {
        "-lc++"
    } else {
        "-lstdc++"
    };
    println!("cargo:rustc-link-arg-bin=forkwait-cxx={cxx_lib}");
}
