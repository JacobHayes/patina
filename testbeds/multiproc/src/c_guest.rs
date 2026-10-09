use std::ffi::CString;

extern "C" {
    fn multiproc_fixture(dir: *const std::ffi::c_char) -> i32;
}

fn main() {
    let name = env!("CARGO_BIN_NAME");
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--help") {
        println!("Usage: {name} DIRECTORY\nSelf-checking native process fixture; Patina currently refuses this pending gap.");
        return;
    }
    assert_eq!(args.len(), 1, "one scratch directory argument required");
    std::fs::create_dir_all(&args[0]).expect("scratch directory");
    let dir = CString::new(args[0].as_str()).unwrap();
    // SAFETY: the C fixture receives a live nul-terminated directory string.
    let status = unsafe { multiproc_fixture(dir.as_ptr()) };
    if status != 0 {
        patina_dst::verdict(
            patina_dst::VerdictKind::Violation,
            name,
            "native process invariant failed",
        );
        std::process::exit(status);
    }
    patina_dst::verdict(
        patina_dst::VerdictKind::Pass,
        name,
        "process invariants hold",
    );
    let digest = name.bytes().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    });
    println!("MP_RESULT workload={name} digest={digest:016x}");
}
