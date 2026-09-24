// An ordinary Rust program: no Patina-specific init/shutdown calls. The
// packaged `cargo patina build`/`run` startup path installs and
// finalizes the deterministic runtime around it.
fn main() {
    use std::hash::{BuildHasher, Hasher};

    println!("PATINA_STRACE_MARKER");

    let mut first_hash = std::collections::hash_map::RandomState::new().build_hasher();
    first_hash.write(b"patina");
    let mut second_hash = std::collections::hash_map::RandomState::new().build_hasher();
    second_hash.write(b"patina");
    let (first_hash, second_hash) = (first_hash.finish(), second_hash.finish());
    if first_hash == second_hash {
        std::process::exit(32);
    }
    let Ok(system) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        std::process::exit(21);
    };
    // Patina's default virtual realtime epoch, 2026-07-22T23:00:09Z, read at
    // monotonic zero. Read after the entropy draws: a run with no runtime
    // installed is refused at its first entropy request, while a clock read
    // there answers from the shim's bootstrap window.
    if system.as_nanos() != 1_784_761_209_000_000_000 {
        std::process::exit(30);
    }
    let started = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(2));
    if started.elapsed() != std::time::Duration::from_millis(2) {
        std::process::exit(31);
    }
    if std::fs::create_dir("/state").is_err() {
        std::process::exit(40);
    }
    if std::fs::create_dir("/state/nested").is_err() {
        std::process::exit(41);
    }
    if std::fs::write("/state/value", b"ordinary-std").is_err() {
        std::process::exit(42);
    }
    if std::os::unix::fs::symlink("value", "/state/link").is_err() {
        std::process::exit(43);
    }
    if !matches!(std::fs::metadata("/state/value"), Ok(value) if value.len() == 12) {
        std::process::exit(44);
    }
    if !matches!(std::fs::read("/state/value"), Ok(value) if value == b"ordinary-std") {
        std::process::exit(45);
    }

    let mut entries = Vec::new();
    let Ok(read_dir) = std::fs::read_dir("/state") else {
        std::process::exit(46);
    };
    for entry in read_dir {
        let Ok(entry) = entry else {
            std::process::exit(47);
        };
        let Ok(file_type) = entry.file_type() else {
            std::process::exit(48);
        };
        let kind = if file_type.is_symlink() {
            "symlink"
        } else if file_type.is_dir() {
            "dir"
        } else if file_type.is_file() {
            "file"
        } else {
            std::process::exit(49);
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            std::process::exit(50);
        };
        entries.push(format!("{name}:{kind}"));
    }
    let fs_summary = entries.join(",");
    if fs_summary != "link:symlink,nested:dir,value:file" {
        std::process::exit(51);
    }
    if !matches!(std::fs::read_link("/state/link"), Ok(target) if target == std::path::Path::new("value"))
    {
        std::process::exit(52);
    }
    if !matches!(std::fs::symlink_metadata("/state/link"), Ok(metadata) if metadata.file_type().is_symlink())
    {
        std::process::exit(53);
    }
    if !matches!(std::fs::metadata("/state/link"), Ok(metadata) if metadata.len() == 12 && metadata.is_file())
    {
        std::process::exit(54);
    }

    if std::fs::rename("/state/value", "/state/renamed").is_err() {
        std::process::exit(55);
    }
    if std::fs::remove_file("/state/link").is_err() {
        std::process::exit(56);
    }
    if std::fs::remove_file("/state/renamed").is_err() {
        std::process::exit(57);
    }
    if std::fs::remove_dir("/state/nested").is_err() {
        std::process::exit(58);
    }
    if std::fs::remove_dir("/state").is_err() {
        std::process::exit(59);
    }
    println!(
        "NATIVE_STD_RESULT epoch_ns={} first_hash={first_hash:016x} second_hash={second_hash:016x} fs={fs_summary}",
        system.as_nanos(),
    );
}
