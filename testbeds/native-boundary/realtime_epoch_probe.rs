// The virtual wall clock an ordinary std program reads. `SystemTime` and the
// filesystem's timestamps come from one clock, which starts at the run's
// realtime epoch (Patina's default, or `run --realtime-epoch`): a file written
// after the read can never be stamped before it.
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let Ok(epoch) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        std::process::exit(20);
    };
    if std::fs::write("/stamp", b"x").is_err() {
        std::process::exit(21);
    }
    let Ok(modified) = std::fs::metadata("/stamp").and_then(|metadata| metadata.modified()) else {
        std::process::exit(22);
    };
    let Ok(mtime) = modified.duration_since(UNIX_EPOCH) else {
        std::process::exit(23);
    };
    if mtime < epoch {
        std::process::exit(24);
    }
    println!(
        "NATIVE_REALTIME_EPOCH_RESULT epoch_ns={} mtime_ns={}",
        epoch.as_nanos(),
        mtime.as_nanos()
    );
}
