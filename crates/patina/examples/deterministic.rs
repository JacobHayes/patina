use patina_dst::{ClockKind, RuntimeError};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (seed, entropy, time, stored) = patina_dst::run(|context| {
        let entropy = context.entropy_bytes(12)?;
        context.write_file("/state/entropy", &entropy)?;
        context.sleep_for(250_000_000)?;
        let time = context.now(ClockKind::Monotonic)?;
        let stored = context.read_file("/state/entropy")?;
        Ok::<_, RuntimeError>((context.root_seed(), entropy, time, stored))
    })?;

    println!(
        "PATINA_RESULT seed={seed} entropy={} time_ns={time} stored={}",
        hex(&entropy),
        hex(&stored)
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
        output
    })
}
