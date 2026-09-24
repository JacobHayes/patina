//! `conformance-coverage`: the registry entries of this target that no
//! conformance scenario covers and no exclusion accounts for. Exits 1 when
//! any exist.

#[cfg(target_os = "linux")]
fn main() {
    let report = patina_dst_conformance::coverage::uncovered();
    for row in &report.syscalls {
        println!("syscall {} ({})", row.name, row.disposition.render());
    }
    for row in &report.symbols {
        println!("symbol {} ({})", row.name, row.status.render());
    }
    println!(
        "uncovered: {} syscall rows, {} symbol rows (no scenario, no exclusion)",
        report.syscalls.len(),
        report.symbols.len()
    );
    std::process::exit(if report.is_empty() { 0 } else { 1 });
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("conformance-coverage: the scenarios are the Linux syscall ABI");
    std::process::exit(2);
}
