//! The one probe binary: `conformance-probe <scenario> --vehicle V --dir D
//! [--strict]` runs one scenario through one vehicle, writing its events on
//! stdout (crates/patina-conformance/src/lib.rs).

#[cfg(target_os = "linux")]
fn main() {
    use patina_dst_conformance::catalog;
    use patina_dst_conformance::probe::Probe;
    use patina_dst_conformance::vehicle::Vehicle;

    const USAGE: &str =
        "usage: conformance-probe <scenario> --vehicle libc|syscall|raw --dir DIR [--strict]";
    let fail = |message: String| -> ! {
        eprintln!("{message}\n{USAGE}");
        std::process::exit(2)
    };
    let mut args = std::env::args().skip(1);
    let name = args
        .next()
        .unwrap_or_else(|| fail("missing scenario".into()));
    let (mut vehicle, mut dir, mut strict) = (None, None, false);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--vehicle" => {
                let value = args.next().unwrap_or_default();
                vehicle =
                    Some(Vehicle::parse(&value).unwrap_or_else(|| {
                        fail(format!("no vehicle {value:?} on this architecture"))
                    }));
            }
            "--dir" => dir = args.next(),
            "--strict" => strict = true,
            other => fail(format!("unknown argument {other:?}")),
        }
    }
    let vehicle = vehicle.unwrap_or_else(|| fail("missing --vehicle".into()));
    let dir = dir.unwrap_or_else(|| fail("missing --dir".into()));
    let (name, run) = match catalog::scenario(&name) {
        Some(scenario) if scenario.vehicles.contains(&vehicle) => (scenario.name, scenario.run),
        Some(scenario) => fail(format!(
            "{} has no shape through {}",
            scenario.name,
            vehicle.name()
        )),
        None => {
            catalog::planted(&name).unwrap_or_else(|| fail(format!("unknown scenario {name:?}")))
        }
    };
    run(&Probe::new(name, vehicle, strict, dir));
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("conformance-probe: the scenarios are the Linux syscall ABI");
    std::process::exit(2);
}
