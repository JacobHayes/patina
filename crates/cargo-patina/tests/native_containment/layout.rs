//! The guest's address layout: one seed, one set of addresses, and the
//! operator's explicit opt-out for hosts that forbid it.
use crate::common;
use common::native::*;

/// `address_layout_probe.rs`'s report: each region's address, and the order
/// of its small heap blocks by a hash of their addresses.
fn address_layout(output: &[u8]) -> std::collections::BTreeMap<&str, &str> {
    text(output)
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect()
}

/// The probe's mode that reports the first layout and skips the churn, for
/// the tests about the layout policy rather than about the layout itself.
const NO_CHURN: &str = "no-churn";

// With randomization off, the kernel puts the guest's image where it was
// linked, in every run of a seed, recorded or replayed. On Linux the initial
// stack the control plane cannot resize puts the main stack and its first
// thread-local block at fixed addresses too, and everything else the probe
// reports — thread stacks, heap blocks and mappings, before and after a churn
// of recorded operations beside guest allocations, and the pointer-keyed
// order — is a function of the guest's own allocations, because the runtime
// allocates from an arena of its own: the same in a seeded run, a recording
// and its replay. On Darwin the thread stacks sit at fixed addresses; the main
// stack moves with the length of the kernel's random apple strings, and the
// heap (with the thread-local block dyld allocates from it) is placed by
// libmalloc from exec-time entropy no seed reaches (VALIDATION.md, the
// unpaired list).
#[test]
fn address_layout_is_the_same_in_every_run_of_a_seed() {
    let g = Guest::assert_build("address_layout_probe.rs");
    let pinned: &[&str] = if cfg!(target_os = "linux") {
        &[
            "code",
            "stack",
            "tls",
            "heap",
            "mmap",
            "after-churn-heap-16",
            "after-churn-mmap-1",
        ]
    } else {
        &["code", "thread-stack"]
    };
    let seeded = g.assert_run_success(1, &[]).stdout;
    let trace = g.dir.path().join("layout.patina");
    let record = || {
        g.assert_run_success(1, &["--record", trace.to_str().unwrap()])
            .stdout
    };
    let runs = [
        g.assert_run_success(1, &[]).stdout,
        record(),
        record(),
        assert_success(g.command("replay", &[trace.to_str().unwrap()])).stdout,
    ];
    let baseline = address_layout(&seeded);
    for region in pinned {
        assert!(baseline.contains_key(region), "{}", text(&seeded));
    }
    for run in &runs {
        let layout = address_layout(run);
        if cfg!(target_os = "linux") {
            assert_eq!(baseline, layout, "every line: {}", text(run));
        }
        for region in pinned {
            assert_eq!(baseline[region], layout[region], "{region}: {}", text(run));
        }
    }
}

/// `cargo patina run` of `g` at seed 1, with `args`, from a parent whose soft
/// stack limit is `soft` and whose hard limit is `hard` (`None` keeps the
/// inherited one).
#[cfg(target_os = "linux")]
fn run_with_stack_limit(
    g: &Guest,
    soft: u64,
    hard: Option<u64>,
    args: &[&str],
) -> std::process::Output {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_cargo-patina"));
    command
        .current_dir(common::native_workspace())
        .arg("run")
        .arg(&g.binary)
        .args(["--seed", "1"])
        .args(args);
    // SAFETY: `getrlimit` and `setrlimit` are async-signal-safe and allocate
    // nothing.
    unsafe {
        command.pre_exec(move || {
            let mut limit = std::mem::zeroed::<libc::rlimit>();
            if libc::getrlimit(libc::RLIMIT_STACK, &mut limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            limit.rlim_cur = soft;
            limit.rlim_max = hard.unwrap_or(limit.rlim_max);
            if libc::setrlimit(libc::RLIMIT_STACK, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    common::output_with_deadline(&mut command, std::time::Duration::from_secs(60))
        .expect("native run exceeded 60s")
}

// The kernel sizes the gap below the main stack, and glibc the threads'
// default stacks, from the stack limit at exec. The supervisor execs every
// guest at the modeled limit, so a seed's layout is the same whatever limit
// the supervisor itself inherited.
#[cfg(target_os = "linux")]
#[test]
fn the_inherited_stack_limit_does_not_move_the_layout() {
    let g = Guest::assert_build("address_layout_probe.rs");
    // SAFETY: `limit` is a writable `struct rlimit`.
    let hard = unsafe {
        let mut limit = std::mem::zeroed::<libc::rlimit>();
        assert_eq!(libc::getrlimit(libc::RLIMIT_STACK, &mut limit), 0);
        limit.rlim_max
    };
    let limits: Vec<u64> = [8 << 20, 256 << 20, libc::RLIM_INFINITY]
        .into_iter()
        .filter(|soft| *soft <= hard)
        .collect();
    assert!(
        limits.len() >= 2,
        "the hard stack limit {hard} leaves nothing to compare"
    );
    let baseline = assert_success(run_with_stack_limit(&g, limits[0], None, &[])).stdout;
    for soft in &limits[1..] {
        let run = assert_success(run_with_stack_limit(&g, *soft, None, &[])).stdout;
        assert_eq!(
            text(&baseline),
            text(&run),
            "inherited soft stack limit {soft}"
        );
    }
}

// A guest that raises its stack limit gets the main stack it asked for, and
// the raise moves nothing: the layout was fixed at exec.
#[cfg(target_os = "linux")]
#[test]
fn a_raised_stack_limit_grows_the_main_stack_and_moves_no_mapping() {
    let g = Guest::assert_build("address_layout_probe.rs");
    // The probe ignores any other argument; one of the same length leaves the
    // initial stack and the heap as `deep-stack` does.
    let plain = g.assert_run_success(1, &["--", "flat-stack"]).stdout;
    let deep = g.assert_run_success(1, &["--", "deep-stack"]).stdout;
    assert_eq!(text(&plain), text(&deep));
}

// A stack limit past the host's hard limit cannot be applied: the run stops,
// and the envelope attributes the stop to the host, not to the guest.
#[cfg(target_os = "linux")]
#[test]
fn a_stack_limit_the_host_cannot_apply_is_the_hosts_refusal() {
    let g = Guest::assert_build("address_layout_probe.rs");
    let modeled = 8 << 20;
    let stopped = run_with_stack_limit(
        &g,
        modeled,
        Some(modeled),
        &["--format", "json", "--", "deep-stack"],
    );
    assert!(!stopped.status.success(), "{stopped:?}");
    let result = envelope(&stopped);
    assert_eq!(result["refusal"]["class"], "host_limit", "{result}");
}

// A randomized launch pads nothing, so a small inherited stack limit, whose
// argument space the padding would overflow, still runs it.
#[cfg(target_os = "linux")]
#[test]
fn a_randomized_launch_fits_a_small_inherited_stack_limit() {
    let g = Guest::assert_build("address_layout_probe.rs");
    let ran = run_with_stack_limit(&g, 1 << 20, None, &["--allow-randomized-address-layout"]);
    assert!(text(&assert_success(ran).stdout).contains("code="));
}

// The shim checks the layout the supervisor promised: a guest exec'd with the
// promise but with randomization on stops before `main`, and runs without it.
#[test]
fn a_fixed_layout_the_host_did_not_apply_stops_the_run() {
    let g = Guest::assert_build("address_layout_probe.rs");
    let control = [("PATINA_MODE", "seeded"), ("PATINA_SEED", "1")];
    let mut promised = std::process::Command::new(&g.binary);
    promised
        .env_clear()
        .envs(control)
        .env("PATINA_ADDRESS_LAYOUT", "fixed");
    // The test's own parent may run with randomization off (`setarch -R`);
    // the guest must not inherit that.
    #[cfg(target_os = "linux")]
    // SAFETY: `personality` is async-signal-safe and allocates nothing.
    unsafe {
        use std::os::unix::process::CommandExt;
        promised.pre_exec(|| {
            let persona = libc::personality(0xffff_ffff);
            if persona == -1
                || libc::personality((persona & !libc::ADDR_NO_RANDOMIZE) as libc::c_ulong) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let refused = common::output_with_deadline(&mut promised, std::time::Duration::from_secs(20))
        .expect("standalone guest exceeded 20s");
    assert!(!refused.status.success(), "{refused:?}");
    assert!(refused.stdout.is_empty(), "{refused:?}");
    assert!(
        text(&refused.stderr).contains("PATINA_ADDRESS_LAYOUT"),
        "{refused:?}"
    );
    assert_standalone_success(&g.binary, &[], &control);
}

/// A seccomp filter like Docker's default profile for `personality`: the
/// personas it lists pass, every other one is `EPERM`.
#[cfg(target_os = "linux")]
fn docker_personality_filter() -> Vec<libc::sock_filter> {
    const ALLOWED: [u32; 5] = [0, 0x8, 0x20000, 0x20008, 0xffff_ffff];
    // `struct seccomp_data`: the call number, then (after the arch and the
    // instruction pointer) the arguments; the persona is the low word of the
    // first.
    const NR: u32 = 0;
    const ARG0: u32 = 16;
    let statement = |code: u32, k: u32| libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let equals = |k: u32, jt: usize, jf: usize| libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt: jt as u8,
        jf: jf as u8,
        k,
    };
    let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    let ret = libc::BPF_RET | libc::BPF_K;
    // The program's last instruction allows; each jump counts the
    // instructions it skips to reach it.
    let length = 3 + ALLOWED.len() + 2;
    let to_allow = |index: usize| length - 1 - index - 1;
    let mut program = vec![
        statement(load, NR),
        equals(libc::SYS_personality as u32, 0, to_allow(1)),
        statement(load, ARG0),
    ];
    for persona in ALLOWED {
        let index = program.len();
        program.push(equals(persona, to_allow(index), 0));
    }
    program.push(statement(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    program.push(statement(ret, libc::SECCOMP_RET_ALLOW));
    assert_eq!(program.len(), length);
    program
}

/// `cargo patina VERB` from a parent under [`docker_personality_filter`].
#[cfg(target_os = "linux")]
fn under_docker_seccomp(args: &[&str]) -> std::process::Output {
    use std::os::unix::process::CommandExt;
    let program = docker_personality_filter();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_cargo-patina"));
    command.current_dir(common::native_workspace()).args(args);
    // SAFETY: `prctl` is async-signal-safe; the filter was built before the
    // fork and the hook allocates nothing.
    unsafe {
        command.pre_exec(move || {
            let filter = libc::sock_fprog {
                len: program.len() as u16,
                filter: program.as_ptr().cast_mut(),
            };
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &raw const filter,
                ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    common::output_with_deadline(&mut command, std::time::Duration::from_secs(60))
        .expect("native command exceeded 60s")
}

/// The last line of `output`'s stdout, a JSON result envelope.
#[cfg(target_os = "linux")]
fn envelope(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_str(text(&output.stdout).lines().last().unwrap()).unwrap()
}

// A host that forbids turning randomization off (Docker's default seccomp
// profile) refuses the run before the guest starts, and names the opt-out.
#[cfg(target_os = "linux")]
#[test]
fn a_host_that_forbids_a_fixed_layout_refuses_the_run_by_name() {
    let g = Guest::assert_build("address_layout_probe.rs");
    let refused = under_docker_seccomp(&["run", g.binary.to_str().unwrap(), "--seed", "1"]);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(!text(&refused.stdout).contains("code="), "{refused:?}");
    assert!(
        text(&refused.stderr).contains("--allow-randomized-address-layout"),
        "{refused:?}"
    );
}

// With the opt-out the same host runs the guest: the result envelope
// qualifies the run, the trace records the choice, and a replay must make it
// too, in both directions.
#[cfg(target_os = "linux")]
#[test]
fn the_randomized_layout_opt_out_qualifies_the_run_and_binds_its_replay() {
    const FLAG: &str = "--allow-randomized-address-layout";
    let g = Guest::assert_build("address_layout_probe.rs");
    let binary = g.binary.to_str().unwrap();
    let trace = g.dir.path().join("randomized.patina");
    let trace = trace.to_str().unwrap();
    let recorded = assert_success(under_docker_seccomp(&[
        "run", binary, "--seed", "1", "--record", trace, FLAG, "--format", "json", "--", NO_CHURN,
    ]));
    let result = envelope(&recorded);
    let kinds: Vec<&str> = result["qualifications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|qualification| qualification["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["randomized_address_layout"], "{result}");
    assert_eq!(
        result["trace"]["metadata"]["address_layout"], "randomized",
        "{result}"
    );
    assert!(
        result["stdout"].as_str().unwrap().contains("code="),
        "{result}"
    );

    let unqualified = assert_refused(g.command("replay", &[trace]), &[FLAG]);
    assert!(
        !text(&unqualified.stdout).contains("code="),
        "{unqualified:?}"
    );
    let replayed = assert_success(under_docker_seccomp(&["replay", binary, trace, FLAG]));
    assert!(text(&replayed.stdout).contains("code="), "{replayed:?}");
    assert!(text(&replayed.stderr).contains(FLAG), "{replayed:?}");

    let fixed = g.dir.path().join("fixed.patina");
    let fixed = fixed.to_str().unwrap();
    g.assert_run_success(1, &["--record", fixed, "--", NO_CHURN]);
    assert_refused(g.command("replay", &[fixed, FLAG]), &[FLAG]);
}

// A trace with no layout was recorded before Patina controlled it, with the
// host's randomization on: replay accepts it only as randomized, and says why.
#[test]
fn a_trace_without_a_layout_replays_only_as_randomized() {
    const FLAG: &str = "--allow-randomized-address-layout";
    let g = Guest::assert_build("address_layout_probe.rs");
    let fixed = g.dir.path().join("fixed.patina");
    g.assert_run_success(1, &["--record", fixed.to_str().unwrap(), "--", NO_CHURN]);
    let mut bundle = patina_dst_trace::TraceBundle::load(&fixed).unwrap();
    assert_eq!(
        bundle.metadata.address_layout,
        Some(patina_dst_trace::AddressLayout::Fixed)
    );
    bundle.metadata.address_layout = None;
    let legacy = g.dir.path().join("legacy.patina");
    bundle.write_atomic(&legacy).unwrap();
    let legacy = legacy.to_str().unwrap();
    let refused = assert_refused(g.command("replay", &[legacy]), &[FLAG]);
    assert!(!text(&refused.stdout).contains("code="), "{refused:?}");
    let replayed = assert_success(g.command("replay", &[legacy, FLAG]));
    assert!(text(&replayed.stdout).contains("code="), "{replayed:?}");
}

// A campaign started with the opt-out runs every generation with it, on a
// host that refuses a fixed layout, and records the choice in its spec.
#[cfg(target_os = "linux")]
#[test]
fn a_campaign_with_the_opt_out_runs_every_generation_under_it() {
    let g = Guest::assert_build("address_layout_probe.rs");
    let out = g.dir.path().join("campaign");
    let out = out.to_str().unwrap();
    let binary = g.binary.to_str().unwrap();
    assert_success(under_docker_seccomp(&[
        "campaign",
        binary,
        "--gens",
        "2",
        "--out-dir",
        out,
        "--allow-randomized-address-layout",
        "--",
        NO_CHURN,
    ]));
    let state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::path::Path::new(out).join("campaign-state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["spec"]["address_layout"], "randomized", "{state}");
}

/// `g`'s binary launched directly with `args`, without the supervisor,
/// replaying `trace` through an inherited descriptor.
fn replay_standalone(
    g: &Guest,
    trace: &std::path::Path,
    fingerprint: &str,
    args: &[&str],
) -> std::process::Output {
    let mut command = std::process::Command::new("/bin/sh");
    command
        .env_clear()
        .args(["-c", "exec 3<\"$1\"; shift; exec \"$@\"", "replay"])
        .arg(trace)
        .arg(&g.binary)
        .args(args)
        .envs([
            ("PATINA_MODE", "replay"),
            ("PATINA_TRACE_FD", "3"),
            ("PATINA_FINGERPRINT", fingerprint),
        ]);
    common::output_with_deadline(&mut command, std::time::Duration::from_secs(20))
        .expect("standalone replay exceeded 20s")
}

// A launch without the supervisor keeps the host's randomization, so it may
// replay only a trace that ran randomized too: a fixed recording is refused
// and pointed at `cargo patina replay`, while a standalone recording, which
// records no layout, replays standalone.
#[test]
fn a_standalone_replay_refuses_a_fixed_recording() {
    let g = Guest::assert_build("address_layout_probe.rs");
    let fixed = g.dir.path().join("fixed.patina");
    g.assert_run_success(1, &["--record", fixed.to_str().unwrap(), "--", NO_CHURN]);
    let refused = replay_standalone(&g, &fixed, "patina-native", &[NO_CHURN]);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(!text(&refused.stdout).contains("code="), "{refused:?}");
    assert!(
        text(&refused.stderr).contains("cargo patina replay"),
        "{refused:?}"
    );

    let (recorded, standalone) = g.record_standalone(&[NO_CHURN]);
    assert_success(recorded);
    let replayed = assert_success(replay_standalone(
        &g,
        &standalone,
        "native-boundary",
        &[NO_CHURN],
    ));
    assert!(text(&replayed.stdout).contains("code="), "{replayed:?}");
}

// A native campaign records its layout policy from its first generation. A
// state without one predates layout control: its generations ran with the
// host's randomization, so continuing it is refused rather than mixing layouts.
#[test]
fn a_campaign_from_before_layout_control_is_not_continued() {
    let g = Guest::assert_build("address_layout_probe.rs");
    let out = g.dir.path().join("campaign");
    let campaign = |args: &[&str]| {
        let mut argv = vec!["campaign"];
        argv.extend_from_slice(args);
        common::invoke_with_deadline(
            env!("CARGO_BIN_EXE_cargo-patina"),
            common::native_workspace(),
            &argv,
            std::time::Duration::from_secs(120),
        )
        .expect("campaign exceeded 120s")
    };
    let out_dir = out.to_str().unwrap();
    let binary = g.binary.to_str().unwrap();
    assert_success(campaign(&[
        binary,
        "--gens",
        "1",
        "--out-dir",
        out_dir,
        "--",
        NO_CHURN,
    ]));
    // The continuation itself works on the state as written.
    assert_success(campaign(&["--extend", "1", "--out-dir", out_dir]));
    let state_path = out.join("campaign-state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(state["spec"]["address_layout"], "fixed", "{state}");

    state["spec"]
        .as_object_mut()
        .unwrap()
        .remove("address_layout");
    let legacy = serde_json::to_vec(&state).unwrap();
    std::fs::write(&state_path, &legacy).unwrap();
    let refused = campaign(&["--extend", "1", "--out-dir", out_dir]);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(text(&refused.stderr).contains("--out-dir"), "{refused:?}");
    assert_eq!(std::fs::read(&state_path).unwrap(), legacy);
}

/// A C guest that prints `main ran`, linked by hand over the POSIX layer with
/// the allocator routing or without it, and with the driver flags `flags`.
#[cfg(target_os = "linux")]
fn main_ran_guest(routed: bool, flags: &[&str]) -> Guest {
    let archive = common::shim_archive();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("guest.c");
    std::fs::write(
        &source,
        "#include <stdio.h>\nint main(void) { return puts(\"main ran\") < 0; }\n",
    )
    .unwrap();
    let binary = dir.path().join("guest");
    let mut cc = common::c_compiler();
    // The product link's dead-section removal, so the C link drops the std
    // sections nothing uses (and their imports the audit refuses).
    cc.arg(&source)
        .arg(common::compile_posix_object(dir.path()))
        .arg(&archive)
        .arg("-Wl,--gc-sections")
        .args(flags);
    if routed {
        cc.args(common::shim_linker_args(&archive, dir.path()));
    } else {
        cc.arg("-Wl,--wrap=dlsym");
    }
    assert_success(cc.arg("-o").arg(&binary).output().unwrap());
    Guest { dir, binary }
}

// The runtime keeps its allocations off the guest's heap only where the link
// routes Rust's allocator entry points to its arena. A binary linked without
// the routing would run with heap addresses that differ between a seeded run,
// a recording and its replay, so a fixed-layout run of it stops before its
// `main`; the same program linked with the routing runs.
#[cfg(target_os = "linux")]
#[test]
fn a_binary_linked_without_the_allocator_routing_stops_the_run() {
    let unrouted = main_ran_guest(false, &[]).command("run", &["--seed", "1"]);
    assert!(!unrouted.status.success(), "{}", text(&unrouted.stderr));
    assert!(!text(&unrouted.stdout).contains("main ran"));
    let routed = main_ran_guest(true, &[]).assert_run_success(1, &[]);
    assert!(text(&routed.stdout).contains("main ran"));
}

// The routing is code the link wraps onto, not linker symbol assignments, so
// every linker with `--wrap` links it: gold too, whose `--defsym` cannot name
// a wrapped symbol's real definition. (Gold's dead-section removal keeps a
// `splice` import of std's that GNU ld drops, with or without the routing, so
// the run allows it.)
#[cfg(target_os = "linux")]
#[test]
fn a_gold_link_routes_the_runtime_allocations() {
    let gold = common::c_compiler()
        .args(["-fuse-ld=gold", "-Wl,--version"])
        .output()
        .is_ok_and(|output| output.status.success() && text(&output.stdout).contains("gold"));
    if !gold {
        eprintln!("skipped: this host's C compiler has no gold linker (-fuse-ld=gold)");
        return;
    }
    let routed = main_ran_guest(true, &["-fuse-ld=gold"])
        .assert_run_success(1, &["--allow-unsupported-symbols", "splice"]);
    assert!(text(&routed.stdout).contains("main ran"));
}

// The kernel grows a stack mapping (`MAP_GROWSDOWN`) down into address space
// nothing maps, and how much of the arena's region is unmapped differs by
// mode, so a guest stack mapping is refused by name (`ENOSYS`) wherever it
// is asked for: one just above the region never grows into it.
#[cfg(target_os = "linux")]
#[test]
fn a_stack_mapping_is_refused_by_name() {
    const ENOSYS: &str = "errno 38";
    let g = Guest::assert_build("arena_region_probe.rs");
    let output = g.assert_run_success(1, &["--", "growsdown"]);
    let answers = address_layout(&output.stdout);
    assert_eq!(
        answers.get("growsdown"),
        Some(&ENOSYS),
        "{}",
        text(&output.stdout)
    );
    assert!(
        !text(&output.stdout).contains("grew"),
        "{}",
        text(&output.stdout)
    );
    assert!(
        text(&output.stderr).contains("MAP_GROWSDOWN"),
        "{}",
        text(&output.stderr)
    );
}

// The runtime arena's region is the runtime's whatever the arena has mapped
// of it, and how much it has differs by mode: a recording has grown its trace
// there, a replay holds the trace it loaded. So every memory call about the
// region answers the same in every run of a seed, after a churn of recorded
// writes: a fixed mapping there is refused (`EEXIST` under
// `MAP_FIXED_NOREPLACE`), never made over runtime memory; a hint there is not
// honoured; and the runtime runs on.
#[cfg(target_os = "linux")]
#[test]
fn the_arena_region_answers_the_guest_alike_in_every_run_of_a_seed() {
    const EEXIST: &str = "errno 17";
    let g = Guest::assert_build("arena_region_probe.rs");
    let trace = g.dir.path().join("region.patina");
    let runs = [
        g.assert_run_success(1, &[]).stdout,
        g.assert_run_success(1, &["--record", trace.to_str().unwrap()])
            .stdout,
        assert_success(g.command("replay", &[trace.to_str().unwrap()])).stdout,
    ];
    let seeded = address_layout(&runs[0]);
    assert_eq!(seeded.get("after"), Some(&"ok"), "{}", text(&runs[0]));
    for run in &runs[1..] {
        assert_eq!(seeded, address_layout(run), "{}", text(run));
    }
    for (call, answer) in &seeded {
        match *call {
            "after" => {}
            "hint-start" => assert_eq!(*answer, "outside", "{call}"),
            "mremap-grow-maymove" => assert_eq!(*answer, "moved", "{call}"),
            _ if call.starts_with("noreplace-") => assert_eq!(*answer, EEXIST, "{call}"),
            _ => assert!(answer.starts_with("errno "), "{call}={answer}"),
        }
    }
}
