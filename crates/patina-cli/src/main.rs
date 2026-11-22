//! `patina`: the command line, the launcher, the sandbox's keeper (hidden `__sandbox`), the
//! supervisor (hidden `__sup`) and the tools.

mod branch;
mod check;
mod cli;
mod config;
mod ctl;
mod debug;
mod doctor;
mod durability;
mod events;
mod explain;
mod faults;
mod guide;
mod host;
mod inputs;
mod insn;
mod launch;
mod launcher;
mod log;
mod minimize;
mod outcome;
mod ready;
mod recheck;
mod replay;
mod report;
mod result;
mod rewrite;
mod sandbox;
mod signature;
mod sup;
mod sweep;
mod sys;
mod verify;

use cli::{Args, Cmd};
use outcome::Outcome;
use std::path::PathBuf;
use std::process::ExitCode;

/// A request that ended without a run: the outcome (`error` or `internal`) and why.
struct Fail(Outcome, String);

fn error(e: String) -> Fail {
    Fail(Outcome::Error, e)
}

fn internal(e: String) -> Fail {
    Fail(Outcome::Internal, e)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(first) = args.first() else {
        eprint!("{}", cli::help_text(None));
        return ExitCode::from(2);
    };
    let rest = &args[1..];
    // A checker server lent by a sweep (a serving checker): kept from what this process starts.
    check::adopt_server();
    let hidden = match first.as_str() {
        "__sup" => Some(sup::main(rest)),
        "__sandbox" => Some(sandbox::keeper_main(rest)),
        "__native" => Some(launch::native_main(rest)),
        "__sandbox-views" => Some(sandbox::views_main()),
        "__insn-scan" => Some(insn::main(rest)),
        "__rewrite" => Some(rewrite::main(rest)),
        "__ready" => return ready::runner(rest),
        _ => None,
    };
    if let Some(r) = hidden {
        return r.unwrap_or_else(|e| {
            eprintln!("patina: {e}");
            ExitCode::from(2)
        });
    }
    if first == "--version" || first == "-V" {
        println!("patina {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if first == "--help" || first == "-h" {
        if rest
            .windows(2)
            .any(|w| w[0] == "--format" && w[1] == "json")
            || rest.iter().any(|a| a == "--format=json")
        {
            println!("{}", cli::help_json());
        } else {
            print!("{}", cli::help_text(None));
        }
        return ExitCode::SUCCESS;
    }
    // Its words are the control call's, not options (`partition --from A --to B`).
    if first == "ctl" && !rest.iter().any(|a| a == "--help" || a == "-h") {
        return ctl::main(rest);
    }
    let Some(cmd) = cli::find_cmd(first) else {
        eprintln!("patina: unknown command {first}\n");
        eprint!("{}", cli::help_text(None));
        return ExitCode::from(2);
    };
    let a = match cli::parse(cmd, rest) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("patina: {e}");
            return ExitCode::from(Outcome::Error.exit());
        }
    };
    if a.has("--help") {
        if a.json() {
            println!("{}", cli::help_json());
        } else {
            print!("{}", cli::help_text(Some(cmd)));
        }
        return ExitCode::SUCCESS;
    }
    // `--fault help`: the classes and every fault key, in place of a run.
    if a.all("--fault").iter().any(|v| v == "help") {
        print!("{}", faults::help_text());
        return ExitCode::SUCCESS;
    }
    let r = match cmd {
        Cmd::Run => run(&a),
        Cmd::Verify => verify(&a),
        Cmd::Replay => replay(&a),
        Cmd::Explain => explain::main(&a),
        Cmd::Debug => debug::main(&a),
        Cmd::Log => log::main(&a).map_err(error),
        Cmd::Doctor => doctor::doctor(&a).map_err(error),
        Cmd::Sweep => sweep::main(&a),
        Cmd::Report if a.has("--recheck") => recheck::main(&a),
        Cmd::Report if a.has("--check") || a.has("--jobs") => Err(error(
            "--check and -j judge runs again: give --recheck".into(),
        )),
        Cmd::Report => report::main(&a).map_err(error),
        Cmd::Minimize => minimize::main(&a),
        Cmd::Ctl => Ok(ctl::main(&a.positional)),
        Cmd::Wait => Ok(ready::wait(&a.positional)),
        Cmd::Guide => guide::main(&a).map_err(error),
        Cmd::Skill => guide::skill(&a).map_err(error),
    };
    r.unwrap_or_else(|Fail(o, e)| {
        // A full filesystem (ENOSPC, EDQUOT) is named, as the supervisor names it in a run.
        let full = ["(os error 28)", "(os error 122)"]
            .iter()
            .any(|c| e.contains(c));
        let stop = if full { "disk-full" } else { o.name() };
        if full {
            eprintln!("patina: {} ({stop}): {e}", o.name());
        } else {
            eprintln!("patina: {}: {e}", o.name());
        }
        if a.json() {
            println!("{}", result::error_json(o, stop, &e));
        }
        ExitCode::from(o.exit())
    })
}

/// `p` absolute, by name (`config::logical`).
fn absolute(p: PathBuf) -> PathBuf {
    config::logical(&p.to_string_lossy())
}

fn out_dir(a: &Args, default: String) -> Result<PathBuf, Fail> {
    let out = absolute(PathBuf::from(
        a.last("--out").map(|s| s.to_string()).unwrap_or(default),
    ));
    replay::clear_out(&out).map_err(error)?;
    Ok(out)
}

fn run(a: &Args) -> Result<ExitCode, Fail> {
    let cfg = config::resolve(a).map_err(error)?;
    let o = cfg.opts().map_err(error)?;
    launch::preflight(&o).map_err(error)?;
    let out = out_dir(a, format!("patina-out/run-{}", cfg.seed))?;
    let cpu = launch::default_cpu();
    let (_, r) = launch::run_one(&o, &out, cpu, false).map_err(internal)?;
    if a.json() {
        println!("{}", serde_json::to_string_pretty(&r).unwrap());
    } else {
        result::print_human(&r, &out);
    }
    Ok(ExitCode::from(r["exit"].as_u64().unwrap_or(2) as u8))
}

fn verify(a: &Args) -> Result<ExitCode, Fail> {
    let cfg = config::resolve(a).map_err(error)?;
    let o = cfg.opts().map_err(error)?;
    launch::preflight(&o).map_err(error)?;
    let out = out_dir(a, format!("patina-out/verify-{}", cfg.seed))?;
    let runs = a.num::<usize>("--runs").map_err(error)?.unwrap_or(3);
    let mut vary = vec![];
    let v = a.last("--vary").unwrap_or("cpu,load,aslr,sandbox,repeat");
    for k in v.split(',').filter(|k| !k.is_empty()) {
        match k {
            "cpu" | "aslr" | "sandbox" | "load" | "repeat" | "parallel" | "env" | "time" => {
                vary.push(k.to_string())
            }
            _ => return Err(error(format!("--vary: unknown variant {k}"))),
        }
    }
    let (c, code) = verify::verify(&o, &out, runs, &vary).map_err(internal)?;
    if a.json() {
        let v = serde_json::json!({
            "schema": result::RESULT_SCHEMA,
            "outcome": c.outcome.name(),
            "stop": c.stop,
            "message": c.message,
            "exit": c.outcome.exit(),
            "seed": cfg.seed,
            "runs": runs,
            "dir": out,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        println!("{} ({}): {}", c.outcome.name(), c.stop, c.message);
    }
    Ok(code)
}

fn replay(a: &Args) -> Result<ExitCode, Fail> {
    let r = replay::replay(a).map_err(error)?;
    let c = &r.classified;
    if a.json() {
        println!("{}", serde_json::to_string_pretty(&r.result).unwrap());
    } else {
        if c.outcome == Outcome::Nondeterministic {
            println!("nondeterministic: {}", c.message);
        } else if c.stop == "check-unstable" || c.stop == "inputs-changed" {
            println!("{}: {}", c.stop, c.message);
        } else {
            println!("identical: the replay's log equals the run's");
        }
        result::print_human(&r.result, &r.dir);
    }
    Ok(ExitCode::from(r.result["exit"].as_u64().unwrap_or(2) as u8))
}
