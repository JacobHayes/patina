//! `patina`: the command line, the launcher, the supervisor (hidden `__sup`) and the tools.

mod cli;
mod config;
mod doctor;
mod durability;
mod faults;
mod insn;
mod launch;
mod launcher;
mod log;
mod outcome;
mod replay;
mod result;
mod sup;
mod sys;
mod table;
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
    let hidden = match first.as_str() {
        "__sup" => Some(sup::main(rest)),
        "__insn-scan" => Some(insn::main(rest)),
        _ => None,
    };
    if let Some(r) = hidden {
        return r.unwrap_or_else(|e| {
            eprintln!("patina: {e}");
            ExitCode::from(2)
        });
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
    let r = match cmd {
        Cmd::Run => run(&a),
        Cmd::Verify => verify(&a),
        Cmd::Replay => replay(&a),
        Cmd::Log => log::main(&a).map_err(error),
        Cmd::Table => {
            table::print();
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Doctor => doctor::doctor(&a).map_err(error),
    };
    r.unwrap_or_else(|Fail(o, e)| {
        eprintln!("patina: {}: {e}", o.name());
        if a.json() {
            println!("{}", result::error_json(o, o.name(), &e));
        }
        ExitCode::from(o.exit())
    })
}

fn absolute(p: PathBuf) -> PathBuf {
    std::path::absolute(&p).unwrap_or(p)
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
    launch::pmu_event(&o).map_err(error)?;
    let out = out_dir(a, format!("patina-out/run-{}", cfg.seed))?;
    let cpu = cfg.host_cpu.unwrap_or_else(launch::default_cpu);
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
    launch::pmu_event(&o).map_err(error)?;
    let out = out_dir(a, format!("patina-out/verify-{}", cfg.seed))?;
    let runs = a.num::<usize>("--runs").map_err(error)?.unwrap_or(3);
    let mut vary = vec![];
    if let Some(v) = a.last("--vary") {
        for k in v.split(',').filter(|k| !k.is_empty()) {
            match k {
                "cpu" | "aslr" | "sandbox" | "load" | "repeat" | "parallel" | "env" | "time" => {
                    vary.push(k.to_string())
                }
                _ => return Err(error(format!("--vary: unknown variant {k}"))),
            }
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
        } else {
            println!("identical: the replay's log equals the run's");
        }
        result::print_human(&r.result, &r.dir);
    }
    Ok(ExitCode::from(c.outcome.exit()))
}
