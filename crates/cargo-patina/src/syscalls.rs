//! `cargo patina syscalls`: the live syscall registry, printed.
//!
//! The registry (`patina_dst_native_shim::registry`) is code — the SUD
//! dispatcher is generated from it and the vendored-table gates hold it
//! complete — so humans and agents inspect the rows here rather than a doc
//! that could drift. The JSON form is schema `patina.syscalls/v1`.

use std::collections::BTreeMap;
use std::ffi::OsString;

use patina_dst_native_shim::registry::table::{linux_source, linux_table};
use patina_dst_native_shim::registry::{
    self, Arch, Disposition, Os, Serves, SymbolRow, SymbolStatus, SyscallRow,
};
use serde_json::{Value, json};

use crate::CliError;
use crate::cli;
use crate::help;
use crate::output;

pub(crate) const SYSCALLS_SCHEMA: &str = "patina.syscalls/v1";

pub(crate) struct SyscallsInvocation {
    os: Os,
    arch: Arch,
}

pub(crate) fn parse(arguments: Vec<OsString>) -> Result<SyscallsInvocation, CliError> {
    if arguments.iter().any(|argument| argument == "--") {
        return Err(CliError::usage(
            "syscalls takes no guest arguments or `--` separator",
        ));
    }
    let args = cli::parse("syscalls", help::Family::Sole, arguments)?;
    // The grammar already restricted both values to the registry's spellings.
    let os = args
        .text("--os")
        .map(|value| Os::parse(value).expect("registry grammar"))
        .unwrap_or(Os::host());
    let arch = args
        .text("--arch")
        .map(|value| Arch::parse(value).expect("registry grammar"))
        .unwrap_or(Arch::host());
    Ok(SyscallsInvocation { os, arch })
}

pub(crate) fn execute(invocation: SyscallsInvocation) -> Result<i32, CliError> {
    let SyscallsInvocation { os, arch } = invocation;
    if os == Os::Darwin {
        // Fail closed rather than print an empty table that reads as "Darwin
        // dispatches nothing": the xnu table is vendored so the keying is real,
        // but no row has been dispositioned against it yet.
        return Err(CliError(
            "the Darwin syscall table is vendored (crates/patina-native-shim/abi/darwin/\
             syscalls.master) but has no registry rows yet (docs/arcs/syscall-conformance.md \
             §8); pass --os linux"
                .to_string(),
        ));
    }
    let report = Report::linux(arch);
    if output::options().is_json() {
        println!(
            "{}",
            serde_json::to_string_pretty(&report.to_json())
                .map_err(|error| CliError(format!("serializing the syscall registry: {error}")))?
        );
    } else {
        print!("{}", report.render());
    }
    Ok(0)
}

/// One report: the rows for an (os, arch), the table they are gated against,
/// and the symbol layer for that OS.
struct Report {
    os: Os,
    arch: Arch,
    rows: Vec<(u32, &'static SyscallRow)>,
    table_path: &'static str,
    table_url: &'static str,
    table_abis: &'static [&'static str],
    table_numbers: usize,
    symbols: Vec<&'static SymbolRow>,
}

impl Report {
    fn linux(arch: Arch) -> Self {
        let source = linux_source(arch);
        let symbols = registry::SYMBOLS
            .iter()
            .filter(|symbol| symbol.platform.defines_on(Os::Linux))
            .collect();
        Report {
            os: Os::Linux,
            arch,
            rows: registry::rows_for(arch),
            table_path: source.path,
            table_url: source.url,
            table_abis: source.abis,
            table_numbers: linux_table(arch).len(),
            symbols,
        }
    }

    /// Disposition → row count, keyed by the rendered disposition (so the
    /// trap classes count separately).
    fn disposition_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for (_, row) in &self.rows {
            let key = match row.disposition {
                Disposition::Constant(_) => "constant".to_string(),
                Disposition::SoftDeny(_) => "soft-deny".to_string(),
                other => other.render(),
            };
            *counts.entry(key).or_insert(0) += 1;
        }
        counts
    }

    fn status_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for symbol in &self.symbols {
            let key = match symbol.status {
                SymbolStatus::Deny(_) => "deny".to_string(),
                other => other.render(),
            };
            *counts.entry(key).or_insert(0) += 1;
        }
        counts
    }

    /// The defined symbols that serve a row on this OS. The libc `syscall(2)`
    /// vehicle serves every row and is reported once, under `vehicles`; the
    /// `Absent` spellings are reported in their own section, never beside a
    /// real definition.
    fn symbols_for(&self, row: &SyscallRow) -> Vec<&'static SymbolRow> {
        self.symbols
            .iter()
            .copied()
            .filter(|symbol| symbol.status != SymbolStatus::Absent)
            .filter(|symbol| match symbol.serves {
                Serves::Syscalls(names) => names.contains(&row.name),
                Serves::Darwin(_) | Serves::Dispatcher | Serves::LibcOnly => false,
            })
            .collect()
    }

    fn to_json(&self) -> Value {
        let rows: Vec<Value> = self
            .rows
            .iter()
            .map(|(nr, row)| {
                json!({
                    "name": row.name,
                    "nr": nr,
                    "nrs": {
                        "x86_64": row.nr.x86_64,
                        "aarch64": row.nr.aarch64,
                    },
                    "family": row.family.name(),
                    "disposition": disposition_json(row.disposition),
                    "reasoning": row.reasoning,
                    "closes_in": row.closes_in,
                    "probe": row.probe,
                    "symbols": self
                        .symbols_for(row)
                        .iter()
                        .map(|symbol| json!({
                            "name": symbol.name,
                            "status": symbol.status.render(),
                        }))
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        let symbols: Vec<Value> = self
            .symbols
            .iter()
            .map(|symbol| {
                json!({
                    "name": symbol.name,
                    "platform": symbol.platform.name(),
                    "status": symbol.status.render(),
                    "serves": match symbol.serves {
                        Serves::Syscalls(names) | Serves::Darwin(names) => {
                            Value::Array(names.iter().map(|name| json!(name)).collect())
                        }
                        Serves::Dispatcher => json!("*"),
                        Serves::LibcOnly => Value::Null,
                    },
                })
            })
            .collect();
        json!({
            "schema": SYSCALLS_SCHEMA,
            "os": self.os.name(),
            "arch": self.arch.name(),
            "table": {
                "path": format!("crates/patina-native-shim/{}", self.table_path),
                "url": self.table_url,
                "abis": self.table_abis,
                "numbers": self.table_numbers,
            },
            "summary": {
                "rows": self.rows.len(),
                "dispositions": self.disposition_counts(),
                "symbols": self.status_counts(),
            },
            "vehicles": self
                .symbols
                .iter()
                .filter(|symbol| symbol.serves == Serves::Dispatcher)
                .map(|symbol| symbol.name)
                .collect::<Vec<_>>(),
            "rows": rows,
            "symbols": symbols,
        })
    }

    fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "syscall registry: {} {} — {} numbers in crates/patina-native-shim/{} (abi columns {})\n",
            self.os.name(),
            self.arch.name(),
            self.table_numbers,
            self.table_path,
            self.table_abis.join(",")
        ));
        out.push_str("dispositions:");
        for (disposition, count) in self.disposition_counts() {
            out.push_str(&format!(" {disposition} {count}"));
        }
        out.push('\n');
        out.push_str(&format!(
            "{:>4}  {:<24} {:<11} {:<19} {:<30} symbols\n",
            "nr", "name", "family", "disposition", "closes-in"
        ));
        for (nr, row) in &self.rows {
            let symbols: Vec<&str> = self
                .symbols_for(row)
                .iter()
                .map(|symbol| symbol.name)
                .collect();
            out.push_str(&format!(
                "{nr:>4}  {:<24} {:<11} {:<19} {:<30} {}\n",
                row.name,
                row.family.name(),
                row.disposition.render(),
                row.closes_in.unwrap_or("-"),
                if symbols.is_empty() {
                    "-".to_string()
                } else {
                    symbols.join(",")
                }
            ));
        }
        out.push_str(&format!(
            "symbols: {} rows on {} —",
            self.symbols.len(),
            self.os.name()
        ));
        for (status, count) in self.status_counts() {
            out.push_str(&format!(" {status} {count}"));
        }
        out.push('\n');
        let mut group = |title: &str, predicate: &dyn Fn(&SymbolRow) -> bool| {
            let names: Vec<&str> = self
                .symbols
                .iter()
                .filter(|symbol| predicate(symbol))
                .map(|symbol| symbol.name)
                .collect();
            if !names.is_empty() {
                out.push_str(&format!("{title} ({}): {}\n", names.len(), names.join(" ")));
            }
        };
        group(
            "absent — known ABI spellings the shim does not define (a guest importing one reaches the host or is audit-refused)",
            &|symbol| symbol.status == SymbolStatus::Absent,
        );
        group(
            "deny-trap — linking is inert, the first call aborts by name",
            &|symbol| matches!(symbol.status, SymbolStatus::Deny(_)),
        );
        group("libc-only — no kernel row", &|symbol| {
            symbol.serves == Serves::LibcOnly && symbol.status != SymbolStatus::Absent
        });
        group(
            "vehicles — serve every row through the dispatcher",
            &|symbol| symbol.serves == Serves::Dispatcher,
        );
        out
    }
}

fn disposition_json(disposition: Disposition) -> Value {
    match disposition {
        Disposition::Modeled | Disposition::Passthrough | Disposition::Absent => {
            json!({ "kind": disposition.kind() })
        }
        Disposition::Constant(value) => json!({ "kind": "constant", "value": value }),
        Disposition::SoftDeny(errno) => json!({
            "kind": "soft-deny",
            "errno": errno,
            "errno_name": registry::errno_name(errno),
        }),
        Disposition::Trap(class) => json!({ "kind": "trap", "class": class }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_report_carries_every_row_and_the_symbol_inventory() {
        let report = Report::linux(Arch::X86_64).to_json();
        assert_eq!(report["schema"], SYSCALLS_SCHEMA);
        assert_eq!(report["rows"].as_array().unwrap().len(), 386);
        assert_eq!(report["table"]["numbers"], 386);
        let read = &report["rows"][0];
        assert_eq!(read["name"], "read");
        assert_eq!(read["nrs"]["aarch64"], 63);
        assert_eq!(read["disposition"]["kind"], "modeled");
        assert!(
            read["symbols"]
                .as_array()
                .unwrap()
                .iter()
                .any(|symbol| symbol["name"] == "read")
        );
        let fork = report["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "fork")
            .unwrap();
        assert_eq!(
            fork["disposition"],
            json!({ "kind": "trap", "class": "process" })
        );
        let absent: Vec<&Value> = report["symbols"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|symbol| symbol["status"] == "absent")
            .collect();
        assert!(absent.iter().any(|symbol| symbol["name"] == "__read_chk"));
        assert_eq!(report["vehicles"], json!(["syscall"]));
        // The aarch64 view is the generic table's 328 numbers.
        assert_eq!(
            Report::linux(Arch::Aarch64).to_json()["rows"]
                .as_array()
                .unwrap()
                .len(),
            328
        );
    }

    #[test]
    fn human_report_lists_rows_and_absent_symbols() {
        let text = Report::linux(Arch::X86_64).render();
        assert!(text.contains("386 numbers"));
        assert!(text.contains("   0  read"));
        assert!(text.contains("trap(process)"));
        assert!(text.contains("absent — known ABI spellings"));
        assert!(text.contains("__open64_2"));
    }
}
