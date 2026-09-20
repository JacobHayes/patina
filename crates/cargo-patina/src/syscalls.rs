//! `cargo patina syscalls`: the live syscall registry, printed.
//!
//! The registry (`patina_dst_native_shim::registry`) is code — the SUD
//! dispatcher is generated from it and the vendored-table gates hold it
//! complete — so humans and agents inspect the rows here rather than a doc
//! that could drift. The JSON form is schema `patina.syscalls/v2`.

use std::collections::BTreeMap;
use std::ffi::OsString;

use patina_dst_native_shim::registry::{
    self, Arch, Disposition, Os, Serves, SymbolRow, SymbolStatus, VIRTUAL_ABI,
};
#[cfg(target_os = "linux")]
use registry::SyscallRow;
use serde_json::{Value, json};

use crate::CliError;
use crate::cli;
use crate::help;
use crate::output;

pub(crate) const SYSCALLS_SCHEMA: &str = "patina.syscalls/v2";

pub(crate) struct SyscallsInvocation;

pub(crate) fn parse(arguments: Vec<OsString>) -> Result<SyscallsInvocation, CliError> {
    if arguments.iter().any(|argument| argument == "--") {
        return Err(CliError::usage(
            "syscalls takes no guest arguments or `--` separator",
        ));
    }
    cli::parse("syscalls", help::Family::Sole, arguments)?;
    Ok(SyscallsInvocation)
}

pub(crate) fn execute(_: SyscallsInvocation) -> Result<i32, CliError> {
    #[cfg(target_os = "linux")]
    let (report, text) = {
        let report = Report::linux();
        (report.to_json(), report.render())
    };
    #[cfg(target_os = "macos")]
    let (report, text) = {
        let report = darwin_report();
        let text = render_darwin(&report);
        (report, text)
    };
    if output::options().is_json() {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| CliError(e.to_string()))?
        );
    } else {
        print!("{text}");
    }
    Ok(0)
}

/// One report: the rows for an (os, arch), the table they are gated against,
/// and the symbol layer for that OS.
#[cfg(target_os = "linux")]
struct Report {
    os: Os,
    arch: Arch,
    rows: Vec<(u32, &'static SyscallRow)>,
    table_abis: &'static [&'static str],
    table_numbers: usize,
    symbols: Vec<&'static SymbolRow>,
}

#[cfg(target_os = "linux")]
impl Report {
    fn linux() -> Self {
        let symbols = registry::SYMBOLS
            .iter()
            .filter(|symbol| symbol.platform.defines_on(Os::Linux))
            .collect();
        Report {
            os: Os::Linux,
            arch: Arch::host(),
            rows: registry::rows_for(),
            table_abis: if cfg!(target_arch = "x86_64") {
                &["common", "64"]
            } else {
                &["common", "64", "renameat", "rlimit", "memfd_secret"]
            },
            table_numbers: registry::ENTRIES.len(),
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
        let table = registry::ENTRIES;
        let rows: Vec<Value> = self
            .rows
            .iter()
            .map(|(nr, row)| {
                let source = table.iter().find(|entry| entry.nr == *nr).expect("registry/table gate");
                json!({
                    "name": row.name,
                    "nr": nr,
                    "namespace": "linux",
                    "subcode": null,
                    "variants": [{"entry": source.entry, "condition": null,
                        "table_status": if source.is_implemented() { "declared" } else { "unimplemented" }}],
                    "linux": {
                    "family": row.family.name(),
                    "disposition": disposition_json(row.disposition),
                    "reasoning": row.reasoning,
                    "closes_in": row.closes_in,
                    "probe": row.probe,
                    "since": row.since,
                    },
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
                    "probe": symbol.probe,
                    "serves": match symbol.serves {
                        Serves::Syscalls(ids) => json!(ids),
                        Serves::Darwin(names) => {
                            Value::Array(names.iter().map(|name| json!(name)).collect())
                        }
                        Serves::Dispatcher => json!("*"),
                        Serves::LibcOnly => Value::Null,
                    },
                })
            })
            .collect();
        let unprobed = registry::modeled_rows_without_probe();
        json!({
            "schema": SYSCALLS_SCHEMA,
            "os": self.os.name(),
            "arch": self.arch.name(),
            "metadata": {"linux": {"virtual_abi": VIRTUAL_ABI}},
            "scope": {"namespaces": ["linux"], "unit": "kernel-entry"},
            "sources": source_json("linux"),
            "summary": {
                "rows": self.rows.len(),
                "dispositions": self.disposition_counts(),
                "symbols": symbol_status_counts(&self.symbols),
                "modeled_without_probe": {
                    "count": unprobed.len(),
                    "names": unprobed,
                },
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
            "syscall registry: {} {} — {} numbers (abi columns {}); virtual ABI {VIRTUAL_ABI}\n",
            self.os.name(),
            self.arch.name(),
            self.table_numbers,
            self.table_abis.join(",")
        ));
        out.push_str("dispositions:");
        for (disposition, count) in self.disposition_counts() {
            out.push_str(&format!(" {disposition} {count}"));
        }
        out.push('\n');
        let unprobed = registry::modeled_rows_without_probe();
        out.push_str(&format!(
            "modeled rows without a probe: {}{}\n",
            unprobed.len(),
            if unprobed.is_empty() {
                String::new()
            } else {
                format!(" ({})", unprobed.join(" "))
            }
        ));
        out.push_str(&format!(
            "{:>4}  {:<24} {:<11} {:<19} {:<30} {:<24} symbols\n",
            "nr", "name", "family", "disposition", "closes-in", "probe"
        ));
        for (nr, row) in &self.rows {
            let symbols: Vec<&str> = self
                .symbols_for(row)
                .iter()
                .map(|symbol| symbol.name)
                .collect();
            out.push_str(&format!(
                "{nr:>4}  {:<24} {:<11} {:<19} {:<30} {:<24} {}\n",
                row.name,
                row.family.name(),
                row.disposition.render(),
                row.closes_in.unwrap_or("-"),
                row.probe.unwrap_or("-"),
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
        for (status, count) in symbol_status_counts(&self.symbols) {
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

#[cfg(target_os = "macos")]
fn source_revision(os: &str) -> &'static str {
    registry::generated::SOURCES
        .iter()
        .find(|s| s.0 == os)
        .unwrap()
        .2
}

fn source_json(os: &str) -> Value {
    json!(
        registry::generated::SOURCES
            .iter()
            .filter(|s| s.0 == os)
            .map(|s| json!({"path": s.3, "url": s.4, "version": s.1,
            "revision": s.2, "sha256": s.5}))
            .collect::<Vec<_>>()
    )
}

fn symbol_status_counts(symbols: &[&SymbolRow]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for symbol in symbols {
        let key = match symbol.status {
            SymbolStatus::Deny(_) => "deny".to_string(),
            other => other.render(),
        };
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

/// Darwin source declarations and interception facts intentionally do not use
/// Linux runtime dispositions. A symbol model is not a raw-entry model.
#[cfg(target_os = "macos")]
fn darwin_report() -> Value {
    let inventory = registry::ENTRIES;
    let symbols: Vec<_> = registry::SYMBOLS
        .iter()
        .filter(|s| s.platform.defines_on(Os::Darwin))
        .collect();
    let rows: Vec<_> = inventory
        .iter()
        .map(|row| {
            let bindings: Vec<_> = symbols
                .iter()
                .filter(|s| match s.serves {
                    Serves::Darwin(names) => row.variants.iter().any(|v| names.contains(&v.entry)),
                    _ => false,
                })
                .map(|s| json!({"name": s.name, "status": s.status.render()}))
                .collect();
            json!({
                "namespace": row.namespace, "nr": row.nr, "subcode": row.subcode,
                "name": row.variants[0].entry,
                "variants": row.variants.iter().map(|v| json!({
                    "entry": v.entry, "condition": v.condition,
                    "table_status": v.table_status, "declaration": v.declaration,
                })).collect::<Vec<_>>(),
                "darwin": {"raw_entry": "not-interposed",
                    "applicability": if row.namespace == "mach" && matches!(row.nr, 0 | -3 | -4) {
                        "shadowed-by-arm64-dispatch"
                    } else if row.namespace == "mach" && row.nr == -47 {
                        "__LP64__ || __arm64__"
                    } else { "source-conditional" }},
                "symbols": bindings,
            })
        })
        .collect();
    json!({
        "schema": SYSCALLS_SCHEMA, "os": "darwin", "arch": "aarch64",
        "metadata": {"darwin": {"reference_revision": source_revision("darwin")}},
        "scope": {"unit": "kernel-entry", "namespaces": ["bsd", "mach", "arm-special", "arm-platform"],
            "excludes": ["MIG message IDs", "commpage APIs", "unassigned selectors"],
            "note": "Reference-source inventory, not a host configuration or a whole-kernel model. Guards and invalid slots are retained; status is not an observed errno. Raw entries are not interposed; symbol statuses describe only their C surface."},
        "sources": source_json("darwin"),
        "summary": {"rows": rows.len(), "symbols": symbol_status_counts(&symbols)},
        "rows": rows,
        "symbols": symbols.iter().map(|s| json!({
            "name": s.name, "platform": s.platform.name(), "status": s.status.render(),
            "serves": match s.serves { Serves::Darwin(names) => json!(names), _ => Value::Null },
            "mapping": match s.serves { Serves::Darwin(_) => "explicit-darwin-entry", Serves::LibcOnly => "libc-only", _ => "not-mapped-on-darwin" },
        })).collect::<Vec<_>>(),
    })
}

#[cfg(target_os = "macos")]
fn render_darwin(report: &Value) -> String {
    let mut out = format!(
        "syscall inventory: darwin aarch64 — {} entries; XNU {}\n{}\n",
        report["summary"]["rows"],
        source_revision("darwin"),
        report["scope"]["note"].as_str().unwrap()
    );
    out.push_str("scope: BSD, Mach table, ARM special traps, ARM platform subcodes; excludes MIG message IDs, commpage APIs, unassigned selectors\n");
    for row in report["rows"].as_array().unwrap() {
        for v in row["variants"].as_array().unwrap() {
            out.push_str(&format!(
                "{} {} subcode={} {} [{}] guard={} raw=not-interposed symbols={}\n",
                row["namespace"].as_str().unwrap(),
                row["nr"],
                row["subcode"],
                v["entry"].as_str().unwrap(),
                v["table_status"].as_str().unwrap(),
                v["condition"],
                row["symbols"]
            ));
        }
    }
    out.push_str("symbol layer (status is not raw-entry coverage):\n");
    for s in report["symbols"].as_array().unwrap() {
        out.push_str(&format!(
            "{} {} {}\n",
            s["name"].as_str().unwrap(),
            s["status"].as_str().unwrap(),
            s["mapping"].as_str().unwrap()
        ));
    }
    out
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
    fn foreign_selectors_are_refused() {
        for args in [["--os", "linux"], ["--arch", "x86_64"]] {
            assert!(parse(args.into_iter().map(OsString::from).collect()).is_err());
        }
    }

    #[test]
    fn shared_report_contract_active_target() {
        #[cfg(target_os = "linux")]
        let report = Report::linux().to_json();
        #[cfg(target_os = "macos")]
        let report = darwin_report();
        let os = Os::host().name();
        let arch = Arch::host().name();
        {
            assert_eq!(report["schema"], SYSCALLS_SCHEMA);
            assert_eq!(report["os"], os);
            assert_eq!(report["arch"], arch);
            assert!(report["metadata"][os].is_object());
            assert_eq!(report["scope"]["unit"], "kernel-entry");
            let namespaces = report["scope"]["namespaces"].as_array().unwrap();
            assert!(namespaces.iter().all(Value::is_string));
            for source in report["sources"].as_array().unwrap() {
                assert!(source["path"].is_string() && source["url"].is_string());
            }
            let symbols = report["symbols"].as_array().unwrap();
            let mut expected = BTreeMap::<String, usize>::new();
            for symbol in symbols {
                assert!(symbol["name"].is_string() && symbol["platform"].is_string());
                let status = symbol["status"].as_str().unwrap();
                let key = if status.starts_with("deny(") {
                    "deny"
                } else {
                    status
                };
                *expected.entry(key.to_string()).or_default() += 1;
                assert!(
                    symbol["serves"].is_null()
                        || symbol["serves"].is_array()
                        || symbol["serves"] == "*"
                );
            }
            assert!(report["summary"]["symbols"].is_object());
            assert_eq!(report["summary"]["symbols"], json!(expected));
            let rows = report["rows"].as_array().unwrap();
            assert_eq!(
                report["summary"]["rows"].as_u64().unwrap() as usize,
                rows.len()
            );
            let mut identities = std::collections::BTreeSet::new();
            for row in rows {
                assert!(namespaces.contains(&row["namespace"]));
                let namespace = row["namespace"].as_str().unwrap();
                let nr = row["nr"].as_i64().unwrap();
                assert!(row["subcode"].is_null() || row["subcode"].is_u64());
                assert!(identities.insert((namespace, nr, row["subcode"].as_u64())));
                assert!(row["name"].is_string());
                let variants = row["variants"].as_array().unwrap();
                assert!(!variants.is_empty());
                for variant in variants {
                    assert!(variant["entry"].is_null() || variant["entry"].is_string());
                    assert!(variant["table_status"].is_string());
                    assert!(variant["condition"].is_null() || variant["condition"].is_string());
                }
                for symbol in row["symbols"].as_array().unwrap() {
                    assert!(symbol["name"].is_string() && symbol["status"].is_string());
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_report_preserves_namespaces_guards_and_interposition_boundary() {
        let report = darwin_report();
        assert_eq!(report["schema"], SYSCALLS_SCHEMA);
        assert!(report.get("virtual_abi").is_none());
        assert!(report["metadata"].get("linux").is_none());
        let rows = report["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 692);
        let bsd_read = rows
            .iter()
            .find(|r| r["namespace"] == "bsd" && r["nr"] == 3)
            .unwrap();
        assert_eq!(bsd_read["variants"][0]["entry"], "read");
        assert_eq!(bsd_read["darwin"]["raw_entry"], "not-interposed");
        assert!(bsd_read.get("linux").is_none());
        let guarded = rows
            .iter()
            .find(|r| r["namespace"] == "bsd" && r["nr"] == 27)
            .unwrap();
        assert_eq!(guarded["variants"].as_array().unwrap().len(), 2);
        for namespace in ["mach", "arm-special"] {
            assert!(
                rows.iter()
                    .any(|r| r["namespace"] == namespace && r["nr"] == -3)
            );
        }
        let timebase = rows
            .iter()
            .find(|r| r["namespace"] == "mach" && r["nr"] == -89)
            .unwrap();
        assert!(
            timebase["symbols"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["name"] == "mach_timebase_info")
        );
        assert!(render_darwin(&report).contains("not a host configuration"));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn json_report_carries_every_row_and_the_symbol_inventory() {
        let report = Report::linux().to_json();
        assert_eq!(report["schema"], SYSCALLS_SCHEMA);
        assert_eq!(report["rows"].as_array().unwrap().len(), 386);
        assert!(!report["sources"][0]["sha256"].as_str().unwrap().is_empty());
        let read = &report["rows"][0];
        assert_eq!(read["name"], "read");
        assert_eq!(read["namespace"], "linux");
        assert_eq!(read["variants"][0]["entry"], "sys_read");
        assert!(read.get("nrs").is_none());
        assert_eq!(read["linux"]["disposition"]["kind"], "modeled");
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
            fork["linux"]["disposition"],
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
        assert_eq!(report["metadata"]["linux"]["virtual_abi"], VIRTUAL_ABI);
        assert_eq!(read["linux"]["probe"], "fs/open_rw");
        assert_eq!(read["linux"]["since"], Value::Null);
        let fchroot = report["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "fchroot")
            .unwrap();
        assert_eq!(fchroot["linux"]["disposition"], json!({ "kind": "absent" }));
        assert_eq!(fchroot["linux"]["since"], "7.3");
        assert_eq!(fchroot["linux"]["probe"], "abi/newer-than-virtual");
        let unprobed = &report["summary"]["modeled_without_probe"];
        assert_eq!(
            unprobed["count"].as_u64().unwrap() as usize,
            unprobed["names"].as_array().unwrap().len()
        );
        assert!(
            unprobed["names"]
                .as_array()
                .unwrap()
                .iter()
                .any(|name| name == "readv"),
            "readv is modeled with no probe yet: {unprobed}"
        );
        assert!(
            !unprobed["names"]
                .as_array()
                .unwrap()
                .iter()
                .any(|name| name == "read")
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn human_report_lists_rows_and_absent_symbols() {
        let text = Report::linux().render();
        assert!(text.contains("386 numbers"));
        assert!(text.contains(&format!("virtual ABI {VIRTUAL_ABI}")));
        assert!(text.contains("modeled rows without a probe: "));
        assert!(
            text.contains(" readv "),
            "the unprobed names are listed: {text}"
        );
        assert!(text.contains("   0  read"));
        assert!(text.contains("fs/open_rw"));
        assert!(text.contains(" 472  fchroot                  privileged  absent"));
        assert!(text.contains("trap(process)"));
        assert!(text.contains("absent — known ABI spellings"));
        assert!(text.contains("__open64_2"));
    }
}
