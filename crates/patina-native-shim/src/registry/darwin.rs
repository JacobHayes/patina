//! XNU ARM64 kernel-entry inventory, not a runtime dispatcher or an ABI promise.
//! Keep build-conditional alternatives: the reference source is not a running
//! macOS kernel configuration. MIG messages and commpage APIs are not entries.

use std::collections::BTreeSet;

pub const REVISION: &str = "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea";
pub const MACH_TABLE: &str = include_str!("../../abi/darwin/syscall_sw.c");
const ARM_TRAPS: &str = include_str!("../../abi/darwin/traps.h");
const ARM_REGISTERS: &str = include_str!("../../abi/darwin/proc_reg.h");
const ARM_DISPATCH: &str = include_str!("../../abi/darwin/sleh.c");
const ARM_PLATFORM: &str = include_str!("../../abi/darwin/machine_routines.c");

/// Local file and original path at [`REVISION`].
pub const SOURCES: &[(&str, &str)] = &[
    ("syscalls.master", "bsd/kern/syscalls.master"),
    ("syscall_sw.c", "osfmk/kern/syscall_sw.c"),
    ("traps.h", "osfmk/mach/arm/traps.h"),
    ("proc_reg.h", "osfmk/arm64/proc_reg.h"),
    ("sleh.c", "osfmk/arm64/sleh.c"),
    ("machine_routines.c", "osfmk/arm64/machine_routines.c"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Variant {
    pub entry: String,
    /// Source condition, not a statement about the host kernel's configuration.
    pub condition: Option<String>,
    /// Source declaration only; never an observed native errno.
    pub table_status: &'static str,
    pub declaration: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub namespace: &'static str,
    /// BSD number, negative Mach trap selector, or ARM special selector.
    pub nr: i64,
    /// ARM platform calls multiplex on register x3.
    pub subcode: Option<u32>,
    pub variants: Vec<Variant>,
}

fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !text.as_bytes()[0].is_ascii_digit()
}

/// The reference tables currently use one-level #if/#else blocks. Refuse new
/// syntax rather than silently dropping or guessing its architecture meaning.
#[derive(Default)]
struct Guard {
    condition: Option<String>,
    otherwise: bool,
}
impl Guard {
    fn directive(&mut self, line: &str) -> bool {
        if let Some(condition) = line.strip_prefix("#if ") {
            assert!(self.condition.is_none(), "nested condition: {line}");
            let condition = condition.split("/*").next().unwrap().trim();
            assert!(!condition.is_empty(), "empty condition");
            self.condition = Some(condition.to_string());
            self.otherwise = false;
        } else if line == "#else" || line.starts_with("#else ") {
            assert!(
                self.condition.is_some() && !self.otherwise,
                "unmatched else"
            );
            self.otherwise = true;
        } else if line == "#endif" || line.starts_with("#endif ") {
            assert!(self.condition.take().is_some(), "unmatched endif");
            self.otherwise = false;
        } else {
            return false;
        }
        true
    }
    fn text(&self) -> Option<String> {
        self.condition.as_ref().map(|c| {
            if self.otherwise {
                format!("!({c})")
            } else {
                c.clone()
            }
        })
    }
}

fn variant(entry: &str, declaration: &str, guard: &Guard) -> Variant {
    assert!(identifier(entry), "invalid entry name: {entry}");
    Variant {
        entry: entry.to_string(),
        condition: guard.text(),
        table_status: match entry {
            "nosys" => "nosys",
            "enosys" => "enosys",
            "kern_invalid" => "invalid",
            _ => "declared",
        },
        declaration: declaration.to_string(),
    }
}

fn add(rows: &mut Vec<Entry>, namespace: &'static str, slot: u32, variant: Variant) {
    let nr = if namespace == "mach" {
        -i64::from(slot)
    } else {
        i64::from(slot)
    };
    if let Some(row) = rows.iter_mut().find(|r| r.nr == nr) {
        assert_eq!(row.variants.len(), 1, "too many alternatives for {nr}");
        let first = row.variants[0]
            .condition
            .as_ref()
            .expect("duplicate unconditional number");
        assert_eq!(
            variant.condition.as_ref(),
            Some(&format!("!({first})")),
            "duplicate/non-complementary number {nr}"
        );
        row.variants.push(variant);
    } else {
        assert_eq!(
            slot as usize,
            rows.len(),
            "missing or out-of-order slot {slot}"
        );
        rows.push(Entry {
            namespace,
            nr,
            subcode: None,
            variants: vec![variant],
        });
    }
}

pub fn parse_bsd(text: &str) -> Vec<Entry> {
    let mut rows = Vec::new();
    let mut guard = Guard::default();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with(';') || line.starts_with("#include <") {
            continue;
        }
        if guard.directive(line) {
            continue;
        }
        let (head, rest) = line.split_once('{').expect("malformed BSD row");
        let fields: Vec<_> = head.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "bad BSD columns: {line}");
        let nr = fields[0].parse().expect("bad BSD number");
        assert!(fields[1].starts_with("AUE_"), "bad audit column");
        assert!(
            fields[2] == "ALL" || fields[2].chars().all(|c| "TNHP".contains(c)),
            "bad files column"
        );
        let (declaration, tail) = rest.split_once('}').expect("unclosed BSD prototype");
        // The pinned upstream has an extra closing brace on NECP slots 501/522.
        assert!(
            tail.trim().is_empty()
                || (tail.trim() == "}" && matches!(nr, 501 | 522))
                || (tail.trim().starts_with('{') && tail.trim().ends_with('}')),
            "bad BSD annotation: {line}"
        );
        let (prefix, args) = declaration.split_once('(').expect("missing BSD prototype");
        let (_, suffix) = args.split_once(')').expect("unclosed BSD arguments");
        assert!(
            matches!(
                suffix.split_whitespace().collect::<String>().as_str(),
                ";" | "NO_SYSCALL_STUB;"
            ),
            "unknown BSD attribute: {suffix}"
        );
        let entry = prefix.split_whitespace().last().expect("missing BSD entry");
        add(&mut rows, "bsd", nr, variant(entry, line, &guard));
    }
    assert!(guard.condition.is_none(), "unclosed BSD condition");
    assert!(!rows.is_empty(), "empty BSD table");
    assert!(
        rows.iter()
            .all(|r| r.variants[0].condition.is_none() || r.variants.len() == 2),
        "lost BSD conditional alternative"
    );
    rows
}

pub fn parse_mach(text: &str) -> Vec<Entry> {
    let body = section(
        text,
        "const mach_trap_t       mach_trap_table[MACH_TRAP_TABLE_COUNT] = {",
        "\n};",
    );
    let mut rows = Vec::new();
    let mut guard = Guard::default();
    for line in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if guard.directive(line) || line == "/* traps 100-107 reserved for IOKit */" {
            continue;
        }
        let (slot, rest) = line
            .strip_prefix("/* ")
            .expect("unknown Mach row")
            .split_once(" */ MACH_TRAP(")
            .expect("malformed Mach row");
        let slot = slot.parse().expect("bad Mach slot");
        let (args, tail) = rest.split_once("),").expect("malformed Mach declaration");
        assert!(
            tail.trim().is_empty()
                || (tail.trim().starts_with("/*") && tail.trim().ends_with("*/")),
            "bad Mach annotation"
        );
        let args: Vec<_> = args.split(',').map(str::trim).collect();
        assert!((4..=5).contains(&args.len()), "bad Mach argument count");
        assert!(
            args[1].parse::<u32>().is_ok() && args[2].parse::<u32>().is_ok() && identifier(args[3]),
            "bad Mach arguments"
        );
        assert!(
            args.len() == 4 || args[4] == ".mach_trap_returns_port = 1",
            "unknown Mach attribute"
        );
        add(&mut rows, "mach", slot, variant(args[0], line, &guard));
    }
    assert!(guard.condition.is_none(), "unclosed Mach condition");
    assert!(!rows.is_empty(), "empty Mach table");
    assert!(
        rows.iter()
            .all(|r| r.variants[0].condition.is_none() || r.variants.len() == 2),
        "lost Mach conditional alternative"
    );
    rows
}

fn section<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let (_, tail) = text.split_once(start).expect("missing source section");
    assert!(!tail.contains(start), "duplicate source section");
    tail.split_once(end).expect("unclosed source section").0
}

fn arm_entries() -> Vec<Entry> {
    let dispatch = section(
        ARM_DISPATCH,
        "handle_svc(arm_saved_state_t *state)\n{",
        "\n}\n",
    );
    let special_cases: Vec<_> = dispatch
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("case "))
        .collect();
    assert_eq!(
        special_cases,
        ["MACH_ARM_TRAP_ABSTIME:", "MACH_ARM_TRAP_CONTTIME:"],
        "unclassified ARM dispatch case"
    );
    assert!(
        dispatch.contains("trap_no == (int)PLATFORM_SYSCALL_TRAP_NO")
            && dispatch.contains("platform_syscall(state);")
            && dispatch.contains("if (trap_no < 0)"),
        "ARM selector routing changed"
    );
    let mut rows = Vec::new();
    for line in ARM_TRAPS
        .lines()
        .filter(|l| l.starts_with("#define MACH_ARM_TRAP_"))
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 3);
        let entry = match fields[1] {
            "MACH_ARM_TRAP_ABSTIME" => "handle_mach_absolute_time_trap",
            "MACH_ARM_TRAP_CONTTIME" => "handle_mach_continuous_time_trap",
            other => panic!("unclassified ARM special trap {other}"),
        };
        assert!(
            ARM_DISPATCH.contains(&format!("case {}:\n\t\t\t{entry}(state);", fields[1])),
            "ARM dispatch changed"
        );
        rows.push(Entry {
            namespace: "arm-special",
            nr: fields[2].parse().expect("bad ARM trap number"),
            subcode: None,
            variants: vec![variant(entry, line, &Guard::default())],
        });
    }
    assert_eq!(rows.len(), 2, "ARM time trap inventory changed");
    let platform = ARM_REGISTERS
        .lines()
        .find(|l| l.starts_with("#define PLATFORM_SYSCALL_TRAP_NO "))
        .expect("missing platform selector");
    let selector = u32::from_str_radix(
        platform
            .split_whitespace()
            .last()
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .expect("bad platform selector");
    // handle_svc interprets the low 32-bit selector as a signed int.
    let nr = i64::from(selector as i32);
    check_platform_source(ARM_PLATFORM);
    for (subcode, entry, status) in [
        (0, "icache_flush", "removed"),
        (1, "dcache_flush", "removed"),
        (2, "thread_set_cthread_self", "declared"),
        (3, "thread_get_cthread_self", "declared"),
    ] {
        let mut v = variant(
            entry,
            &format!("platform_syscall x3={subcode}"),
            &Guard::default(),
        );
        v.table_status = status;
        rows.push(Entry {
            namespace: "arm-platform",
            nr,
            subcode: Some(subcode),
            variants: vec![v],
        });
    }
    rows
}

fn check_platform_source(source: &str) {
    let body = section(
        source,
        "platform_syscall(arm_saved_state_t *state)\n{",
        "\n}\n",
    );
    assert!(
        body.contains("get_saved_state_reg(state, 3)"),
        "platform selector register changed"
    );
    let cases: Vec<_> = body
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("case "))
        .map(|l| l.split_once(':').unwrap().0.parse::<u32>().unwrap())
        .collect();
    assert_eq!(cases, [2, 3, 0, 1], "unclassified platform subcode");
    // Pinned switch grammar only: compare executable statements per branch,
    // including the removed 0/1 fallthrough to default (there is no panic).
    let switch = section(body, "switch (code) {", "\n\t}");
    let mut code = String::new();
    let mut rest = switch;
    while let Some((before, comment)) = rest.split_once("/*") {
        code.push_str(before);
        rest = comment
            .split_once("*/")
            .expect("unclosed platform comment")
            .1;
    }
    code.push_str(rest);
    let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let blocks: Vec<_> = compact.split("case").skip(1).collect();
    assert_eq!(
        blocks,
        [
            r#"2:platform_syscall_kprintf("setcthreadself.\n");thread_set_cthread_self(get_saved_state_reg(state,0));break;"#,
            r#"3:platform_syscall_kprintf("getcthreadself.\n");set_user_saved_state_reg(state,0,thread_get_cthread_self());break;"#,
            "0:",
            r#"1:default:platform_syscall_kprintf("unknown:%d\n",code);break;"#,
        ],
        "platform case handler/fallthrough changed"
    );
    assert!(
        body.contains("thread_exception_return();"),
        "platform return changed"
    );
}

pub fn inventory() -> Vec<Entry> {
    let mut rows = parse_bsd(super::table::DARWIN_TABLE);
    rows.extend(parse_mach(MACH_TABLE));
    rows.extend(arm_entries());
    let keys: BTreeSet<_> = rows
        .iter()
        .map(|r| (r.namespace, r.nr, r.subcode))
        .collect();
    assert_eq!(keys.len(), rows.len(), "duplicate Darwin identity");
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent test-only projection: scan source lines and guard ranges, not
    // Guard/variant/add or either production parser. No authoritative row list.
    fn check_source_projection(rows: &[Entry]) {
        for (namespace, source) in [
            ("bsd", super::super::table::DARWIN_TABLE),
            ("mach", MACH_TABLE),
        ] {
            let lines: Vec<_> = source.lines().map(str::trim).collect();
            let mut expected = Vec::new();
            for (index, line) in lines.iter().enumerate() {
                let (nr, name) = if namespace == "bsd" {
                    if !line.starts_with(|c: char| c.is_ascii_digit()) {
                        continue;
                    }
                    let nr = line
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .parse::<i64>()
                        .unwrap();
                    let prefix = line.split('(').next().unwrap();
                    (nr, prefix.split_whitespace().last().unwrap())
                } else {
                    if !line.starts_with("/* ") || !line.contains(" */ MACH_TRAP(") {
                        continue;
                    }
                    let nr = -line
                        .split_whitespace()
                        .nth(1)
                        .unwrap()
                        .parse::<i64>()
                        .unwrap();
                    let name = line
                        .split("MACH_TRAP(")
                        .nth(1)
                        .unwrap()
                        .split(',')
                        .next()
                        .unwrap()
                        .trim();
                    (nr, name)
                };
                let mut condition = None;
                // The nearest preceding if/endif determines whether this row
                // is guarded; an intervening else selects its complement.
                let mut otherwise = false;
                for preceding in lines[..index].iter().rev() {
                    if preceding.starts_with("#endif") {
                        break;
                    }
                    if preceding.starts_with("#else") {
                        otherwise = true;
                    }
                    if let Some(expr) = preceding.strip_prefix("#if ") {
                        let expr = expr.split("/*").next().unwrap().trim();
                        condition = Some(if otherwise {
                            format!("!({expr})")
                        } else {
                            expr.to_string()
                        });
                        break;
                    }
                }
                let status = match name {
                    "nosys" => "nosys",
                    "enosys" => "enosys",
                    "kern_invalid" => "invalid",
                    _ => "declared",
                };
                expected.push((nr, name.to_string(), condition, status));
            }
            assert!(!expected.is_empty());
            let mut actual: Vec<_> = rows
                .iter()
                .filter(|r| r.namespace == namespace)
                .flat_map(|r| {
                    r.variants
                        .iter()
                        .map(move |v| (r.nr, v.entry.clone(), v.condition.clone(), v.table_status))
                })
                .collect();
            actual.sort();
            expected.sort();
            assert_eq!(
                actual, expected,
                "independent {namespace} source projection"
            );
        }
    }

    #[test]
    fn every_bsd_mach_variant_matches_independent_source_projection() {
        check_source_projection(&inventory());
    }

    #[test]
    fn platform_source_detector_binds_each_case_and_removed_fallthrough() {
        check_platform_source(ARM_PLATFORM);
        for source in [
            ARM_PLATFORM
                .replace(
                    "thread_set_cthread_self(get_saved_state_reg(state, 0));",
                    "SWAP;",
                )
                .replace(
                    "set_user_saved_state_reg(state, 0, thread_get_cthread_self());",
                    "thread_set_cthread_self(get_saved_state_reg(state, 0));",
                )
                .replace(
                    "SWAP;",
                    "set_user_saved_state_reg(state, 0, thread_get_cthread_self());",
                ),
            ARM_PLATFORM.replace(
                "case 0: /* I-Cache flush (removed) */",
                "case 0: panic(\"removed\");",
            ),
            ARM_PLATFORM.replace("case 1: /* D-Cache flush (removed) */", "case 1: break;"),
        ] {
            assert!(
                std::panic::catch_unwind(|| check_platform_source(&source)).is_err(),
                "platform source mutation survived"
            );
        }
    }

    #[test]
    fn reference_inventory_covers_namespaces_and_guarded_holes() {
        let rows = inventory();
        assert_eq!(rows.len(), 558 + 128 + 6);
        assert_eq!(rows[27].variants.len(), 2);
        assert_eq!(rows[27].variants[1].table_status, "nosys");
        assert_eq!(rows[8].variants[0].table_status, "enosys");
        assert_eq!(rows[558 + 47].variants.len(), 2);
        assert!(
            rows.iter()
                .filter(|r| r.namespace == "arm-platform")
                .all(|r| r.nr == -2147483648)
        );
    }

    #[test]
    fn inventory_mutation_detector_rejects_lost_rows_variants_and_identity() {
        let baseline = inventory();
        for mutation in 0..5 {
            let mut rows = baseline.clone();
            match mutation {
                0 => {
                    rows.remove(5);
                }
                1 => {
                    rows[27].variants.pop();
                }
                2 => rows[558].namespace = "bsd",
                3 => rows[3].nr = 4,
                _ => rows[8].variants[0].table_status = "declared",
            }
            assert!(
                std::panic::catch_unwind(|| check_source_projection(&rows)).is_err(),
                "mutation {mutation} survived"
            );
        }
    }

    #[test]
    fn parsers_refuse_unknown_syntax_and_corrupt_tables() {
        let bsd = super::super::table::DARWIN_TABLE;
        for text in [
            bsd.replace("#if SOCKETS", "#ifdef SOCKETS"),
            bsd.replace("3\tAUE_NULL", "2\tAUE_NULL"),
            bsd.replace(
                "{ int fork(void) NO_SYSCALL_STUB; }",
                "{ int fork(void) UNKNOWN; }",
            ),
            bsd.replacen("#else", "#elif OTHER", 1),
            format!("{bsd}\nunknown"),
        ] {
            assert!(std::panic::catch_unwind(|| parse_bsd(&text)).is_err());
        }
        for text in [
            MACH_TABLE.replacen("/* 10 */", "/* 9 */", 1),
            MACH_TABLE.replacen("MACH_TRAP(_kernelrpc", "UNKNOWN(_kernelrpc", 1),
        ] {
            assert!(std::panic::catch_unwind(|| parse_mach(&text)).is_err());
        }
    }
}
