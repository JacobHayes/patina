use patina_dst_syscalls::cancellation::{GLIBC_CANCELLATION_POINTS, ONLY_WHERE_IT_WAITS};
use patina_dst_syscalls::{Platform, SymbolStatus, symbols::ALL_SYMBOLS_WITH_ARCH};
use serde_json::{Value, json};
use std::path::Path;

mod rust;
mod traps;

fn pattern(context: &str, selector: &str) -> Value {
    json!({"pattern": {"context": context, "selector": selector}})
}

fn function(name: &str) -> Value {
    json!({"all": [{"kind": "function_definition"}, {"has": {
        "kind": "function_declarator", "has": {"field": "declarator", "regex": format!("^{name}$")},
        "stopBy": "end"
    }}]})
}

fn body(context: &str) -> Value {
    json!({"has": {"field": "body", "pattern": {"context": context, "selector": "compound_statement"}}})
}

fn emit_rule(
    id: &str,
    message: &str,
    rule: Value,
    valid: Vec<String>,
    invalid: Vec<String>,
    fixtures: Option<&Path>,
) {
    emit_language_rule("C", id, message, rule, valid, invalid, fixtures);
}

fn emit_language_rule(
    language: &str,
    id: &str,
    message: &str,
    rule: Value,
    valid: Vec<String>,
    invalid: Vec<String>,
    fixtures: Option<&Path>,
) {
    let files = match language {
        "Rust" => vec!["crates/patina-native-shim/**/*.rs"],
        "C" => vec![
            "crates/patina-native-shim/**/*.c",
            "crates/patina-native-shim/**/*.h",
        ],
        _ => unreachable!("unsupported structural rule language"),
    };
    let metadata = json!({"id": id, "language": language, "severity": "error", "message": message,
        "files": files, "ignores": ["**/target/**"], "rule": rule});
    println!("---\n{}", serde_json::to_string_pretty(&metadata).unwrap());
    if let Some(directory) = fixtures {
        std::fs::create_dir_all(directory).unwrap();
        let fixture = json!({"id": id, "valid": valid, "invalid": invalid});
        std::fs::write(
            directory.join(format!("{id}.yml")),
            serde_json::to_vec_pretty(&fixture).unwrap(),
        )
        .unwrap();
    }
}

pub fn emit(fixtures: Option<&Path>) {
    traps::emit(fixtures);
    rust::helpers(fixtures);
    for name in GLIBC_CANCELLATION_POINTS {
        let defined = ALL_SYMBOLS_WITH_ARCH.iter().any(|(row, _)| {
            row.name == *name
                && matches!(row.platform, Platform::Linux | Platform::Both)
                && row.status != SymbolStatus::Absent
        });
        if !defined || ONLY_WHERE_IT_WAITS.contains(name) {
            continue;
        }
        if matches!(
            *name,
            "fcntl" | "fcntl64" | "open" | "openat" | "open64" | "openat64" | "__open" | "__open64"
        ) {
            rust::cancellation(name, fixtures);
            continue;
        }
        let context = cancellation_body(name);
        let valid = context
            .replace("$$$REST", "return 0;")
            .replace("$$$LOCK", "return 0;");
        emit_rule(
            &format!("shim-cancellation-{name}"),
            "Cancellation must run unconditionally at the wrapper's prescribed entry, before the operation.",
            json!({"all": [function(name), {"not": body(&context)}]}),
            vec![valid.clone()],
            vec![
                format!("int {name}(void) {{ if (0) PATINA_CANCEL_POINT(\"{name}\"); return 0; }}"),
                valid
                    .replace("PATINA_CANCEL_POINT(", "if (0) PATINA_CANCEL_POINT(")
                    .replace("PATINA_CANCEL_ENTER(", "if (0) PATINA_CANCEL_ENTER(")
                    .replace(
                        "if (patina_cancel_test())",
                        "if (0 && patina_cancel_test())",
                    ),
                valid
                    .replace("PATINA_CANCEL_POINT(", "return 0; PATINA_CANCEL_POINT(")
                    .replace("PATINA_CANCEL_ENTER(", "return 0; PATINA_CANCEL_ENTER(")
                    .replace(
                        "if (patina_cancel_test())",
                        "return; if (patina_cancel_test())",
                    ),
            ],
            fixtures,
        );
    }
}

// These are syntax contracts, not whole-body pins: the ordinary entry check
// dominates all later statements. The four acting/wait-only spellings retain
// their actual platform and argument-validation semantics.
fn cancellation_body(name: &str) -> String {
    match name {
        "pthread_testcancel" => "void pthread_testcancel(void) { if (patina_cancel_test()) patina_act_on_cancel(); }".into(),
        "clock_nanosleep" => "int clock_nanosleep(void) { if (clock_id == CLOCK_THREAD_CPUTIME_ID) return EINVAL; PATINA_CANCEL_ENTER(outer); int rc = (int)-patina_clock_nanosleep((int)clock_id, flags, request, remain); PATINA_CANCEL_LEAVE(outer); return rc; }".into(),
        "nanosleep" => "int nanosleep(void) {\n#ifdef __linux__\n PATINA_CANCEL_ENTER(outer); int rc = patina_nanosleep(duration, remaining); PATINA_CANCEL_LEAVE(outer); return rc;\n#else\n return patina_nanosleep(duration, remaining);\n#endif\n }".into(),
        "sleep" => "unsigned int sleep(void) { struct timespec duration = {(time_t)seconds, 0}; struct timespec remaining = {0, 0};\n#ifdef __linux__\n PATINA_CANCEL_ENTER(outer); int rc = patina_nanosleep(&duration, &remaining); PATINA_CANCEL_LEAVE(outer);\n#else\n int rc = patina_nanosleep(&duration, &remaining);\n#endif\n $$$REST }".into(),
        _ => format!("int {name}(void) {{ PATINA_CANCEL_POINT(\"{name}\"); $$$REST }}"),
    }
}
