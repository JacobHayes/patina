use patina_dst_syscalls::cancellation::{GLIBC_CANCELLATION_POINTS, ONLY_WHERE_IT_WAITS};
use patina_dst_syscalls::{Platform, SymbolStatus, symbols::ALL_SYMBOLS_WITH_ARCH};
use serde_json::{Value, json};
use std::path::Path;

mod traps;

fn function(name: &str) -> Value {
    json!({"all": [{"kind": "function_definition"}, {"has": {
        "kind": "function_declarator", "has": {"field": "declarator", "regex": format!("^{name}$")},
        "stopBy": "end"
    }}]})
}

fn pattern(context: &str, selector: &str) -> Value {
    json!({"pattern": {"context": context, "selector": selector}})
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
    let metadata = json!({"id": id, "language": "C", "severity": "error", "message": message,
        "files": ["crates/patina-native-shim/**/*.c", "crates/patina-native-shim/**/*.h"],
        "ignores": ["**/target/**"], "rule": rule});
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
    for name in GLIBC_CANCELLATION_POINTS {
        let defined = ALL_SYMBOLS_WITH_ARCH.iter().any(|(row, _)| {
            row.name == *name
                && matches!(row.platform, Platform::Linux | Platform::Both)
                && row.status != SymbolStatus::Absent
        });
        if !defined || ONLY_WHERE_IT_WAITS.contains(name) {
            continue;
        }
        let context = cancellation_body(name);
        let valid = context
            .replace("$$$REST", "return 0;")
            .replace("$$$LOCK", "return 0;");
        emit_rule(
            &format!("shim-cancellation-{name}"),
            "Cancellation must run unconditionally at the wrapper's prescribed entry, before the operation.",
            json!({"all": [function(name), {"not": cancellation_contract(name, &context)}]}),
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
        "fcntl" => r#"int fcntl(void) { if (command == F_GETLK || command == F_SETLK || command == F_SETLKW
#ifdef F_OFD_SETLK
 || command == F_OFD_GETLK || command == F_OFD_SETLK || command == F_OFD_SETLKW
#endif
) { if (patina_fcntl_waits(command)) PATINA_CANCEL_POINT("fcntl"); $$$LOCK }
$$$REST }"#.into(),
        "fcntl64" => "int fcntl64(void) { if (patina_fcntl_waits(command)) PATINA_CANCEL_POINT(\"fcntl64\"); $$$REST }".into(),
        "pthread_testcancel" => "void pthread_testcancel(void) { if (patina_cancel_test()) patina_act_on_cancel(); }".into(),
        "clock_nanosleep" => "int clock_nanosleep(void) { if (clock_id == CLOCK_THREAD_CPUTIME_ID) return EINVAL; PATINA_CANCEL_ENTER(outer); int rc = (int)-patina_clock_nanosleep((int)clock_id, flags, request, remain); PATINA_CANCEL_LEAVE(outer); return rc; }".into(),
        "nanosleep" => "int nanosleep(void) {\n#ifdef __linux__\n PATINA_CANCEL_ENTER(outer); int rc = patina_nanosleep(duration, remaining); PATINA_CANCEL_LEAVE(outer); return rc;\n#else\n return patina_nanosleep(duration, remaining);\n#endif\n }".into(),
        "sleep" => "unsigned int sleep(void) { struct timespec duration = {(time_t)seconds, 0}; struct timespec remaining = {0, 0};\n#ifdef __linux__\n PATINA_CANCEL_ENTER(outer); int rc = patina_nanosleep(&duration, &remaining); PATINA_CANCEL_LEAVE(outer);\n#else\n int rc = patina_nanosleep(&duration, &remaining);\n#endif\n $$$REST }".into(),
        _ => format!("int {name}(void) {{ PATINA_CANCEL_POINT(\"{name}\"); $$$REST }}"),
    }
}

fn cancellation_contract(name: &str, context: &str) -> Value {
    if name != "fcntl" {
        return body(context);
    }
    let condition = r"^\(\s*command\s*==\s*F_GETLK\s*\|\|\s*command\s*==\s*F_SETLK\s*\|\|\s*command\s*==\s*F_SETLKW\s*#ifdef\s+F_OFD_SETLK\s*\|\|\s*command\s*==\s*F_OFD_GETLK\s*\|\|\s*command\s*==\s*F_OFD_SETLK\s*\|\|\s*command\s*==\s*F_OFD_SETLKW\s*#endif\s*\)$";
    json!({"has": {"field": "body", "has": {"all": [
        {"kind": "if_statement"},
        {"not": {"follows": {"not": {"any": [{"kind": "comment"}, {"regex": "^[{}]$"}]}, "stopBy": "end"}}},
        {"has": {"field": "condition", "regex": condition}},
        {"has": {"field": "consequence", "kind": "compound_statement", "has": {"all": [
            pattern("void lint(void) { if (patina_fcntl_waits(command)) PATINA_CANCEL_POINT(\"fcntl\"); }", "if_statement"),
            {"not": {"follows": {"not": {"any": [{"kind": "comment"}, {"regex": "^[{}]$"}]}, "stopBy": "end"}}}
        ]}}}
    ]}}})
}
