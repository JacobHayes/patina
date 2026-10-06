use super::{emit_rule, function, pattern};
use patina_dst_syscalls::{SymbolStatus, symbols::ALL_SYMBOLS_WITH_ARCH};
use serde_json::{Value, json};
use std::path::Path;

pub(super) fn emit(fixtures: Option<&Path>) {
    let mut registered_calls = Vec::new();
    for (row, _) in ALL_SYMBOLS_WITH_ARCH {
        if row.status != SymbolStatus::Deny("process") {
            continue;
        }
        let name = row.name;
        let statement = pattern(
            &format!("void lint(void) {{ patina_process_trap(\"{name}\"); }}"),
            "expression_statement",
        );
        let discarded = json!({"all": [pattern("void lint(void) { (void)$ARG; }", "expression_statement"),
            {"has": {"kind": "cast_expression", "has": {"field": "value", "kind": "identifier"}}}
        ]});
        let terminal = json!({"all": [statement,
            {"not": {"follows": {"not": {"any": [{"kind": "comment"}, {"regex": "^[{}]$"}, discarded]}, "stopBy": "end"}}},
            {"not": {"precedes": {"not": {"any": [{"kind": "comment"}, {"regex": "^[{}]$"}]}, "stopBy": "end"}}}
        ]});
        let protected = json!({"has": {"field": "body", "has": terminal}});
        emit_rule(
            &format!("shim-process-deny-{name}"),
            "A process deny wrapper may discard arguments and then must unconditionally reach its own terminal named trap.",
            json!({"all": [function(name), {"not": protected}]}),
            vec![format!(
                "int {name}(void) {{ (void)arg; patina_process_trap(\"{name}\"); }}"
            )],
            vec![
                format!("int {name}(void) {{ if (0) patina_process_trap(\"{name}\"); }}"),
                format!("int {name}(void) {{ return 0; patina_process_trap(\"{name}\"); }}"),
                format!(
                    "int {name}(void) {{ (void)operation(); patina_process_trap(\"{name}\"); }}"
                ),
                format!("int {name}(void) {{ patina_process_trap(\"{name}\"); return 0; }}"),
            ],
            fixtures,
        );
        let mut owner = function(name);
        owner
            .as_object_mut()
            .unwrap()
            .insert("stopBy".into(), json!("end"));
        registered_calls.push(json!({"inside": {"all": [
            pattern(&format!("void lint(void) {{ patina_process_trap(\"{name}\"); }}"), "call_expression"),
            {"inside": owner}
        ]}}));
    }
    // Match the identifier rather than only calls: aliases and indirect calls
    // must not create additional ways to reach a named trap.
    let declaration = json!({"inside": {"kind": "function_declarator", "field": "declarator"}});
    let mut permitted = vec![declaration.clone()];
    permitted.extend(registered_calls);
    emit_rule(
        "shim-process-trap-inventory",
        "Only each registered process-deny wrapper may reference its own trap label.",
        json!({"all": [{"kind": "identifier", "regex": "^patina_process_trap$"}, {"not": {"any": permitted}}]}),
        vec![
            "void fork(void) { patina_process_trap(\"fork\"); }".into(),
            "static void patina_process_trap(const char *symbol) {}".into(),
        ],
        vec![
            "void helper(void) { patina_process_trap(\"not_in_registry\"); }".into(),
            "void helper(void) { patina_process_trap(\"fork\"); }".into(),
            "void helper(void) { void *alias = patina_process_trap; }".into(),
        ],
        fixtures,
    );
    emit_rule("shim-native-trap-inventory", "Native deny traps may be called only by the two registry-generated wrapper macros.",
        json!({"all": [{"kind": "identifier", "regex": "^patina_native_trap$"}, {"not": declaration}]}),
        vec!["static void patina_native_trap(const char *klass, const char *symbol) {}".into()],
        vec!["void helper(void) { patina_native_trap(\"host-introspection\", \"not_in_registry\"); }".into(), "void helper(void) { void *alias = patina_native_trap; }".into()], fixtures);
    macro_rules(fixtures);
}

fn macro_rules(fixtures: Option<&Path>) {
    let mut sanctioned_bodies = Vec::<Value>::new();
    for name in ["PATINA_FRAMEWORK_TRAP", "PATINA_INTROSPECTION_TRAP"] {
        sanctioned_bodies.push(json!({"inside": {"pattern": format!("#undef {name}\n")}}));
    }
    for (macro_name, class) in [
        ("PATINA_FRAMEWORK_TRAP", "macos-framework"),
        ("PATINA_INTROSPECTION_TRAP", "host-introspection"),
    ] {
        let definition = format!(
            "#define {macro_name}(name) void name(void) {{ patina_native_trap(\"{class}\", #name); }}\n"
        );
        // The C grammar stores macro replacement lists as preproc_arg tokens.
        // Anchor their entire contents; a hidden conditional or extra statement
        // must not inherit the generated macro's inventory exemption.
        let exact = format!(
            r#"^\s*(?:\\\s*)?void\s+name\s*\(\s*void\s*\)\s*\{{\s*patina_native_trap\s*\(\s*"{class}"\s*,\s*#\s*name\s*\)\s*;\s*\}}\s*$"#
        );
        let correct = json!({"all": [{"kind": "preproc_arg", "regex": exact},
            {"inside": {"kind": "preproc_function_def", "has": {"field": "name", "regex": format!("^{macro_name}$")}}}
        ]});
        sanctioned_bodies.push(correct.clone());
        emit_rule(
            &format!("shim-trap-macro-{class}"),
            "The generated trap macro must expand to one unconditional correctly classified trap.",
            json!({"all": [{"kind": "preproc_function_def"}, {"has": {"field": "name", "regex": format!("^{macro_name}$")}}, {"not": {"all": [{"has": correct}, {"has": {"field": "parameters", "regex": "^\\(\\s*name\\s*\\)$"}}]}}]}),
            vec![definition.clone()],
            vec![
                definition.replace("patina_native_trap(", "if (0) patina_native_trap("),
                definition.replace(class, "wrong-class"),
                definition.replace("(name)", "(other)"),
                format!("#define {macro_name}(name) void name(void) {{}}\n"),
            ],
            fixtures,
        );
        let names = ALL_SYMBOLS_WITH_ARCH
            .iter()
            .filter_map(|(row, _)| (row.status == SymbolStatus::Deny(class)).then_some(row.name))
            .collect::<Vec<_>>()
            .join("|");
        emit_rule(
            &format!("shim-trap-macro-invocation-{class}"),
            "Trap macro invocations must name a symbol in their own registry deny class.",
            json!({"all": [{"kind": "identifier", "regex": format!("^{macro_name}$")},
                {"not": {"any": [
                    {"inside": {"kind": "preproc_function_def", "field": "name"}},
                    {"inside": {"kind": "call_expression", "field": "function", "has": {"field": "arguments", "pattern": {"context": format!("void lint(void) {{ {macro_name}($NAME); }}"), "selector": "argument_list"}, "has": {"kind": "identifier", "regex": format!("^({names})$")}}}},
                    {"inside": {"kind": "macro_type_specifier", "field": "name", "has": {"field": "type", "kind": "type_descriptor", "regex": format!("^({names})$")}}}
                ]}}
            ]}),
            vec![
                format!("{macro_name}({});", names.split('|').next().unwrap()),
                format!("{macro_name}({})\n", names.split('|').next().unwrap()),
            ],
            vec![
                format!("{macro_name}(not_in_registry);"),
                format!("{macro_name}(not_in_registry)\n"),
                format!("{macro_name}(fork);"),
                format!("void helper(void) {{ void *alias = {macro_name}; }}"),
            ],
            fixtures,
        );
    }
    emit_rule("shim-trap-preprocessor-inventory", "Macro bodies must not add, alias, or conditionally bypass trap calls outside the sanctioned generated definitions.",
        json!({"all": [{"kind": "preproc_arg", "regex": "\\b(?:patina_(?:process|native)_trap|PATINA_(?:FRAMEWORK|INTROSPECTION)_TRAP)\\b"}, {"not": {"any": sanctioned_bodies}}]}),
        vec!["#define PATINA_FRAMEWORK_TRAP(name) void name(void) { patina_native_trap(\"macos-framework\", #name); }\n".into()],
        vec!["#define EXTRA() patina_process_trap(\"fork\")\n".into(), "#define EXTRA() PATINA_FRAMEWORK_TRAP(not_in_registry)\n".into(), "#define EXTRA() patina_native_trap(\"host-introspection\", \"not_in_registry\")\n".into(), "#define PATINA_FRAMEWORK_TRAP(name) void name(void) { if (0) patina_native_trap(\"macos-framework\", #name); }\n".into()], fixtures);
}
