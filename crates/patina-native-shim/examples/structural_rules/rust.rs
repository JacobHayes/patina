use super::emit_language_rule;
use serde_json::json;
use std::path::Path;

pub(super) fn helpers(fixtures: Option<&Path>) {
    let entry = "if matches!(command, libc::F_SETLKW | libc::F_OFD_SETLKW) { cancel(name); }";
    let linux = "#[cfg(target_os = \"linux\")]";
    let valid = format!("fn cancel_fcntl(command: c_int, name: &CStr) {{ {linux} {entry} }}");
    let preceding = json!({"not": {"any": [
        {"kind": "line_comment"}, {"kind": "block_comment"}, {"regex": "^[{}]$"}
    ]}});
    let protected = json!({"has": {"field": "body", "has": {"all": [
        {"pattern": {"context": format!("fn lint() {{ {entry} }}"), "selector": "expression_statement"}},
        {"follows": {
            "all": [{"pattern": linux}, {"not": {"follows": {"all": [preceding.clone()], "stopBy": "end"}}}],
            "stopBy": preceding
        }}
    ]}}});
    // The helper preserves the C contract: only waiting lock commands reach
    // cancellation, and the Linux gate dominates all other helper operations.
    let rule = json!({"all": [
        {"kind": "function_item"},
        {"has": {"field": "name", "regex": "^cancel_fcntl$"}},
        {"not": protected}
    ]});
    emit_language_rule(
        "Rust",
        "shim-cancellation-fcntl-helper",
        "The fcntl cancellation helper must check both waiting lock commands at Linux entry.",
        rule,
        vec![
            valid.clone(),
            valid.replace(entry, &format!("// Entry comment.\n{entry}")),
        ],
        vec![
            valid.replace("cancel(name);", ""),
            valid.replace("cancel(name);", "if false { cancel(name); }"),
            valid.replace("libc::F_SETLKW | libc::F_OFD_SETLKW", "libc::F_SETLKW"),
            valid.replace(linux, "#[cfg(target_os = \"macos\")]"),
            valid.replace(linux, &format!("return; {linux}")),
            valid.replace(entry, &format!("return; {entry}")),
        ],
        fixtures,
    );
}

pub(super) fn cancellation(name: &str, fixtures: Option<&Path>) {
    let call = if matches!(name, "fcntl" | "fcntl64") {
        format!("super::cancel_fcntl(command, c\"{name}\");")
    } else {
        format!("super::cancel(c\"{name}\");")
    };
    let guard = "let _panic_scope = crate::panic_boundary::PanicScope::enter();";
    let context = format!("#[unsafe(no_mangle)] fn {name}() {{ {guard} {call} $$$REST }}");
    let valid = context.replace("$$$REST", "operation();");
    let comments = valid.replace(&call, &format!("// Entry documentation.\n{call}"));
    let definition = json!({"all": [
        {"kind": "function_item"},
        {"any": [
            {"all": [
                {"has": {"field": "name", "regex": format!("^{name}$")}},
                {"any": [
                    {"follows": {
                        "all": [{"kind": "attribute_item"}, {"has": {
                            "kind": "identifier", "regex": "^(r#)?no_mangle$", "stopBy": "end"
                        }}],
                        "stopBy": {"not": {"any": [
                            {"kind": "attribute_item"}, {"kind": "line_comment"}, {"kind": "block_comment"}
                        ]}}
                    }},
                    {"all": [
                        {"has": {"kind": "visibility_modifier"}},
                        {"has": {"kind": "function_modifiers", "has": {
                            "kind": "extern_modifier", "any": [
                                {"has": {"kind": "string_literal", "regex": "^\"C(-unwind)?\"$"}},
                                {"not": {"has": {"kind": "string_literal"}}}
                            ]
                        }}}
                    ]}
                ]}
            ]},
            {"follows": {
                "pattern": format!("#[unsafe(export_name = \"{name}\")]"),
                "stopBy": {"not": {"any": [
                    {"kind": "attribute_item"}, {"kind": "line_comment"}, {"kind": "block_comment"}
                ]}}
            }}
        ]}
    ]});
    let protected = json!({"has": {"field": "body", "has": {"all": [
        {"pattern": call},
        {"follows": {"pattern": guard, "stopBy": {"not": {"any": [
            {"kind": "line_comment"}, {"kind": "block_comment"}
        ]}}}}
    ]}}});
    emit_language_rule(
        "Rust",
        &format!("shim-cancellation-{name}"),
        "A Rust cancellation-point door must check cancellation immediately after entering its panic scope.",
        json!({"all": [definition, {"not": protected}]}),
        vec![
            valid.clone(),
            comments,
            format!("fn {name}() {{ operation(); }}"),
            format!("pub fn {name}() {{ operation(); }}"),
        ],
        vec![
            valid.replace(&call, ""),
            valid.replace(&call, &format!("if false {{ {call} }}")),
            valid.replace(&call, &format!("operation(); {call}")),
            valid.replace(&call, &format!("return; {call}")),
            valid.replace(&format!("c\"{name}\""), "c\"wrong\""),
            format!("#[unsafe(export_name = \"{name}\")] fn renamed() {{ {guard} operation(); }}"),
            format!("pub extern \"C\" fn {name}() {{ {guard} operation(); }}"),
        ],
        fixtures,
    );
}
