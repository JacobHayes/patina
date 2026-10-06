//! Regression tests for recognize.

use super::*;

#[test]
fn sdk_recognizer_table_matches_exported_runtime_site_macros() {
    let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../patina/src/lib.rs");
    let source = fs::read_to_string(&sdk).expect("read SDK source");
    let parsed = syn::parse_file(&source).expect("parse SDK source");
    let mut exported_runtime_macros = BTreeSet::new();
    for item in parsed.items {
        let syn::Item::Macro(mac) = item else {
            continue;
        };
        if !mac
            .attrs
            .iter()
            .any(|attr| attr.path().is_ident("macro_export"))
        {
            continue;
        }
        let Some(ident) = mac.ident else {
            continue;
        };
        let tokens = mac.mac.tokens.to_string();
        if site_runtime_shim_calls()
            .iter()
            .any(|needle| tokens.contains(needle))
        {
            exported_runtime_macros.insert(ident.to_string());
        }
    }
    let recognized = recognized_sdk_site_macros();
    let missing = exported_runtime_macros
        .iter()
        .filter(|name| !recognized.contains(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "SDK macros call runtime site shims but are absent from the sites recognizer table: {missing:?}"
    );
}

// Wave 5's link-time table only closes the never-reached blind spot for
// macros that actually emit a descriptor. A new SDK site macro (or a dropped
// literal-label arm) would silently reopen it, so every exported macro that
// registers a runtime site must also expand `__patina_static_site!`.
#[test]
fn every_exported_site_macro_emits_a_link_time_descriptor() {
    let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../patina/src/lib.rs");
    let source = fs::read_to_string(&sdk).expect("read SDK source");
    let parsed = syn::parse_file(&source).expect("parse SDK source");
    let mut missing = Vec::new();
    let mut checked = 0_usize;
    for item in parsed.items {
        let syn::Item::Macro(mac) = item else {
            continue;
        };
        if !mac
            .attrs
            .iter()
            .any(|attr| attr.path().is_ident("macro_export"))
        {
            continue;
        }
        let Some(ident) = mac.ident else {
            continue;
        };
        let tokens = mac.mac.tokens.to_string();
        if !site_runtime_shim_calls()
            .iter()
            .any(|needle| tokens.contains(needle))
        {
            continue;
        }
        checked += 1;
        if !tokens.contains("__patina_static_site") {
            missing.push(ident.to_string());
        }
    }
    assert_eq!(
        checked,
        recognized_sdk_site_macros().len(),
        "expected every recognized SDK site macro to be scanned"
    );
    assert!(
        missing.is_empty(),
        "SDK site macros register a runtime site but emit no link-time descriptor, \
             so a never-reached call stays invisible: {missing:?}"
    );
}

fn site_runtime_shim_calls() -> &'static [&'static str] {
    &[
        "__rt :: buggify",
        "__rt :: buggify_delay",
        "__rt :: buggify_knob",
        "__rt :: always",
        "__rt :: sometimes",
        "__rt :: reachable",
    ]
}
