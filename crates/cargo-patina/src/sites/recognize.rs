//! Rust source and macro site recognition.

use super::*;
use patina_dst::SDK_SITE_MACROS;

const EXTERNAL_RECOGNIZER_NAMES: &[&str] = &[
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "unreachable",
    "proptest",
    "prop_assert",
    "prop_assert_eq",
    "prop_assert_ne",
    "quickcheck",
    "#[quickcheck]",
    "antithesis_sdk::*",
    "assert_always",
    "assert_always_or_unreachable",
    "assert_sometimes",
    "assert_reachable",
    "assert_unreachable",
];

pub(super) fn recognizer_count() -> usize {
    SDK_SITE_MACROS.len() + EXTERNAL_RECOGNIZER_NAMES.len()
}

pub(super) fn scan_file(file: &SourceFile, bytes: &[u8]) -> CachedFile {
    let text = String::from_utf8_lossy(bytes);
    match syn::parse_file(&text) {
        Ok(parsed) => {
            let mut scanner = FileScanner::new(file);
            scanner.visit_file(&parsed);
            CachedFile {
                sha256: hex_digest(bytes),
                sites: scanner.sites,
                error: None,
            }
        }
        Err(error) => CachedFile {
            sha256: hex_digest(bytes),
            sites: Vec::new(),
            error: Some(error.to_string()),
        },
    }
}

struct FileScanner<'a> {
    file: &'a SourceFile,
    module_stack: Vec<String>,
    test_depth: usize,
    imported_macros: BTreeMap<String, String>,
    sites: Vec<SiteRecord>,
}

impl<'a> FileScanner<'a> {
    fn new(file: &'a SourceFile) -> Self {
        Self {
            file,
            module_stack: Vec::new(),
            test_depth: 0,
            imported_macros: BTreeMap::new(),
            sites: Vec::new(),
        }
    }

    fn current_module(&self) -> String {
        let mut module = self.file.module.clone();
        for segment in &self.module_stack {
            module.push_str("::");
            module.push_str(segment);
        }
        module
    }

    fn current_context(&self) -> String {
        if self.test_depth > 0 {
            "test".to_string()
        } else {
            self.file.context.as_str().to_string()
        }
    }

    fn push_site(
        &mut self,
        kind: &str,
        runtime: &str,
        label: Option<String>,
        label_dynamic: bool,
        macro_path: String,
        span: Span,
    ) {
        let start = span.start();
        let line = start.line;
        let column = start.column + 1;
        let id = label
            .clone()
            .unwrap_or_else(|| SiteRecord::anonymous_id(&self.file.rel_path, line, column, kind));
        self.sites.push(SiteRecord {
            id,
            kind: kind.to_string(),
            runtime: runtime.to_string(),
            label,
            label_dynamic,
            file: self.file.rel_path.clone(),
            line,
            crate_name: self.file.crate_name.clone(),
            module: self.current_module(),
            context: self.current_context(),
            groups: Vec::new(),
            macro_path,
        });
    }
}

impl<'ast> Visit<'ast> for FileScanner<'_> {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        collect_use_aliases(&item.tree, Vec::new(), &mut self.imported_macros);
        visit::visit_item_use(self, item);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let was_test = has_cfg_test(&item.attrs);
        if was_test {
            self.test_depth += 1;
        }
        if item.content.is_some() {
            self.module_stack.push(item.ident.to_string());
            visit::visit_item_mod(self, item);
            self.module_stack.pop();
        }
        if was_test {
            self.test_depth -= 1;
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if has_quickcheck_attr(&item.attrs) {
            self.push_site(
                "quickcheck",
                "invisible",
                Some(item.sig.ident.to_string()),
                false,
                "#[quickcheck]".to_string(),
                item.sig.ident.span(),
            );
        }
        visit::visit_item_fn(self, item);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let macro_path = path_to_string(&mac.path);
        let final_segment = mac
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        let canonical = self
            .imported_macros
            .get(&final_segment)
            .cloned()
            .unwrap_or_else(|| final_segment.clone());
        if let Some(site) = classify_macro(&macro_path, &canonical, &mac.tokens) {
            match site {
                MacroSite::Single {
                    kind,
                    runtime,
                    label,
                    label_dynamic,
                } => self.push_site(
                    kind,
                    runtime,
                    label,
                    label_dynamic,
                    macro_path,
                    mac.path.span(),
                ),
                MacroSite::Proptest(functions) => {
                    if functions.is_empty() {
                        self.push_site(
                            "proptest",
                            "invisible",
                            None,
                            false,
                            macro_path,
                            mac.path.span(),
                        );
                    } else {
                        for (name, span) in functions {
                            self.push_site(
                                "proptest",
                                "invisible",
                                Some(name),
                                false,
                                macro_path.clone(),
                                span,
                            );
                        }
                    }
                }
            }
        }
        visit::visit_macro(self, mac);
    }
}

fn collect_use_aliases(
    tree: &syn::UseTree,
    prefix: Vec<String>,
    aliases: &mut BTreeMap<String, String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut prefix = prefix;
            prefix.push(path.ident.to_string());
            collect_use_aliases(&path.tree, prefix, aliases);
        }
        syn::UseTree::Name(name) => {
            if recognized_import_path(&prefix, &name.ident.to_string()) {
                let ident = name.ident.to_string();
                aliases.insert(ident.clone(), ident);
            }
        }
        syn::UseTree::Rename(rename) => {
            let original = rename.ident.to_string();
            if recognized_import_path(&prefix, &original) {
                aliases.insert(rename.rename.to_string(), original);
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_aliases(item, prefix.clone(), aliases);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

fn recognized_import_path(prefix: &[String], ident: &str) -> bool {
    SDK_SITE_MACROS.iter().any(|site| site.name == ident)
        || matches!(
            ident,
            "assert_always"
                | "assert_always_or_unreachable"
                | "assert_sometimes"
                | "assert_reachable"
                | "assert_unreachable"
        )
        || prefix.first().is_some_and(|head| head == "antithesis_sdk")
}

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr.meta.require_list().ok().is_some_and(|list| {
                list.tokens
                    .to_string()
                    .split_whitespace()
                    .any(|token| token == "test")
            })
    })
}

fn has_quickcheck_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "quickcheck")
    })
}

enum MacroSite {
    Single {
        kind: &'static str,
        runtime: &'static str,
        label: Option<String>,
        label_dynamic: bool,
    },
    Proptest(Vec<(String, Span)>),
}

fn classify_macro(macro_path: &str, canonical: &str, tokens: &TokenStream) -> Option<MacroSite> {
    let args = split_args(tokens);
    if let Some(site) = SDK_SITE_MACROS.iter().find(|site| site.name == canonical) {
        return sdk_label_site(site.kind, site.runtime, site.label_index, &args);
    }
    match canonical {
        "assert" | "assert_eq" | "assert_ne" => Some(MacroSite::Single {
            kind: "assert",
            runtime: "invisible",
            label: None,
            label_dynamic: false,
        }),
        "debug_assert" | "debug_assert_eq" | "debug_assert_ne" => Some(MacroSite::Single {
            kind: "debug_assert",
            runtime: "invisible",
            label: None,
            label_dynamic: false,
        }),
        "unreachable" => Some(MacroSite::Single {
            kind: "unreachable",
            runtime: "invisible",
            label: None,
            label_dynamic: false,
        }),
        "prop_assert" | "prop_assert_eq" | "prop_assert_ne" => Some(MacroSite::Single {
            kind: "prop_assert",
            runtime: "invisible",
            label: None,
            label_dynamic: false,
        }),
        "proptest" => Some(MacroSite::Proptest(proptest_functions(tokens))),
        "quickcheck" => Some(MacroSite::Single {
            kind: "quickcheck",
            runtime: "invisible",
            label: None,
            label_dynamic: false,
        }),
        "assert_always" | "assert_always_or_unreachable" => {
            antithesis_site("antithesis_always", &args)
        }
        "assert_sometimes" => antithesis_site("antithesis_sometimes", &args),
        "assert_reachable" => antithesis_site("antithesis_reachable", &args),
        "assert_unreachable" => antithesis_site("antithesis_unreachable", &args),
        _ if is_antithesis_path(macro_path) => antithesis_site("antithesis_reachable", &args),
        _ => None,
    }
}

fn sdk_label_site(
    kind: &'static str,
    runtime: &'static str,
    label_index: usize,
    args: &[TokenStream],
) -> Option<MacroSite> {
    let label = args.get(label_index).and_then(string_literal_arg);
    Some(MacroSite::Single {
        kind,
        runtime,
        label,
        label_dynamic: args
            .get(label_index)
            .is_some_and(|arg| string_literal_arg(arg).is_none()),
    })
}

fn antithesis_site(kind: &'static str, args: &[TokenStream]) -> Option<MacroSite> {
    Some(MacroSite::Single {
        kind,
        runtime: "invisible",
        label: args.iter().find_map(string_literal_arg),
        label_dynamic: false,
    })
}

fn is_antithesis_path(path: &str) -> bool {
    path == "antithesis_sdk" || path.starts_with("antithesis_sdk::")
}

fn split_args(tokens: &TokenStream) -> Vec<TokenStream> {
    let mut args = Vec::new();
    let mut current = TokenStream::new();
    for token in tokens.clone() {
        match &token {
            TokenTree::Punct(punct) if punct.as_char() == ',' => {
                args.push(current);
                current = TokenStream::new();
            }
            _ => current.extend([token]),
        }
    }
    if !current.is_empty() || tokens.is_empty() {
        args.push(current);
    }
    args
}

fn string_literal_arg(tokens: &TokenStream) -> Option<String> {
    let mut iter = tokens.clone().into_iter();
    let first = iter.next()?;
    if iter.next().is_some() {
        return None;
    }
    let TokenTree::Literal(literal) = first else {
        return None;
    };
    syn::parse_str::<syn::LitStr>(&literal.to_string())
        .ok()
        .map(|lit| lit.value())
}

fn proptest_functions(tokens: &TokenStream) -> Vec<(String, Span)> {
    let mut out = Vec::new();
    collect_proptest_functions(tokens.clone(), &mut out);
    out
}

fn collect_proptest_functions(tokens: TokenStream, out: &mut Vec<(String, Span)>) {
    let mut iter = tokens.into_iter().peekable();
    while let Some(token) = iter.next() {
        match token {
            TokenTree::Ident(ident) if ident == "fn" => {
                if let Some(TokenTree::Ident(name)) = iter.peek() {
                    out.push((name.to_string(), name.span()));
                }
            }
            TokenTree::Group(group) if group.delimiter() != Delimiter::None => {
                collect_proptest_functions(group.stream(), out);
            }
            _ => {}
        }
    }
}

fn path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

#[cfg(test)]
mod tests;
