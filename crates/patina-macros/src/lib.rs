//! Procedural macros for `patina-dst`.
//!
//! This crate intentionally has no third-party dependencies. The `#[patina_dst::test]`
//! surface is small enough to parse directly from `proc_macro` token trees, and
//! keeping it hand-rolled preserves the SDK's dependency-light default.

use proc_macro::{Delimiter, TokenStream, TokenTree};
use std::str::FromStr;

#[proc_macro_attribute]
pub fn test(attr: TokenStream, item: TokenStream) -> TokenStream {
    match expand_test(attr, item) {
        Ok(expanded) => expanded,
        Err(error) => compile_error(&error),
    }
}

fn expand_test(attr: TokenStream, item: TokenStream) -> Result<TokenStream, String> {
    let cli_args = parse_cli_args(attr)?;
    let parsed = parse_test_fn(item)?;
    let cli_args = cli_args
        .iter()
        .map(|arg| rust_string_literal(arg))
        .collect::<Vec<_>>()
        .join(", ");

    let attrs = prefix_line(&parsed.attrs);
    let vis = prefix_inline(&parsed.vis);
    let wrapper = format!(
        "{attrs}#[test]\n{vis}fn {name}() {{\n    if ::patina_dst::is_simulated() {{\n        ::patina_dst::__rt::assert_test_return({helper}());\n    }} else {{\n        ::patina_dst::__rt::orchestrate(&::patina_dst::__rt::DstTest {{\n            manifest_dir: env!(\"CARGO_MANIFEST_DIR\"),\n            harness_target: env!(\"CARGO_CRATE_NAME\"),\n            test_path: concat!(module_path!(), \"::\", stringify!({name})),\n            cli_args: &[{cli_args}],\n        }});\n    }}\n}}\nfn {helper}",
        name = parsed.name,
        helper = parsed.helper,
    );
    let mut expanded = TokenStream::from_str(&wrapper)
        .map_err(|error| format!("failed to build #[patina_dst::test] expansion: {error}"))?;
    expanded.extend(parsed.tail);
    Ok(expanded)
}

struct ParsedTestFn {
    attrs: String,
    vis: String,
    name: String,
    helper: String,
    tail: TokenStream,
}

fn parse_test_fn(item: TokenStream) -> Result<ParsedTestFn, String> {
    let tokens = item.into_iter().collect::<Vec<_>>();
    let fn_index = tokens
        .iter()
        .position(|token| matches!(token, TokenTree::Ident(ident) if ident.to_string() == "fn"))
        .ok_or_else(|| "#[patina_dst::test] can only be used on a free function".to_string())?;
    let name_index = fn_index + 1;
    let name = match tokens.get(name_index) {
        Some(TokenTree::Ident(ident)) => ident.to_string(),
        _ => return Err("#[patina_dst::test] expected a function name after `fn`".into()),
    };

    let prefix_tokens = &tokens[..fn_index];
    reject_unsupported_prefix(prefix_tokens)?;
    reject_generics(&tokens[name_index + 1..])?;
    reject_arguments(&tokens[name_index + 1..])?;

    let (attrs, vis) = split_attrs_and_visibility(prefix_tokens);
    let tail = tokens[name_index + 1..].iter().cloned().collect();
    let helper = helper_name(&name);
    Ok(ParsedTestFn {
        attrs,
        vis,
        name,
        helper,
        tail,
    })
}

fn reject_unsupported_prefix(tokens: &[TokenTree]) -> Result<(), String> {
    for token in tokens {
        if let TokenTree::Ident(ident) = token {
            let text = ident.to_string();
            if matches!(text.as_str(), "async" | "const" | "unsafe" | "extern") {
                return Err(format!(
                    "#[patina_dst::test] does not support `{text} fn`; use a plain zero-argument test function"
                ));
            }
        }
    }
    Ok(())
}

fn reject_generics(tokens_after_name: &[TokenTree]) -> Result<(), String> {
    for token in tokens_after_name {
        match token {
            TokenTree::Group(group) if group.delimiter() == Delimiter::Parenthesis => return Ok(()),
            TokenTree::Punct(punct) if punct.as_char() == '<' => {
                return Err("#[patina_dst::test] does not support generic test functions".into());
            }
            _ => {}
        }
    }
    Err("#[patina_dst::test] expected a parenthesized argument list".into())
}

fn reject_arguments(tokens_after_name: &[TokenTree]) -> Result<(), String> {
    let Some(TokenTree::Group(group)) = tokens_after_name
        .iter()
        .find(|token| matches!(token, TokenTree::Group(group) if group.delimiter() == Delimiter::Parenthesis))
    else {
        return Err("#[patina_dst::test] expected a parenthesized argument list".into());
    };
    if group.stream().is_empty() {
        Ok(())
    } else {
        Err("#[patina_dst::test] functions must take no arguments".into())
    }
}

fn parse_cli_args(attr: TokenStream) -> Result<Vec<String>, String> {
    let tokens = attr.into_iter().collect::<Vec<_>>();
    let mut args = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if is_comma(&tokens[index]) {
            index += 1;
            continue;
        }
        let name = match &tokens[index] {
            TokenTree::Ident(ident) => flag_name(&ident.to_string()),
            other => {
                return Err(format!(
                    "expected a flag name in #[patina_dst::test(...)], got `{}`",
                    other
                ));
            }
        };
        index += 1;
        if index < tokens.len() && is_equals(&tokens[index]) {
            index += 1;
            let Some(value) = tokens.get(index) else {
                return Err(format!("missing value for `{name}`"));
            };
            let value = match value {
                TokenTree::Literal(literal) => literal_to_cli_value(&literal.to_string())?,
                other => {
                    return Err(format!(
                        "value for `{name}` must be a literal, got `{}`",
                        other
                    ));
                }
            };
            args.push(name);
            args.push(value);
            index += 1;
        } else {
            args.push(name);
        }
        if index < tokens.len() {
            if is_comma(&tokens[index]) {
                index += 1;
            } else {
                return Err(format!(
                    "expected `,` between #[patina_dst::test] arguments, got `{}`",
                    tokens[index]
                ));
            }
        }
    }
    Ok(args)
}

fn is_comma(token: &TokenTree) -> bool {
    matches!(token, TokenTree::Punct(punct) if punct.as_char() == ',')
}

fn is_equals(token: &TokenTree) -> bool {
    matches!(token, TokenTree::Punct(punct) if punct.as_char() == '=')
}

fn flag_name(ident: &str) -> String {
    let ident = ident.strip_prefix("r#").unwrap_or(ident);
    format!("--{}", ident.replace('_', "-"))
}

fn literal_to_cli_value(text: &str) -> Result<String, String> {
    if text.starts_with('"') {
        return parse_string_literal(text);
    }
    if text.starts_with('r') {
        if let Some(value) = parse_raw_string_literal(text) {
            return Ok(value);
        }
    }
    if text
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        let mut value = String::new();
        let mut consumed = 0;
        for ch in text.chars() {
            if ch.is_ascii_digit() {
                value.push(ch);
                consumed += ch.len_utf8();
            } else if ch == '_' {
                consumed += ch.len_utf8();
            } else {
                break;
            }
        }
        if !value.is_empty() {
            let suffix = &text[consumed..];
            if suffix
                .chars()
                .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            {
                return Ok(value);
            }
        }
    }
    Err(format!(
        "unsupported literal `{text}` in #[patina_dst::test]; use a string literal for non-integer values"
    ))
}

fn parse_string_literal(text: &str) -> Result<String, String> {
    if !text.ends_with('"') || text.len() < 2 {
        return Err(format!("malformed string literal `{text}`"));
    }
    let mut out = String::new();
    let mut chars = text[1..text.len() - 1].chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let Some(escaped) = chars.next() else {
            return Err(format!("malformed escape in string literal `{text}`"));
        };
        match escaped {
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            other => {
                return Err(format!(
                    "unsupported escape `\\{other}` in #[patina_dst::test] string literal"
                ));
            }
        }
    }
    Ok(out)
}

fn parse_raw_string_literal(text: &str) -> Option<String> {
    let rest = text.strip_prefix('r')?;
    let hashes = rest.bytes().take_while(|byte| *byte == b'#').count();
    let rest = &rest[hashes..];
    let rest = rest.strip_prefix('"')?;
    let terminator = format!("\"{}", "#".repeat(hashes));
    let value = rest.strip_suffix(&terminator)?;
    Some(value.to_string())
}

fn helper_name(name: &str) -> String {
    let name = name.strip_prefix("r#").unwrap_or(name);
    let mut helper = String::from("__patina_dst_");
    for ch in name.chars() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            helper.push(ch);
        } else {
            helper.push('_');
        }
    }
    helper
}

fn split_attrs_and_visibility(tokens: &[TokenTree]) -> (String, String) {
    let mut index = 0;
    while index + 1 < tokens.len() {
        if matches!(&tokens[index], TokenTree::Punct(punct) if punct.as_char() == '#')
            && matches!(&tokens[index + 1], TokenTree::Group(group) if group.delimiter() == Delimiter::Bracket)
        {
            index += 2;
        } else {
            break;
        }
    }
    (
        tokens_to_string(&tokens[..index]),
        tokens_to_string(&tokens[index..]),
    )
}

fn prefix_line(prefix: &str) -> String {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}\n")
    }
}

fn prefix_inline(prefix: &str) -> String {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix} ")
    }
}

fn tokens_to_string(tokens: &[TokenTree]) -> String {
    tokens
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

fn rust_string_literal(value: &str) -> String {
    let mut literal = String::from('"');
    for ch in value.chars() {
        match ch {
            '\\' => literal.push_str("\\\\"),
            '"' => literal.push_str("\\\""),
            '\n' => literal.push_str("\\n"),
            '\r' => literal.push_str("\\r"),
            '\t' => literal.push_str("\\t"),
            '\0' => literal.push_str("\\0"),
            other => literal.push(other),
        }
    }
    literal.push('"');
    literal
}

fn compile_error(message: &str) -> TokenStream {
    TokenStream::from_str(&format!(
        "compile_error!({});",
        rust_string_literal(message)
    ))
    .expect("compile_error expansion is valid Rust")
}

#[cfg(test)]
mod tests {
    use super::{flag_name, literal_to_cli_value, rust_string_literal};

    #[test]
    fn flag_names_are_mechanical() {
        assert_eq!(flag_name("fs_crash_at"), "--fs-crash-at");
        assert_eq!(flag_name("yield_points"), "--yield-points");
    }

    #[test]
    fn literals_cover_integer_and_string_values() {
        assert_eq!(literal_to_cli_value("200").unwrap(), "200");
        assert_eq!(literal_to_cli_value("1_000u64").unwrap(), "1000");
        assert_eq!(literal_to_cli_value("\"write:3\"").unwrap(), "write:3");
        assert_eq!(literal_to_cli_value("r#\"net:drop\"#").unwrap(), "net:drop");
    }

    #[test]
    fn string_literals_fail_on_unsupported_escapes() {
        let error = literal_to_cli_value("\"\\x41\"").unwrap_err();
        assert!(error.contains("unsupported escape"));
    }

    #[test]
    fn rust_string_literals_escape_for_expansion() {
        assert_eq!(rust_string_literal("a\\b\n\"c\""), "\"a\\\\b\\n\\\"c\\\"\"");
    }
}
