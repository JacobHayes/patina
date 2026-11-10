//! Procedural macros for `patina-dst`.
//!
//! This crate intentionally has no third-party dependencies. The `#[patina_dst::test]`
//! surface is small enough to parse directly from `proc_macro` token trees, and
//! keeping it hand-rolled preserves the SDK's dependency-light default.

use proc_macro::{Delimiter, TokenStream, TokenTree};
use std::str::FromStr;

mod test_flags;
use test_flags::{Arity, TEST_FLAGS};

#[proc_macro_attribute]
pub fn test(attr: TokenStream, item: TokenStream) -> TokenStream {
    match expand_test(attr, item) {
        Ok(expanded) => expanded,
        Err(error) => compile_error(&error),
    }
}

fn expand_test(attr: TokenStream, item: TokenStream) -> Result<TokenStream, String> {
    let cli_args = cli_args(&parse_arguments(attr)?)?;
    let parsed = parse_test_fn(item)?;
    let cli_args = cli_args
        .iter()
        .map(|arg| rust_string_literal(arg))
        .collect::<Vec<_>>()
        .join(", ");

    let attrs = prefix_line(&parsed.attrs);
    let vis = prefix_inline(&parsed.vis);
    let wrapper = format!(
        "{attrs}#[test]\n{vis}fn {name}() {{\n    if ::patina_dst::is_simulated() {{\n        ::patina_dst::__rt::assert_test_return({helper}());\n    }} else {{\n        ::patina_dst::__rt::orchestrate(&::patina_dst::__rt::DstTest {{\n            manifest_dir: env!(\"CARGO_MANIFEST_DIR\"),\n            package: env!(\"CARGO_PKG_NAME\"),\n            crate_name: env!(\"CARGO_CRATE_NAME\"),\n            bin_name: option_env!(\"CARGO_BIN_NAME\"),\n            integration_test: option_env!(\"CARGO_TARGET_TMPDIR\").is_some(),\n            test_path: concat!(module_path!(), \"::\", stringify!({name})),\n            cli_args: &[{cli_args}],\n        }});\n    }}\n}}\nfn {helper}",
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

/// The attribute's arguments as written: each name, and its value if it has
/// one.
fn parse_arguments(attr: TokenStream) -> Result<Vec<(String, Option<String>)>, String> {
    let tokens = attr.into_iter().collect::<Vec<_>>();
    let mut arguments = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if is_comma(&tokens[index]) {
            index += 1;
            continue;
        }
        let name = match &tokens[index] {
            TokenTree::Ident(ident) => {
                let ident = ident.to_string();
                ident.strip_prefix("r#").unwrap_or(&ident).to_string()
            }
            other => {
                return Err(format!(
                    "expected an argument name in #[patina_dst::test(...)], got `{}`",
                    other
                ));
            }
        };
        index += 1;
        let mut value = None;
        if index < tokens.len() && is_equals(&tokens[index]) {
            index += 1;
            value = Some(match tokens.get(index) {
                Some(TokenTree::Literal(literal)) => literal_to_cli_value(&literal.to_string())?,
                Some(other) => {
                    return Err(format!(
                        "value for `{name}` must be a literal, got `{}`",
                        other
                    ));
                }
                None => return Err(format!("missing value for `{name}`")),
            });
            index += 1;
        }
        arguments.push((name, value));
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
    Ok(arguments)
}

/// The `patina test` words the arguments stand for. An argument that names no
/// flag of `patina test`, or has a value where the flag takes none (or none
/// where it takes one), is refused here, when the test is compiled, rather
/// than by the tool when the test runs.
fn cli_args(arguments: &[(String, Option<String>)]) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    for (name, value) in arguments {
        let Some((_, arity)) = TEST_FLAGS.iter().find(|(flag, _)| flag == name) else {
            let mut message = format!("unknown #[patina_dst::test] argument `{name}`");
            if let Some(near) = nearest_flag(name) {
                message.push_str(&format!("; did you mean `{near}`?"));
            }
            message.push_str(" (the arguments are the flags of `patina test`, with `_` for `-`)");
            return Err(message);
        };
        let flag = format!("--{}", name.replace('_', "-"));
        match (arity, value) {
            (Arity::Switch, None) | (Arity::OptionalValue, None) => args.push(flag),
            (Arity::Value, Some(value)) => {
                args.push(flag);
                args.push(value.clone());
            }
            // An optional value is one word with its flag: `--flag VALUE`
            // would read VALUE as a positional.
            (Arity::OptionalValue, Some(value)) => args.push(format!("{flag}={value}")),
            (Arity::Switch, Some(_)) => {
                return Err(format!("`{name}` takes no value; write `{name}` alone"));
            }
            (Arity::Value, None) => {
                return Err(format!("`{name}` needs a value; write `{name} = ...`"));
            }
        }
    }
    Ok(args)
}

/// The flag a misspelled argument most likely meant: the closest by edit
/// distance, when it is close.
fn nearest_flag(name: &str) -> Option<&'static str> {
    TEST_FLAGS
        .iter()
        .map(|(flag, _)| (edit_distance(name, flag), *flag))
        .min()
        .filter(|(distance, _)| *distance <= 2)
        .map(|(_, flag)| flag)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, x) in a.chars().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, y) in b.iter().enumerate() {
            let substituted = diagonal + usize::from(x != *y);
            diagonal = row[j + 1];
            row[j + 1] = substituted.min(diagonal + 1).min(row[j] + 1);
        }
    }
    row[b.len()]
}

fn is_comma(token: &TokenTree) -> bool {
    matches!(token, TokenTree::Punct(punct) if punct.as_char() == ',')
}

fn is_equals(token: &TokenTree) -> bool {
    matches!(token, TokenTree::Punct(punct) if punct.as_char() == '=')
}

fn literal_to_cli_value(text: &str) -> Result<String, String> {
    if text.starts_with('"') {
        return parse_string_literal(text);
    }
    if text.starts_with('r')
        && let Some(value) = parse_raw_string_literal(text)
    {
        return Ok(value);
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
    use super::{cli_args, literal_to_cli_value};

    fn words(arguments: &[(&str, Option<&str>)]) -> Result<Vec<String>, String> {
        let arguments: Vec<(String, Option<String>)> = arguments
            .iter()
            .map(|(name, value)| (name.to_string(), value.map(str::to_string)))
            .collect();
        cli_args(&arguments)
    }

    #[test]
    fn arguments_are_checked_against_the_flags_of_patina_test() {
        assert_eq!(
            words(&[("seeds", Some("3")), ("buggify", None), ("release", None)]).unwrap(),
            ["--seeds", "3", "--buggify", "--release"]
        );
        // A flag whose value is optional carries it in the same word.
        assert_eq!(
            words(&[("buggify", Some("500")), ("sched_pct", Some("3"))]).unwrap(),
            ["--buggify=500", "--sched-pct=3"]
        );
        // A misspelled name, a value on a switch, a value flag without one,
        // and the two flags the attribute supplies itself.
        for refused in [
            ("seedz", Some("2")),
            ("release", Some("1")),
            ("seeds", None),
            ("exact", Some("a::b")),
            ("package", Some("a")),
        ] {
            assert!(words(&[refused]).is_err(), "{refused:?} was accepted");
        }
    }

    #[test]
    fn literals_convert_to_cli_values_and_refuse_unsupported_escapes() {
        assert_eq!(literal_to_cli_value("200").unwrap(), "200");
        assert_eq!(literal_to_cli_value("1_000u64").unwrap(), "1000");
        assert_eq!(literal_to_cli_value("\"write:3\"").unwrap(), "write:3");
        assert_eq!(literal_to_cli_value("r#\"net:drop\"#").unwrap(), "net:drop");
        assert!(literal_to_cli_value("\"\\x41\"").is_err());
    }
}
