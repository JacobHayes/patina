//! Human help and usage rendering.

use super::*;

// ===========================================================================
// Human rendering
// ===========================================================================

/// Column at which flag docs begin (a flag whose left column overruns it wraps
/// its doc onto the next line).
const DOC_COLUMN: usize = 34;
/// Right margin for word-wrapped prose and docs.
const WRAP_WIDTH: usize = 92;

/// The rendered left column for a flag, e.g. `  -o, --output <PATH>`.
fn flag_left(flag: &Flag) -> String {
    let mut left = String::from("  ");
    match flag.short {
        Some(short) => left.push_str(&format!("{short}, {}", flag.name)),
        None => left.push_str(&format!("    {}", flag.name)),
    }
    match flag.value {
        Value::None => {}
        Value::Required(p, _) => left.push_str(&format!(" <{p}>")),
        Value::Optional(p, _) => left.push_str(&format!("[=<{p}>]")),
    }
    if flag.repeatable {
        left.push_str("...");
    }
    left
}

/// Greedy word-wrap of `text` to at most `width` columns per line.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        let candidate = if current.is_empty() {
            word.to_string()
        } else {
            format!("{current} {word}")
        };
        if candidate.chars().count() > width && !current.is_empty() {
            lines.push(current);
            current = word.to_string();
        } else {
            current = candidate;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn push_flag(out: &mut String, flag: &Flag) {
    let left = flag_left(flag);
    let doc_lines = wrap(flag.doc, WRAP_WIDTH.saturating_sub(DOC_COLUMN));
    // The left column and the first doc line share a row unless the left column
    // overruns the doc column, in which case the doc starts on the next line.
    if left.chars().count() + 2 > DOC_COLUMN {
        out.push_str(&left);
        out.push('\n');
        for line in &doc_lines {
            out.push_str(&" ".repeat(DOC_COLUMN));
            out.push_str(line);
            out.push('\n');
        }
    } else {
        out.push_str(&left);
        out.push_str(&" ".repeat(DOC_COLUMN - left.chars().count()));
        for (index, line) in doc_lines.iter().enumerate() {
            if index > 0 {
                out.push_str(&" ".repeat(DOC_COLUMN));
            }
            out.push_str(line);
            out.push('\n');
        }
        if doc_lines.is_empty() {
            out.push('\n');
        }
    }
}

fn push_prose(out: &mut String, prose: &str) {
    for paragraph in prose.split('\n') {
        if paragraph.trim().is_empty() {
            out.push('\n');
            continue;
        }
        for line in wrap(paragraph, WRAP_WIDTH) {
            out.push_str(&line);
            out.push('\n');
        }
    }
}

fn push_output_and_env_footer(out: &mut String) {
    out.push_str("\nOutput options (all verbs; stripped before routing, never reach the guest):\n");
    for flag in GLOBAL_OUTPUT {
        push_flag(out, flag);
    }
    out.push_str("\nRun `cargo patina --help` for the environment protocol and shared sections.\n");
}

/// Render the compact top-level overview.
fn render_overview() -> String {
    let mut out = String::new();
    out.push_str("Patina deterministic Cargo runner\n\n");
    out.push_str("Usage: cargo patina <VERB> [OPTIONS]\n\n");
    out.push_str("Verbs (run `cargo patina <verb> --help` for details):\n");
    let width = VERBS.iter().map(|v| v.name.len()).max().unwrap_or(0);
    for verb in VERBS {
        out.push_str(&format!(
            "  {:<width$}  {}\n",
            verb.name,
            verb.summary,
            width = width
        ));
    }
    out.push('\n');
    out.push_str("Global options:\n");
    for flag in HELP_FLAGS {
        push_flag(&mut out, flag);
    }
    for flag in GLOBAL_OUTPUT {
        push_flag(&mut out, flag);
    }

    out.push_str("\nFlag value syntax:\n");
    push_prose(
        &mut out,
        "A flag that takes a required value accepts both `--flag VALUE` and `--flag=VALUE` in \
every family. A flag with an OPTIONAL value (e.g. --buggify, --sched-pct, --starve, \
--liveness-watchdog, --converge-within) accepts only the bare `--flag` or `--flag=VALUE` — the \
space form is ambiguous with a positional. Everything after a `--` separator is passed to the \
guest/oracle untouched, so `--arg=--help` is how a WASI guest receives a literal `--help`.",
    );

    out.push_str("\nArtifact inference:\n");
    push_prose(
        &mut out,
        "`run`, `audit`, and `replay` are source-first with artifacts accepted uniformly. A \
built artifact is recognized by its leading magic bytes (\\0asm for a WASI module, Mach-O/ELF \
for a native binary) and used as-is; a <SOURCE.rs|DIR|Cargo.toml> is built on the fly through \
the same pipeline as `build` (honoring --target, default native). For `test`, no source \
positional stays the Cargo package family, while a <DIR|Cargo.toml> positional selects native \
libtest harness mode. A positional that names a file path (.wasm/.rs/Cargo.toml, or with a \
separator) but does not exist is a hard error.\n\
\n\
Options and the artifact may appear in any order, like `cargo build`/`cargo run` — \
`run --seed 5 app.wasm` and `run app.wasm --seed 5` are identical. Only known options are \
skipped when scanning for the artifact; an UNKNOWN option (a forwarded cargo flag) stops the \
scan, since its value could otherwise be misread as the artifact. Past that stop an unknown \
option is only forwarded silently in the Cargo package family — if a real artifact stands \
behind it the routing is a hard error, never a surprising Cargo fallthrough.",
    );

    out.push_str("\nENVIRONMENT:\n");
    push_prose(
        &mut out,
        "User-facing knobs, the internal supervisor/oracle protocol vars (set for you; listed \
for transparency), and honored tool vars. `--help --format json` emits the full registry.",
    );
    out.push('\n');
    for env in ENVIRONMENT {
        let tag = match env.scope {
            "protocol" => " [internal protocol]",
            "tool" => " [tool]",
            _ => "",
        };
        out.push_str(&format!("  {}{}\n", env.name, tag));
        for line in wrap(env.doc, WRAP_WIDTH - 6) {
            out.push_str("      ");
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// Render a single verb's focused section.
fn render_verb(verb: &Verb) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "cargo patina {} — {}\n\n",
        verb.name, verb.summary
    ));
    out.push_str("Usage:\n");
    for line in verb.synopsis {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    for group in verb.groups {
        out.push_str(group.title);
        out.push_str(":\n");
        for flag in group.flags {
            push_flag(&mut out, flag);
        }
        out.push('\n');
    }
    push_prose(&mut out, verb.prose);
    push_output_and_env_footer(&mut out);
    out
}

/// Render the requested help topic as human text (exit 0).
pub fn render(topic: Topic) -> String {
    match topic {
        Topic::Overview => render_overview(),
        Topic::Verb(name) => match verb(name) {
            Some(verb) => render_verb(verb),
            None => render_overview(),
        },
    }
}

// ===========================================================================
// Usage-error synopsis (message + synopsis lines + pointer)
// ===========================================================================

/// The synopsis block a usage error appends: the offending verb's synopsis
/// lines plus a `--help` pointer, or the compact top-level list before a verb is
/// resolved.
pub fn usage_synopsis(current_verb: Option<&str>) -> String {
    let mut out = String::new();
    match current_verb.and_then(verb) {
        Some(verb) => {
            out.push_str("Usage:\n");
            for line in verb.synopsis {
                out.push_str("  ");
                out.push_str(line);
                out.push('\n');
            }
            out.push_str(&format!(
                "\nrun `cargo patina {} --help` for details",
                verb.name
            ));
        }
        None => {
            out.push_str("Usage: cargo patina <VERB> [OPTIONS]\n");
            for verb in VERBS {
                out.push_str("  ");
                out.push_str(verb.synopsis[0]);
                out.push('\n');
            }
            out.push_str("\nrun `cargo patina <verb> --help` for details");
        }
    }
    out
}
