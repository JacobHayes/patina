//! `patina guide [TOPIC]` and `patina skill [DIR]`. The guidance is docs/guide/*.md and the
//! skill is skills/patina/SKILL.md, both included at build time: what this binary prints always
//! describes this binary, offline, with no file looked up at run time.

use crate::cli::Args;
use std::path::Path;
use std::process::ExitCode;

pub struct Topic {
    pub name: &'static str,
    pub text: &'static str,
}

/// `patina guide` with no topic: what Patina is, the workflow, and the topics.
pub const CORE: &str = include_str!("../../../docs/guide/core.md");

macro_rules! topics {
    ($($name:literal),* $(,)?) => {
        &[$(Topic { name: $name, text: include_str!(concat!("../../../docs/guide/", $name, ".md")) }),*]
    };
}

/// The topics, in the order `--list` and the core page give them.
pub const TOPICS: &[Topic] = topics![
    "checks",
    "faults",
    "crashes",
    "scheduling",
    "machines",
    "sweeps",
    "failures",
    "profiling",
    "sdk",
    "limits",
    "config",
    "outcomes",
];

/// The skill for coding agents: a pointer to `patina guide`, which carries the guidance.
pub const SKILL: &str = include_str!("../../../skills/patina/SKILL.md");

/// A page's title: its first line, without the `# `.
fn title(text: &str) -> &str {
    text.lines().next().unwrap_or("").trim_start_matches("# ")
}

pub fn list() -> Result<ExitCode, String> {
    for t in TOPICS {
        println!("{:<11} {}", t.name, title(t.text));
    }
    Ok(ExitCode::SUCCESS)
}

pub fn main(a: &Args) -> Result<ExitCode, String> {
    let md = a.last("--format") == Some("md");
    let text = match a.positional.as_slice() {
        [] => CORE,
        [name] => match TOPICS.iter().find(|t| t.name == name) {
            Some(t) => t.text,
            None => {
                let names: Vec<&str> = TOPICS.iter().map(|t| t.name).collect();
                return Err(format!(
                    "no topic {name}: the topics are {}",
                    names.join(", ")
                ));
            }
        },
        _ => return Err("one topic at a time: patina guide TOPIC".into()),
    };
    print!("{}", if md { text.to_string() } else { plain(text) });
    Ok(ExitCode::SUCCESS)
}

/// Markdown as terminal text: comments, fence lines, heading marks, link targets, emphasis and
/// code marks go; code is indented; a table's columns are aligned.
pub fn plain(md: &str) -> String {
    let mut out: Vec<String> = vec![];
    let mut table: Vec<Vec<String>> = vec![];
    let mut fence = false;
    let mut comment = false;
    // A prose line whose code span goes on in the next line, waiting for the line that ends it.
    let mut open = String::new();
    for line in md.lines() {
        if !open.is_empty() && (line.trim().is_empty() || line.starts_with(['|', '<', '`'])) {
            out.push(inline(&std::mem::take(&mut open)));
        }
        if comment {
            comment = !line.contains("-->");
            continue;
        }
        if line.trim_end().starts_with("```") {
            fence = !fence;
            continue;
        }
        if fence {
            out.push(format!("    {line}").trim_end().to_string());
            continue;
        }
        if line.starts_with("<!--") {
            comment = !line.contains("-->");
            continue;
        }
        if line.starts_with('|') {
            let cells: Vec<String> = split_row(line).iter().map(|c| inline(c)).collect();
            if !cells
                .iter()
                .all(|c| !c.is_empty() && c.chars().all(|x| x == '-'))
            {
                table.push(cells);
            }
            continue;
        }
        flush(&mut table, &mut out);
        let line = line.trim_start_matches('#').trim_start_matches(' ');
        if !open.is_empty() {
            open.push('\n');
        }
        open.push_str(line);
        if open.matches('`').count().is_multiple_of(2) {
            out.push(inline(&std::mem::take(&mut open)));
        }
    }
    if !open.is_empty() {
        out.push(inline(&open));
    }
    flush(&mut table, &mut out);
    // A comment's place leaves no run of blank lines.
    let mut s = String::new();
    let mut blank = true;
    for l in out {
        if l.is_empty() && blank {
            continue;
        }
        blank = l.is_empty();
        s.push_str(&l);
        s.push('\n');
    }
    s
}

fn split_row(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|').trim_end_matches('|');
    let mut cells = vec![String::new()];
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'|') => {
                cells.last_mut().unwrap().push('|');
                chars.next();
            }
            '|' => cells.push(String::new()),
            c => cells.last_mut().unwrap().push(c),
        }
    }
    cells.iter().map(|c| c.trim().to_string()).collect()
}

fn flush(table: &mut Vec<Vec<String>>, out: &mut Vec<String>) {
    if table.is_empty() {
        return;
    }
    let n = table.iter().map(|r| r.len()).max().unwrap_or(0);
    let width: Vec<usize> = (0..n)
        .map(|i| {
            table
                .iter()
                .map(|r| r.get(i).map_or(0, |c| c.chars().count()))
                .max()
                .unwrap_or(0)
        })
        .collect();
    for r in table.drain(..) {
        let mut l = String::new();
        for (i, c) in r.iter().enumerate() {
            if i + 1 < r.len() {
                l.push_str(&format!("{c:<w$}  ", w = width[i]));
            } else {
                l.push_str(c);
            }
        }
        out.push(format!("  {}", l.trim_end()));
    }
}

/// One line of prose: `code` and **strong** lose their marks, a link keeps its text.
fn inline(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find(['`', '[', '*']) {
        out.push_str(&rest[..i]);
        let r = &rest[i..];
        if let Some(code) = r.strip_prefix('`') {
            match code.find('`') {
                Some(j) => {
                    out.push_str(&code[..j]);
                    rest = &code[j + 1..];
                }
                None => {
                    out.push_str(r);
                    rest = "";
                }
            }
        } else if let Some(strong) = r.strip_prefix("**") {
            rest = strong;
        } else if let Some(link) = r.strip_prefix('[') {
            // [text](target): the text alone.
            match (link.find("]("), link.find(')')) {
                (Some(j), Some(k)) if j < k && !link[..j].contains('`') => {
                    out.push_str(&inline(&link[..j]));
                    rest = &link[k + 1..];
                }
                _ => {
                    out.push('[');
                    rest = link;
                }
            }
        } else {
            out.push('*');
            rest = &r[1..];
        }
    }
    out.push_str(rest);
    out
}

/// `patina guide skill [DIR]`: write the skill to `DIR/patina/SKILL.md`, replacing an earlier patina
/// skill there; with no DIR, say where to put it.
pub fn skill(a: &Args) -> Result<ExitCode, String> {
    let dir = match a.positional.as_slice() {
        [] => {
            print!(
                "patina guide skill DIR writes the skill for coding agents to DIR/patina/SKILL.md.\n\
                 Give it the skills directory your agent reads, for example:\n\
                 \x20 patina guide skill ~/.agents/skills     for every project of this user\n\
                 \x20 patina guide skill .agents/skills       for this project only\n\
                 The skill tells an agent when to use Patina and to run `patina guide`, which\n\
                 is versioned with this binary: it rarely needs writing again.\n"
            );
            return Ok(ExitCode::SUCCESS);
        }
        [d] => Path::new(d).join("patina"),
        _ => return Err("one directory: patina guide skill DIR".into()),
    };
    if dir.exists() {
        // Only a patina skill is replaced: never another directory that happens to be there.
        let old = std::fs::read_to_string(dir.join("SKILL.md")).unwrap_or_default();
        if !old.lines().any(|l| l.trim() == "name: patina") {
            return Err(format!(
                "{} holds no patina skill (no SKILL.md with name: patina): not replacing it",
                dir.display()
            ));
        }
    }
    let parent = dir.parent().unwrap();
    std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    let tmp = parent.join(format!(".patina.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let write = || -> std::io::Result<()> {
        std::fs::create_dir(&tmp)?;
        std::fs::write(tmp.join("SKILL.md"), SKILL)?;
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        std::fs::rename(&tmp, &dir)
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(format!("{}: {e}", dir.display()));
    }
    println!("wrote {}", dir.join("SKILL.md").display());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outcome::Outcome;

    /// The core page names every topic as `patina guide TOPIC`, so a reader of it finds each.
    #[test]
    fn the_core_lists_every_topic() {
        for t in TOPICS {
            assert!(
                CORE.contains(&format!("patina guide {}", t.name)),
                "docs/guide/core.md does not list `patina guide {}`",
                t.name
            );
        }
    }

    /// A block of a page between `<!-- generated: NAME` and `<!-- end generated -->`, made
    /// from the code's own table: the page must hold what the code makes now.
    /// `GUIDE_BLESS=1 cargo test -p patina-cli guide` writes it.
    fn generated(file: &str, name: &str, text: &str, want: String) {
        let start = text
            .find(&format!("<!-- generated: {name}"))
            .unwrap_or_else(|| panic!("{file}: no generated block {name}"));
        let body = start + text[start..].find("-->").unwrap() + 4;
        let end = body + text[body..].find("<!-- end generated -->").unwrap();
        if text[body..end] == want {
            return;
        }
        if std::env::var_os("GUIDE_BLESS").is_some() {
            let path = format!("{}/../../{file}", env!("CARGO_MANIFEST_DIR"));
            std::fs::write(&path, format!("{}{want}{}", &text[..body], &text[end..])).unwrap();
            return;
        }
        panic!("{file}: the generated block {name} is stale; it should be:\n{want}\n(GUIDE_BLESS=1 cargo test -p patina-cli guide writes it)");
    }

    fn page(name: &str) -> &'static str {
        TOPICS.iter().find(|t| t.name == name).unwrap().text
    }

    #[test]
    fn generated_tables_are_the_codes() {
        let mut o = "| Outcome | Exit | Means |\n|---|---|---|\n".to_string();
        for x in Outcome::ALL {
            o.push_str(&format!(
                "| `{}` | {} | {} |\n",
                x.name(),
                x.exit(),
                x.means()
            ));
        }
        generated("docs/guide/outcomes.md", "outcomes", page("outcomes"), o);
        let mut c = String::new();
        let mut table = "";
        for k in crate::config::TOML_KEYS {
            if k.table != table {
                table = k.table;
                c.push_str(&format!(
                    "{}| `[{table}]` | Value | Default | Sets |\n|---|---|---|---|\n",
                    if c.is_empty() { "" } else { "\n" }
                ));
            }
            c.push_str(&format!(
                "| `{}` | `{}` | {} | {} |\n",
                k.key,
                k.value.replace('|', "\\|"),
                k.default,
                k.help
            ));
        }
        generated("docs/guide/config.md", "config", page("config"), c);
    }

    #[test]
    fn plain_text_drops_marks_and_aligns_tables() {
        let md = "# T\n\n<!-- transcript x\ndir: /tmp\n-->\n```sh\npatina run -- ./a\n```\n\nSee [the faults](faults.md), `--seed N` and **this**.\n\n| A | Bb |\n|---|---|\n| `x\\|y` | z |\n";
        assert_eq!(
            plain(md),
            "T\n\n    patina run -- ./a\n\nSee the faults, --seed N and this.\n\n  A    Bb\n  x|y  z\n"
        );
        // A code span may go on in the next line.
        assert_eq!(
            plain("run `patina\nguide` then\n`x`.\n"),
            "run patina\nguide then\nx.\n"
        );
    }

    #[test]
    fn every_page_renders_without_marks() {
        for (name, text) in
            std::iter::once(("core", CORE)).chain(TOPICS.iter().map(|t| (t.name, t.text)))
        {
            for l in plain(text).lines().filter(|l| !l.starts_with("    ")) {
                assert!(!l.contains('`') && !l.contains("**"), "{name}: {l}");
            }
        }
    }

    #[test]
    fn skill_replaces_only_a_patina_skill() {
        let root = std::env::temp_dir().join(format!("patina-skill-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let a = |d: &Path| Args {
            positional: vec![d.display().to_string()],
            ..Default::default()
        };
        skill(&a(&root)).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("patina/SKILL.md")).unwrap(),
            SKILL
        );
        // An older skill's other files go with it.
        std::fs::write(root.join("patina/old.md"), "x").unwrap();
        skill(&a(&root)).unwrap();
        assert!(!root.join("patina/old.md").exists());
        // Another directory named patina is left alone.
        std::fs::write(root.join("patina/SKILL.md"), "---\nname: other\n---\n").unwrap();
        assert!(skill(&a(&root)).is_err());
        assert!(root.join("patina/SKILL.md").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
