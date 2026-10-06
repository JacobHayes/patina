//! Machine-readable help rendering.

use super::*;

// ===========================================================================
// JSON rendering (schema patina.help/v2, progressive disclosure)
// ===========================================================================
//
// The machine-readable help is served in two shapes under one schema tag:
//
//   * `cargo patina --help --format json` — the INDEX: the schema tag, the
//     global output flags, the `PATINA_*` environment protocol, and every verb
//     as `{summary, forms}` (NO flag_groups). A `verb_detail` hint field names
//     the command that yields a verb's full flag detail.
//   * `cargo patina <verb> --help --format json` — one VERB's detail: the schema
//     tag, the same global flags, and that verb's full entry (name, summary,
//     forms, flag_groups). No other verb and no environment block appear — the
//     env protocol is a single global contract that lives only in the index.
//
// This keeps the per-verb payload small (an agent fetches only the verb it is
// about to run) and the index a compact directory. Both are slices of the same
// underlying registry; there is no separate full-registry emission.
//
// Field-omission convention: a flag serializes only its non-default fields.
// `name`, `value_kind`, and `doc` are always present; `short`, `placeholder`,
// `value_grammar`, and `choices` are omitted when the flag has none, and
// `repeatable` is omitted unless true. Absent therefore means the default (no
// short form / no value / not repeatable), so a reader must treat a missing key
// as that default rather than expecting an explicit `null`/`false`.

/// The schema identifier stamped into both the index and per-verb JSON payloads.
/// Bumped from `patina.help/v1` when progressive disclosure changed the shape
/// (split index vs per-verb payloads; default-valued flag fields omitted).
pub const HELP_SCHEMA: &str = "patina.help/v2";

fn flag_json(flag: &Flag, group: &Group) -> serde_json::Value {
    use serde_json::{Map, Value as J};
    let mut m = Map::new();
    m.insert("name".into(), J::from(flag.name));
    if let Some(short) = flag.short {
        m.insert("short".into(), J::from(short));
    }
    m.insert("value_kind".into(), J::from(flag.value.kind()));
    if let Some(placeholder) = flag.value.placeholder() {
        m.insert("placeholder".into(), J::from(placeholder));
    }
    // The typed value grammar: the syntax a value must satisfy, plus the allowed
    // literals for an `enum` grammar. Omitted entirely for a valueless switch.
    // Lets an agent construct a well-formed value without guessing from the
    // placeholder.
    if let Some(kind) = flag.value.grammar() {
        m.insert("value_grammar".into(), J::from(kind.tag()));
        if let Kind::Enum(choices) = kind {
            m.insert("choices".into(), J::from(choices.to_vec()));
        }
    }
    m.insert("doc".into(), J::from(flag.doc));
    if flag.repeatable {
        m.insert("repeatable".into(), J::from(true));
    }
    // Present only when this flag reaches fewer families than its group, which
    // is how an agent learns that `--budget` is Cargo-family-only while the
    // `--seed` beside it is universal.
    if let Some(parent) = flag.requires {
        m.insert("requires".into(), J::from(parent));
    }
    if let Some(families) = flag.families {
        m.insert(
            "families".into(),
            J::from(families.iter().map(|f| f.tag()).collect::<Vec<_>>()),
        );
    }
    let _ = group;
    J::Object(m)
}

/// One titled flag group as `{title, families, flags}`. `families` names the
/// verb forms whose parser accepts the group — the same declaration that builds
/// those parsers, so an agent reading this payload learns exactly which flags a
/// given form will take.
fn group_json(group: &Group) -> serde_json::Value {
    use serde_json::{Map, Value as J};
    let mut gm = Map::new();
    gm.insert("title".into(), J::from(group.title));
    if group.families != SOLE {
        gm.insert(
            "families".into(),
            J::from(group.families.iter().map(|f| f.tag()).collect::<Vec<_>>()),
        );
    }
    gm.insert(
        "flags".into(),
        J::Array(
            group
                .flags
                .iter()
                .map(|flag| flag_json(flag, group))
                .collect(),
        ),
    );
    J::Object(gm)
}

/// The stand-in group for the always-available flags, which belong to no verb.
const GLOBAL_GROUP: Group = Group {
    title: "",
    families: SOLE,
    flags: &[],
};

/// The always-available output flags as `{title, flags}` (present in both the
/// index and every per-verb payload).
fn global_flags_json() -> serde_json::Value {
    use serde_json::{Map, Value as J};
    let mut global = Map::new();
    global.insert("title".into(), J::from("Output options (all verbs)"));
    global.insert(
        "flags".into(),
        J::Array(
            GLOBAL_OUTPUT
                .iter()
                .map(|flag| flag_json(flag, &GLOBAL_GROUP))
                .collect(),
        ),
    );
    J::Object(global)
}

/// The `PATINA_*` environment protocol as an array of `{name, scope, doc}` (index
/// only — the env contract is global, not per-verb).
fn environment_json() -> serde_json::Value {
    use serde_json::{Map, Value as J};
    let environment: Vec<J> = ENVIRONMENT
        .iter()
        .map(|e| {
            let mut em = Map::new();
            em.insert("name".into(), J::from(e.name));
            em.insert("scope".into(), J::from(e.scope));
            em.insert("doc".into(), J::from(e.doc));
            J::Object(em)
        })
        .collect();
    J::Array(environment)
}

/// The top-level index payload: schema, global flags, environment, every verb as
/// `{summary, forms}` (no flag_groups), and a `verb_detail` hint pointing at the
/// per-verb command.
fn index_json() -> serde_json::Value {
    use serde_json::{Map, Value as J};
    let mut verbs = Map::new();
    for verb in VERBS {
        let mut vm = Map::new();
        vm.insert("summary".into(), J::from(verb.summary));
        vm.insert("forms".into(), J::from(verb.synopsis.to_vec()));
        verbs.insert(verb.name.to_string(), J::Object(vm));
    }

    let mut verb_detail = Map::new();
    verb_detail.insert(
        "hint".into(),
        J::from(
            "Per-verb flag_groups are omitted from this index. Fetch a verb's full \
detail with the command below, substituting {verb} with the verb name.",
        ),
    );
    verb_detail.insert(
        "command_template".into(),
        J::from("cargo patina {verb} --help --format json"),
    );

    let mut root = Map::new();
    root.insert("schema".into(), J::from(HELP_SCHEMA));
    root.insert("global_flags".into(), global_flags_json());
    root.insert("environment".into(), environment_json());
    root.insert("verbs".into(), J::Object(verbs));
    root.insert("verb_detail".into(), J::Object(verb_detail));
    J::Object(root)
}

/// One verb's detail payload: schema, global flags, and the verb's full entry
/// (name, summary, forms, flag_groups). No other verb and no environment block.
fn verb_scoped_json(verb: &Verb) -> serde_json::Value {
    use serde_json::{Map, Value as J};
    let mut vm = Map::new();
    vm.insert("name".into(), J::from(verb.name));
    vm.insert("summary".into(), J::from(verb.summary));
    vm.insert("forms".into(), J::from(verb.synopsis.to_vec()));
    vm.insert(
        "flag_groups".into(),
        J::Array(verb.groups.iter().map(group_json).collect()),
    );

    let mut root = Map::new();
    root.insert("schema".into(), J::from(HELP_SCHEMA));
    root.insert("global_flags".into(), global_flags_json());
    root.insert("verb".into(), J::Object(vm));
    J::Object(root)
}

/// Render the requested help topic as pretty JSON (for `--help --format json`):
/// the compact index for the overview, or one verb's full detail for a verb
/// topic. An unresolved verb name falls back to the index, mirroring [`render`].
pub fn render_json(topic: Topic) -> String {
    let value = match topic {
        Topic::Overview => index_json(),
        Topic::Verb(name) => match verb(name) {
            Some(verb) => verb_scoped_json(verb),
            None => index_json(),
        },
    };
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())
}
