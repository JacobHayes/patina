# Arc designs

Decision docs for the approved build-out arcs (all designs approved 2026-07-30;
implementation waves start on explicit go). Ground rules that apply across every arc:

- **Phase-2 items belong to their arc.** Anything a doc labels "phase 2" is a scheduled
  later wave of that same arc (e.g. coverage-guided exploration is coverage-depth Wave E,
  harness fixtures are point-solution Wave D, static site enumeration is
  invariant-visibility Wave 5) — never an unowned someday-item.
- **Skills are a final pass.** The tool-agnostic skills (`docs/skills/`, from the
  point-solution arc's Wave C) are written last, after every other arc lands, so they
  teach the finished surface.
- Docs here describe flags and verbs that do not exist yet, so this directory stays
  outside `scripts/check-flag-drift.sh`'s gated doc list until the arcs land.

| Arc | One-liner |
|---|---|
| [unified-fault-knobs](unified-fault-knobs.md) | Rate-based seeded fault knobs for every interposed domain (fs first, then DNS/TCP-connect/clock/entropy/spawn), wrapper drivers + per-domain vacuity reports, PRF domain-separated RNG (fixes the entropy/net-fault stream aliasing). |
| [coverage-depth](coverage-depth.md) | Edge coverage in the sancov guard words (percent + density + plateau, offline symbolization), WASI fuel/hostcall depth, campaign accumulation; Wave E = coverage-guided generation scheduling. |
| [invariant-visibility](invariant-visibility.md) | `cargo patina sites`: hybrid runtime-registry + syn-SCA inventory of assertions/oracles with driven/observed/invisible semantics, crate→module→site rollup, `.patina/config.toml`; Wave 5 = static site enumeration. |
| [sometimes-gate](sometimes-gate.md) | Campaign-level `sometimes!` coverage: per-label tallies in `sites.json`, gate-by-default on never-satisfied oracles, `--allow-unmet-sometimes[=MIN_GENS]` waiver. |
| [campaign-steering](campaign-steering.md) | Resumable + extendable campaigns: out-dir-authoritative state, `--extend`/`--resume`, atomic per-generation checkpoints, k-then-extend ≡ fresh-n invariant. |
| [trace-inspection](trace-inspection.md) | `trace info/events/stats/diff` subcommands over a decode layer shared with the HTML renderer; jq-able JSONL event streams. |
| [point-solution-dst](point-solution-dst.md) | `#[patina_dst::test]` under plain `cargo test` via shim-linked re-exec, source-first polish; Wave C = the final skills pass, Wave D = embeddable harness fixtures. |
| [clap-config-eval](clap-config-eval.md) | clap adoption evaluation with a mechanical adopt/reject rule (small spike, ~1 agent-hour, launches on explicit go) + the flag > env > `.patina/` > default config layering design. |

Shared cross-arc contracts: the per-label SDK store is `<out>/sites.json`
(`patina.campaign.sites/v1`; sometimes-gate writes/gates it, `sites --exercised` reads it,
campaign resume folds it); edge coverage persists separately under `<out>/coverage/`
(`patina.coverage.campaign/v1`, with the `generations_applied` watermark campaign resume
requires).
