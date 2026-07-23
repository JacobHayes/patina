# Agent Guidance

This repository contains **Patina**: an experimental deterministic execution and simulation-testing system for Rust.

The key documents are:

1. @INTENTS.md for project goals, non-goals, trade-offs, and design principles.
2. @ARCHITECTURE.md for the source of truth for crate boundaries, interfaces, target model, wrappers, traces, and runtime architecture.
3. @VALIDATION.md for capability acceptance gates and required evidence.
4. @IMPLEMENTATION.md for completed and planned implementation slices.
5. @README.md for the user-facing project summary and current status.

When changing intent, architecture, or user-visible behavior, update the relevant docs in the same change.

## Style

- Write project docs in clear, concise language.
- Avoid implementation-phase language in `INTENTS.md` and `ARCHITECTURE.md`; they should describe the system in present tense.
- `README.md` should remain honest about the project status.
