# The command transcripts in README.md, examples/README.md, ARCHITECTURE.md and the guide's
# pages (docs/guide, which `patina guide` prints) print what the commands print now
# (tests/docs/transcripts.py: how a block is marked and compared). A wording check of our own
# docs against our own tool, by design.
#@ tier=quick,release budget=60 slots=3
: "${PATINA:?}" "${PATINA_GUESTS:?}"
python3 -I "$(dirname "$0")/transcripts.py"
