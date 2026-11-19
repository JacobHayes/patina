# The command transcripts in README.md, docs/GUIDE.md and examples/README.md print what the
# commands print now (tests/docs/transcripts.py: how a block is marked and compared). A wording
# check of our own docs against our own tool, by design.
#@ tier=quick,release budget=60 slots=8
: "${PATINA:?}" "${PATINA_GUESTS:?}"
python3 -I "$(dirname "$0")/transcripts.py"
