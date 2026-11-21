# The guide's pages (docs/guide), README.md, examples/README.md and ARCHITECTURE.md name only
# commands, options, fault keys, fault classes, outcomes and patina.toml keys this patina has,
# and no test input (PATINA_TEST_*); the guide mentions each command, fault class and outcome;
# the skill names nothing that can go stale (tests/docs/names.py). Their command blocks run in
# 01-transcripts. About a second.
#@ tier=quick,release budget=10 slots=1
: "${PATINA:?}"
python3 -I "$(dirname "$0")/names.py"
