# The agent skill (skills/patina) names only commands, options, fault keys, presets, crash kinds
# and outcomes this patina has, and mentions each of its commands, presets and outcomes
# (tests/docs/skill.py). Its command blocks run in 01-transcripts. About a second.
#@ tier=quick,release budget=10 slots=1
: "${PATINA:?}"
python3 -I "$(dirname "$0")/skill.py"
