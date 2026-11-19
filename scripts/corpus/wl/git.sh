#!/bin/bash
# git: init, 20 commits, a branch merge, clone over file://, gc, fsck.
set -euo pipefail; shopt -s inherit_errexit
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
export GIT_AUTHOR_DATE='2026-01-01T00:00:00Z' GIT_COMMITTER_DATE='2026-01-01T00:00:00Z'
git init -q -b main repo; cd repo
for i in $(seq 1 20); do seq 1 $((i*50)) > f$i.txt; git add f$i.txt; git commit -qm "c$i"; done
git checkout -qb side; echo side >> f1.txt; git commit -qam side
git checkout -q main; echo main >> f2.txt; git commit -qam main
git merge -q --no-edit side
cd ..; git clone -q file://$PWD/repo clone
cd clone; git log --oneline | wc -l; git gc -q; git fsck --full 2>&1 | tail -1; git count-objects -v | head -3
