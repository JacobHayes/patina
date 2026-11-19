#!/bin/bash
# SQLite shell: a 2000-row transaction and queries; then 4 concurrent writer processes in WAL mode.
set -euo pipefail; shopt -s inherit_errexit
db=$PWD/t.db
sqlite3 -init /dev/null "$db" <<SQL
PRAGMA journal_mode=WAL;
CREATE TABLE t(id INTEGER PRIMARY KEY, w INTEGER, v TEXT);
BEGIN;
WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<2000) INSERT INTO t(w,v) SELECT 0, hex(randomblob(16)) FROM c;
COMMIT;
CREATE INDEX tv ON t(v);
SQL
for w in 1 2 3 4; do
  ( for i in $(seq 1 25); do echo "PRAGMA busy_timeout=20000; INSERT INTO t(w,v) VALUES($w,'w$w-$i');"; done | sqlite3 -init /dev/null "$db" ) &
done
wait
n=$(sqlite3 -init /dev/null "$db" "SELECT count(*) FROM t WHERE w>0;")
echo "writers rows: $n"
[ "$n" = 100 ]
sqlite3 -init /dev/null "$db" "PRAGMA integrity_check; SELECT count(*) FROM t; VACUUM;"
