#!/bin/bash
# PostgreSQL 18: initdb, start, 4 concurrent psql sessions inserting, a query, pg_ctl stop (fast).
# programs: conda-postgresql
set -euo pipefail; shopt -s inherit_errexit
B=$PROGS/conda-postgresql/18.7/bin
$B/initdb -D $PWD/pgdata -U postgres -A trust >init.log 2>&1
$B/pg_ctl -D $PWD/pgdata -o "-p 41106 -k $PWD -c listen_addresses=127.0.0.1" -l $PWD/pg.log -w start >/dev/null
P="$B/psql -h 127.0.0.1 -p 41106 -U postgres -q -X"
$P -c 'create table k (id serial primary key, w int, v text)'
for w in 1 2 3 4; do ( for i in $(seq 1 25); do echo "insert into k (w,v) values ($w, 'w$w-$i');"; done | $P ) & done; wait
$P -At -c 'select count(*), count(distinct w) from k'
$B/pg_ctl -D $PWD/pgdata -m fast -w stop >/dev/null; echo stopped
