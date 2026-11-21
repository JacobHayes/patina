#!/bin/bash
# MySQL 9.7: --initialize-insecure, start, 4 concurrent client sessions inserting into InnoDB, queries, shutdown.
# programs: conda-mysql-server conda-mysql-client
# run: disk-mb = 1024
set -euo pipefail; shopt -s inherit_errexit
B=$PROGS/conda-mysql-server/9.7.4
$B/bin/mysqld --no-defaults --initialize-insecure --datadir=$PWD/data --basedir=$B >init.log 2>&1
$B/bin/mysqld --no-defaults --datadir=$PWD/data --basedir=$B --socket=$PWD/my.sock --port=41105 --bind-address=127.0.0.1 --mysqlx=OFF --innodb-buffer-pool-size=64M --log-error=$PWD/err.log --pid-file=$PWD/my.pid & pid=$!
M="$PROGS/conda-mysql-client/9.7.4/bin/mysql --no-defaults -uroot --socket=$PWD/my.sock"
for i in $(seq 1 600); do $M -e 'select 1' >/dev/null 2>&1 && break; sleep 0.1; done
$M -e 'create database t; create table t.k (id int primary key auto_increment, w int, v varchar(40)) engine=innodb'
for w in 1 2 3 4; do ( for i in $(seq 1 25); do echo "insert into t.k (w,v) values ($w, 'w$w-$i');"; done | $M ) & done; for j in $(jobs -p); do [ "$j" = "$pid" ] || wait "$j"; done
$M -N -e 'select count(*), count(distinct w) from t.k; check table t.k' | head -3
$PROGS/conda-mysql-client/9.7.4/bin/mysqladmin --no-defaults -uroot --socket=$PWD/my.sock shutdown; wait $pid; echo "mysqld exit $?"
