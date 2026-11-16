# Python's sqlite3 writing 1,000 rows into /work/rows.db in 10 transactions, then reading
# them back. Prints the row count and a checksum.
import sqlite3

db = sqlite3.connect("/work/rows.db")
db.execute("create table if not exists t (id integer primary key, v text)")
for tx in range(10):
    with db:
        db.executemany("insert into t (v) values (?)", [("row %d %s" % (tx * 100 + i, "x" * (i % 50)),) for i in range(100)])
n, s = db.execute("select count(*), sum(length(v)) from t").fetchone()
print("rows", n, "chars", s)
db.close()
