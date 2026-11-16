/* W3 c-sqlite: SQLite durability under crashes (system libsqlite3).
 *
 * usage: sqlite-dur MODE SYNC [ROWS]
 *   MODE: delete | wal (journal_mode), SYNC: off | normal | full | extra (synchronous),
 *   ROWS: rows written per incarnation (default 120).
 *
 * Files: /work/sq/db (+ -journal / -wal / -shm), /work/sq/acks.
 * First incarnation (no /work/sq/acks): create the database and table, fsync the
 * directory, create the ack file (fsynced, directory fsynced).
 * Every incarnation that finds /work/sq/acks first checks:
 *   - the database opens and PRAGMA integrity_check says "ok"   (INVARIANT corrupt-db)
 *   - every row holds the value derived from its id             (INVARIANT row-value)
 *   - every acknowledged id is present                          (INVARIANT acked-row-lost)
 * then writes ROWS more rows, then checks again.
 * A writer thread inserts one row per transaction; after each commit returns it appends
 * "ID\n" to the ack file and fsyncs it (the acknowledgement). Two reader threads, each
 * with its own connection, read the table while the writer runs and check row values.
 * Any SQLite error (an injected I/O error) is a clean stop: "SQLITE-ERROR ..." on stderr,
 * exit 0. Corruption is judged only by PRAGMA integrity_check (retried while injected
 * errors stop it): an error code of SQLITE_CORRUPT triggers that check, it is not a
 * verdict (SQLite returns it for an EIO on a page read).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DIR "/work/sq"
#define DB DIR "/db"
#define ACKS DIR "/acks"

static const char *mode, *syncm;
static int rows = 120;
static volatile int writer_done;

static void invariant(const char *name, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\nINVARIANT %s\n", name);
    fflush(stderr);
    _exit(1);
}

static int integrity(char *first, size_t n);

/* integrity() retried: 1 ok, 0 corrupt, -1 unknown (errors every time). A corruption
 * error code that persists over 10 attempts is corruption: an injected error at a few
 * per mille does not repeat that often. */
static int judge(char *first, size_t n) {
    int corrupt_codes = 0;
    for (int i = 0; i < 20; i++) {
        int r = integrity(first, n);
        if (r >= 0) return r;
        if (r == -2 && ++corrupt_codes >= 10) return 0;
    }
    return -1;
}

/* SQLite reports SQLITE_CORRUPT for some I/O errors (an EIO on a page read gives rc 11
 * with the file intact: checked natively with SQLite 3.46.1), so an error code is not a
 * verdict on the file. The file is judged by integrity_check on a fresh connection,
 * retried while injected errors make it fail. */
static void verify_file(const char *what) {
    char first[256];
    int r = judge(first, sizeof first);
    if (r == 1) {
        fprintf(stderr, "SQLITE-ERROR-NOT-CORRUPT %s: integrity_check ok\n", what);
        return;
    }
    if (r == 0) invariant("corrupt-db", "%s: integrity_check: %s", what, first);
    fprintf(stderr, "SQLITE-ERROR %s: integrity_check kept failing with errors\n", what);
}

/* A clean stop: SQLite reported an error. A corruption code is checked against the file. */
static void clean_stop(const char *what, int rc, sqlite3 *db) {
    int base = rc & 0xff;
    fprintf(stderr, "SQLITE-ERROR %s: rc=%d (%s)\n", what, rc, db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
    if (base == SQLITE_CORRUPT || base == SQLITE_NOTADB) verify_file(what);
    fflush(stderr);
    _exit(0);
}

static void sys_stop(const char *what) {
    fprintf(stderr, "SYS-ERROR %s: %s\n", what, strerror(errno));
    fflush(stderr);
    _exit(0);
}

static uint64_t mix(uint64_t z) {
    z += 0x9e3779b97f4a7c15ull;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

static int val(int64_t id, unsigned char *buf) {
    int len = 40 + (int)(mix((uint64_t)id) % 700);
    for (int i = 0; i < len; i++) buf[i] = (unsigned char)(mix((uint64_t)id * 1000003u + i) & 0xff);
    return len;
}

static void exec(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) clean_stop(sql, rc, db);
}

static sqlite3 *open_db(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(DB, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, NULL);
    if (rc != SQLITE_OK) clean_stop("open", rc, db);
    sqlite3_busy_timeout(db, 60000);
    char q[128];
    snprintf(q, sizeof q, "PRAGMA journal_mode=%s", mode);
    exec(db, q);
    snprintf(q, sizeof q, "PRAGMA synchronous=%s", syncm);
    exec(db, q);
    return db;
}

static void fsync_path(const char *p) {
    int fd = open(p, O_RDONLY | O_DIRECTORY);
    if (fd < 0) sys_stop(p);
    if (fsync(fd) != 0) sys_stop("fsync dir");
    close(fd);
}

/* Acknowledged ids: '\n'-terminated decimal lines; a NUL cuts off what precedes it on
 * its line (zeros an un-fsynced append can leave), a torn last line is not counted. */
static int64_t *read_acks(int *n) {
    FILE *f = fopen(ACKS, "rb");
    if (!f) sys_stop("open acks");
    static char buf[1 << 20];
    size_t len = fread(buf, 1, sizeof buf, f);
    fclose(f);
    int64_t *ids = malloc(sizeof(int64_t) * (len / 2 + 1));
    *n = 0;
    size_t start = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == 0) { start = i + 1; continue; }
        if (buf[i] != '\n') continue;
        if (i > start) {
            int64_t v = 0;
            int ok = 1;
            for (size_t j = start; j < i; j++) {
                if (buf[j] < '0' || buf[j] > '9') { ok = 0; break; }
                v = v * 10 + (buf[j] - '0');
            }
            if (!ok) invariant("ack-line-corrupt", "ack line at %zu not a number", start);
            ids[(*n)++] = v;
        }
        start = i + 1;
    }
    return ids;
}

static int is_corrupt_code(int rc) {
    return (rc & 0xff) == SQLITE_CORRUPT || (rc & 0xff) == SQLITE_NOTADB;
}

/* PRAGMA integrity_check on a fresh connection: 1 "ok", 0 completed with problems that
 * are not I/O errors (a corrupt file), -1 an error stopped it (rows naming an error code
 * are I/O errors that integrity_check met, not corruption), -2 stopped by a corruption
 * error code (an injected read error can give one too, so the caller retries). */
static int integrity(char *first, size_t n) {
    sqlite3 *db = NULL;
    first[0] = 0;
    if (sqlite3_open_v2(DB, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK) {
        int rc = sqlite3_errcode(db);
        sqlite3_close(db);
        return is_corrupt_code(rc) ? -2 : -1;
    }
    sqlite3_busy_timeout(db, 60000);
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &st, NULL) != SQLITE_OK) {
        int rc = sqlite3_errcode(db);
        snprintf(first, n, "prepare: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return is_corrupt_code(rc) ? -2 : -1;
    }
    int rc, lines = 0, ok = 0, ioerr = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 0);
        if (lines++ == 0) snprintf(first, n, "%s", t ? t : "(null)");
        ok = t && strcmp(t, "ok") == 0;
        if (t && strstr(t, "error code=")) ioerr = 1;
    }
    if (rc != SQLITE_DONE) snprintf(first, n, "step: %s", sqlite3_errmsg(db));
    sqlite3_finalize(st);
    sqlite3_close(db);
    if (rc != SQLITE_DONE) return is_corrupt_code(rc) ? -2 : -1;
    if (ioerr) return -1;
    return lines == 1 && ok ? 1 : 0;
}

/* Integrity, values, acknowledged rows. Returns the next id to write. */
static int64_t check(const char *when) {
    char first[256];
    int ir = judge(first, sizeof first);
    if (ir == 0) invariant("corrupt-db", "%s: integrity_check: %s", when, first);
    if (ir < 0) {
        fprintf(stderr, "SQLITE-ERROR %s: integrity_check kept failing with errors\n", when);
        _exit(0);
    }
    sqlite3 *db = open_db();
    sqlite3_stmt *st;
    int rc;
    rc = sqlite3_prepare_v2(db, "SELECT id, v FROM t ORDER BY id", -1, &st, NULL);
    if (rc != SQLITE_OK) clean_stop("prepare select", rc, db);
    int64_t maxid = -1, count = 0;
    static unsigned char want[1024];
    char *present = calloc(1 << 20, 1);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(st, 0);
        int n = val(id, want);
        if (sqlite3_column_bytes(st, 1) != n || memcmp(sqlite3_column_blob(st, 1), want, n) != 0)
            invariant("row-value", "%s: row %lld has the wrong value", when, (long long)id);
        if (id >= 0 && id < (1 << 20)) present[id] = 1;
        if (id > maxid) maxid = id;
        count++;
    }
    if (rc != SQLITE_DONE) clean_stop("select", rc, db);
    sqlite3_finalize(st);
    sqlite3_close(db);
    int n;
    int64_t *acks = read_acks(&n), maxack = -1;
    for (int i = 0; i < n; i++) {
        if (acks[i] < 0 || acks[i] >= (1 << 20) || !present[acks[i]])
            invariant("acked-row-lost", "%s: row %lld was acknowledged and is missing (%lld rows, max id %lld)",
                      when, (long long)acks[i], (long long)count, (long long)maxid);
        if (acks[i] > maxack) maxack = acks[i];
    }
    printf("%s: %lld rows, max id %lld, %d acks (max %lld): ok\n", when, (long long)count, (long long)maxid, n,
           (long long)maxack);
    fflush(stdout);
    free(acks);
    free(present);
    return maxid + 1;
}

static void setup(void) {
    /* A crash before the ack file became durable: start from nothing. */
    const char *old[] = {DB, DB "-journal", DB "-wal", DB "-shm", ACKS};
    mkdir(DIR, 0755);
    for (unsigned i = 0; i < sizeof old / sizeof *old; i++) unlink(old[i]);
    fsync_path("/work");
    sqlite3 *db = open_db();
    exec(db, "CREATE TABLE t(id INTEGER PRIMARY KEY, v BLOB NOT NULL)");
    sqlite3_close(db);
    fsync_path(DIR);
    int fd = open(ACKS, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0 || fsync(fd) != 0) sys_stop("create acks");
    close(fd);
    fsync_path(DIR);
}

static int64_t first_id;

static void *writer(void *arg) {
    (void)arg;
    sqlite3 *db = open_db();
    int ack = open(ACKS, O_WRONLY | O_APPEND);
    if (ack < 0) sys_stop("open acks");
    /* end any torn line a crash left */
    if (write(ack, "\n", 1) != 1 || fsync(ack) != 0) sys_stop("ack separator");
    sqlite3_stmt *ins;
    int rc = sqlite3_prepare_v2(db, "INSERT INTO t(id, v) VALUES(?, ?)", -1, &ins, NULL);
    if (rc != SQLITE_OK) clean_stop("prepare insert", rc, db);
    static unsigned char buf[1024];
    for (int64_t id = first_id; id < first_id + rows; id++) {
        int n = val(id, buf);
        sqlite3_bind_int64(ins, 1, id);
        sqlite3_bind_blob(ins, 2, buf, n, SQLITE_STATIC);
        rc = sqlite3_step(ins);
        if (rc != SQLITE_DONE) clean_stop("insert", rc, db);
        sqlite3_reset(ins);
        char line[32];
        int l = snprintf(line, sizeof line, "%lld\n", (long long)id);
        if (write(ack, line, l) != l) sys_stop("write ack");
        if (fsync(ack) != 0) sys_stop("fsync ack");
    }
    sqlite3_finalize(ins);
    sqlite3_close(db);
    close(ack);
    writer_done = 1;
    return NULL;
}

static void *reader(void *arg) {
    (void)arg;
    sqlite3 *db = open_db();
    sqlite3_stmt *st;
    int rc = sqlite3_prepare_v2(db, "SELECT id, v FROM t WHERE id >= ? ORDER BY id", -1, &st, NULL);
    if (rc != SQLITE_OK) clean_stop("reader prepare", rc, db);
    static __thread unsigned char want[1024];
    int64_t from = first_id;
    int rounds = 0;
    while (!writer_done && rounds++ < 100000) {
        sqlite3_bind_int64(st, 1, from);
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            int64_t id = sqlite3_column_int64(st, 0);
            int n = val(id, want);
            if (sqlite3_column_bytes(st, 1) != n || memcmp(sqlite3_column_blob(st, 1), want, n) != 0)
                invariant("row-value", "reader: row %lld has the wrong value", (long long)id);
            from = id + 1;
        }
        if (rc != SQLITE_DONE) clean_stop("reader select", rc, db);
        sqlite3_reset(st);
        usleep(1000);
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: sqlite-dur delete|wal off|normal|full|extra [ROWS]\n");
        return 2;
    }
    mode = argv[1];
    syncm = argv[2];
    if (argc > 3) rows = atoi(argv[3]);
    struct stat sb;
    if (stat(ACKS, &sb) == 0) {
        first_id = check("recovery");
    } else {
        setup();
        first_id = 0;
    }
    pthread_t w, r[2];
    pthread_create(&w, NULL, writer, NULL);
    for (int i = 0; i < 2; i++) pthread_create(&r[i], NULL, reader, NULL);
    pthread_join(w, NULL);
    for (int i = 0; i < 2; i++) pthread_join(r[i], NULL);
    check("after writing");
    return 0;
}
