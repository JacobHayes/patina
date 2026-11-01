/*
 * C stdio input and file streams: `fopen`/`fdopen`/`freopen`/`fclose`, the
 * reads (`fgets`, `getc`, `ungetc`, `fread`, `getline`, `getdelim`), the
 * positioning calls and the indicators, on a file the probe writes into the
 * directory argv[2], and on stdin. Each case builds a report of every call's
 * answer and writes it to descriptor 1 at the end. `native_abi` runs the
 * `file` and `stdin` cases natively (unlinked) and under the shim and
 * requires the same report; under filesystem faults the `file` report must
 * not change for short reads, and the `faults` case's answers to injected
 * read errors are compared with glibc's rules.
 *
 *   stdio_input_probe file|stdin|faults|fread-fault DIR
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char report[65536];
static size_t reported;
/* The original standard output, where the report goes: a case may reopen
   descriptor 1. */
static int report_fd;

/* The report is formatted by hand: `snprintf` is a host call the pre-run
   audit refuses. */
static void put(const char *bytes) {
    while (*bytes != '\0' && reported < sizeof report) report[reported++] = *bytes++;
}
static void put_number(long value) {
    char digits[24];
    int at = 0;
    unsigned long magnitude = value < 0 ? 0UL - (unsigned long)value : (unsigned long)value;
    if (value < 0) put("-");
    do {
        digits[at++] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude != 0);
    while (at > 0 && reported < sizeof report) report[reported++] = digits[--at];
}

static void note(const char *what, long value) {
    put(what);
    put("=");
    put_number(value);
    put("\n");
}

/* A string answer, with newlines and NULL spelled out. */
static void text(const char *what, const char *value) {
    put(what);
    put("=[");
    if (value == NULL) {
        put("NULL");
    } else {
        for (; *value != '\0'; value++) {
            char one[2] = {*value, '\0'};
            put(*value == '\n' ? "\\n" : one);
        }
    }
    put("]\n");
}

static void state(const char *what, FILE *stream) {
    put("  ");
    put(what);
    note(" errno", errno);
    put("  ");
    put(what);
    note(" feof", feof(stream));
    put("  ");
    put(what);
    note(" ferror", ferror(stream));
    errno = 0;
}

static unsigned long checksum(const char *bytes, size_t length) {
    unsigned long hash = 5381;
    for (size_t i = 0; i < length; i++) hash = hash * 33 + (unsigned char)bytes[i];
    return hash;
}

static int write_all(const char *path, const char *bytes, size_t length, int flags) {
    int fd = open(path, O_WRONLY | O_CREAT | flags, 0644);
    if (fd < 0) return -1;
    while (length > 0) {
        ssize_t n = write(fd, bytes, length);
        if (n <= 0) return -1;
        bytes += n;
        length -= (size_t)n;
    }
    return close(fd);
}

static char path_in[512], path_out[512];
static char content[16384];
static size_t content_length;

static int setup(const char *dir) {
    size_t length = strlen(dir);
    if (length > sizeof path_in - 16) return -1;
    memcpy(path_in, dir, length);
    memcpy(path_in + length, "/in.txt", 8);
    memcpy(path_out, dir, length);
    memcpy(path_out + length, "/out.txt", 9);
    content_length = 0;
    const char *head = "alpha\nbeta\n\n";
    memcpy(content, head, strlen(head));
    content_length = strlen(head);
    memset(content + content_length, 'x', 10000);
    content_length += 10000;
    content[content_length++] = '\n';
    const char *tail = "gamma,delta,eps";
    memcpy(content + content_length, tail, strlen(tail));
    content_length += strlen(tail);
    unlink(path_out);
    int written = write_all(path_in, content, content_length, O_TRUNC);
    errno = 0;
    return written;
}

static int finish(void) {
    unlink(path_in);
    unlink(path_out);
    size_t at = 0;
    while (at < reported) {
        ssize_t n = write(report_fd, report + at, reported - at);
        if (n <= 0) return 1;
        at += (size_t)n;
    }
    return 0;
}

static void lines(const char *what, FILE *stream) {
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    int count = 0;
    while ((length = getline(&line, &capacity, stream)) >= 0) {
        put(what);
        put(" line ");
        put_number(count);
        note(" length", (long)length);
        put(what);
        put(" line ");
        put_number(count);
        note(" sum", (long)(checksum(line, (size_t)length) & 0x7fffffff));
        count++;
    }
    put(what);
    note(" at the end", (long)length);
    state(what, stream);
    free(line);
}

static int file_case(void) {
    char buffer[32];
    static char big[20000];
    FILE *f = fopen(path_in, "r");
    if (f == NULL) return 1;
    note("fileno", fileno(f));
    for (int i = 0; i < 3; i++) text("fgets 4", fgets(buffer, 4, f));
    text("fgets 1", fgets(buffer, 1, f));
    text("fgets 32", fgets(buffer, sizeof buffer, f));
    int c = getc(f);
    note("getc", c);
    note("ungetc the same byte", ungetc(c, f));
    note("ftell after a matching ungetc", ftell(f));
    note("getc again", getc(f));
    note("ungetc another byte", ungetc('Q', f));
    note("ungetc a second", ungetc('R', f));
    note("getc R", getc(f));
    note("getc Q", getc(f));
    note("fread 5", (long)fread(buffer, 1, 5, f));
    buffer[5] = '\0';
    text("  read", buffer);
    note("ftell", ftell(f));
    lines("rest", f);
    note("getc at the end", getc(f));
    state("getc at the end", f);
    clearerr(f);
    state("clearerr", f);

    rewind(f);
    note("rewind ftell", ftell(f));
    char *piece = NULL;
    size_t capacity = 0;
    ssize_t length;
    int pieces = 0;
    while ((length = getdelim(&piece, &capacity, ',', f)) >= 0) {
        put("getdelim ");
        put_number(pieces++);
        note("", (long)length);
    }
    free(piece);
    state("getdelim", f);

    note("fseek 6", fseek(f, 6, SEEK_SET));
    text("  fgets", fgets(buffer, sizeof buffer, f));
    note("fseek -3 cur", fseek(f, -3, SEEK_CUR));
    text("  fgets", fgets(buffer, sizeof buffer, f));
    note("  ftell", ftell(f));
    note("fseeko end", fseeko(f, 0, SEEK_END));
    note("  ftello", (long)ftello(f));
    note("  getc", getc(f));
    state("fseeko end", f);
    errno = 0;
    note("fseek bad whence", fseek(f, 0, 42));
    state("fseek bad whence", f);

    rewind(f);
    note("getc after rewind", getc(f));
    note("fflush the input", fflush(f));
    note("  the descriptor's offset", (long)lseek(fileno(f), 0, SEEK_CUR));
    note("  ftell", ftell(f));
    note("  getc", getc(f));

    rewind(f);
    note("fread big", (long)fread(big, 1, sizeof big, f));
    note("  sum", (long)(checksum(big, content_length) & 0x7fffffff));
    state("fread big", f);
    note("fread past the end", (long)fread(big, 1, 10, f));
    if (write_all(path_in, "more\n", 5, O_APPEND) != 0) return 1;
    note("getc with eof set", getc(f));
    note("fgets with eof set", fgets(buffer, sizeof buffer, f) != NULL);
    note("fread big with eof set", (long)fread(big, 1, sizeof big, f));
    clearerr(f);
    note("fseek back", fseek(f, -5, SEEK_END));
    text("fgets after clearerr", fgets(buffer, sizeof buffer, f));
    note("fclose", fclose(f));

    errno = 0;
    note("fopen missing", fopen("/nonexistent-dir/x", "r") != NULL);
    state("fopen missing", stdin);
    note("fopen bad mode", fopen(path_in, "z") != NULL);
    state("fopen bad mode", stdin);
    note("fopen x existing", fopen(path_in, "wx") != NULL);
    state("fopen x existing", stdin);

    FILE *w = fopen(path_out, "w");
    note("fputs w", fputs("one\n", w));
    note("fprintf w", fprintf(w, "%d\n", 22));
    note("ftell w", ftell(w));
    errno = 0;
    note("getc on w", getc(w));
    state("getc on w", w);
    note("fclose w", fclose(w));
    FILE *a = fopen(path_out, "a");
    note("fputs a", fputs("two\n", a));
    note("fclose a", fclose(a));
    FILE *ar = fopen(path_out, "a+");
    note("a+ ftell at open", ftell(ar));
    note("a+ getc", getc(ar));
    note("fclose a+ read", fclose(ar));
    FILE *aw = fopen(path_out, "a+");
    note("a+ fputs", fputs("+\n", aw));
    note("a+ ftell after a put", ftell(aw));
    note("fclose a+ write", fclose(aw));
    FILE *rw = fopen(path_out, "r+");
    text("r+ fgets", fgets(buffer, sizeof buffer, rw));
    note("r+ fseek cur", fseek(rw, 0, SEEK_CUR));
    note("r+ fputs", fputs("ZZ", rw));
    note("r+ fflush", fflush(rw));
    rewind(rw);
    size_t got = fread(buffer, 1, sizeof buffer - 1, rw);
    buffer[got] = '\0';
    text("r+ contents", buffer);
    note("r+ fread", (long)got);
    state("r+", rw);
    note("fclose r+", fclose(rw));
    FILE *wp = fopen(path_out, "w+");
    note("w+ fputs", fputs("hello\nworld\n", wp));
    rewind(wp);
    text("w+ fgets", fgets(buffer, sizeof buffer, wp));
    text("w+ fgets", fgets(buffer, sizeof buffer, wp));
    note("fclose w+", fclose(wp));

    int fd = open(path_in, O_RDONLY);
    errno = 0;
    note("fdopen w on a read-only fd", fdopen(fd, "w") != NULL);
    state("fdopen w", stdin);
    FILE *d = fdopen(fd, "r");
    note("fdopen fileno is the fd", fileno(d) == fd);
    text("fdopen fgets", fgets(buffer, sizeof buffer, d));
    note("fdopen fclose", fclose(d));
    errno = 0;
    note("the fd after fclose", fcntl(fd, F_GETFD));
    note("  errno", errno);
    int out = open(path_out, O_WRONLY);
    FILE *da = fdopen(out, "a");
    note("fdopen a sets O_APPEND", (fcntl(out, F_GETFL) & O_APPEND) != 0);
    note("fdopen a fputs", fputs("three\n", da));
    note("fdopen a fclose", fclose(da));
    FILE *back = fopen(path_out, "r");
    lines("appended", back);
    fclose(back);

    FILE *many[20];
    for (int i = 0; i < 20; i++) many[i] = fopen(path_in, "r");
    for (int i = 19; i >= 0; i--) {
        if (many[i] == NULL || getc(many[i]) != 'a' || fclose(many[i]) != 0) return 1;
    }
    FILE *again = fopen(path_in, "r");
    note("fopen after closing twenty, fileno", fileno(again));
#ifdef __linux__
    note("setvbuf unbuffered", setvbuf(again, NULL, _IONBF, 0));
    note("  getc", getc(again));
    note("  getc", getc(again));
    note("  the descriptor's offset", (long)lseek(fileno(again), 0, SEEK_CUR));
#endif
    fclose(again);
    return finish();
}

static int stdin_case(void) {
    char buffer[64];
    note("fileno stdin", fileno(stdin));
    note("getc stdin", getc(stdin));
    state("getc stdin", stdin);
    text("fgets stdin", fgets(buffer, sizeof buffer, stdin));
    note("getchar", getchar());
    lines("stdin", stdin);
    errno = 0;
    note("fputc to stdin", fputc('x', stdin));
    state("fputc to stdin", stdin);
    clearerr(stdin);
    FILE *same = freopen(path_in, "r", stdin);
    note("freopen is stdin", same == stdin);
    note("fileno after freopen", fileno(stdin));
    text("fgets after freopen", fgets(buffer, sizeof buffer, stdin));
    note("getchar", getchar());
    note("ungetc", ungetc('A', stdin));
    text("fgets", fgets(buffer, sizeof buffer, stdin));
    lines("reopened", stdin);
    note("freopen missing", freopen("/nonexistent-dir/x", "r", stdin) != NULL);
    note("  errno", errno);
    errno = 0;
    note("the old descriptor after a failed freopen", fcntl(0, F_GETFD));
    note("  errno", errno);
    int fd = open(path_in, O_RDONLY);
    note("open takes descriptor 0", fd);
    FILE *s = freopen(path_in, "r", stdout);
    note("freopen stdout for reading", s == stdout);
    note("  fileno stdout", fileno(stdout));
    text("  fgets stdout", fgets(buffer, sizeof buffer, stdout));
    return finish();
}

/* Under an injected read error on the Nth read: what each call answers. */
static int faults_case(void) {
    char buffer[64];
    if (write_all(path_in, "alpha\nbeta\ngamma", 16, O_TRUNC) != 0) return 1;
    FILE *f = fopen(path_in, "r");
    if (f == NULL) return 1;
    for (int i = 0; i < 2; i++) {
        text("fgets", fgets(buffer, sizeof buffer, f));
        state("fgets", f);
        clearerr(f);
    }
    lines("getline", f);
    char *line = NULL;
    size_t capacity = 0;
    note("getline with the error set", (long)getline(&line, &capacity, f));
    free(line);
    note("fclose", fclose(f));
    return finish();
}

static int fread_fault_case(void) {
    static char big[10000];
    if (write_all(path_in, content, content_length, O_TRUNC) != 0) return 1;
    FILE *f = fopen(path_in, "r");
    if (f == NULL) return 1;
    note("fread", (long)fread(big, 1, 100, f));
    state("fread", f);
    note("fread big", (long)fread(big, 1, sizeof big, f));
    state("fread big", f);
    note("getc with the error set", getc(f));
    note("fclose", fclose(f));
    return finish();
}

int main(int argc, char **argv) {
    report_fd = dup(1);
    if (argc < 3 || report_fd < 0 || setup(argv[2]) != 0) return 2;
    if (strcmp(argv[1], "file") == 0) return file_case();
    if (strcmp(argv[1], "stdin") == 0) return stdin_case();
    if (strcmp(argv[1], "faults") == 0) return faults_case();
    if (strcmp(argv[1], "fread-fault") == 0) return fread_fault_case();
    return 2;
}
