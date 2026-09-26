/*
 * Captured stdio: the sentinel FILE handles, libio's buffering over them, and
 * the printf family.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

/*
 * libc `FILE*` stdio over the virtual kernel. mimalloc and aws-lc write
 * warnings/errors through `fputs`/`fprintf`/`fwrite` to `stdout`/`stderr`
 * (`__stdoutp`/`__stderrp` on Darwin), and C programs print through `printf`.
 * Define the two stream globals as shim-owned SENTINELS pointing at opaque
 * static storage, and interpose the writers so a sentinel stream reaches the
 * shim's own stream state below and, through it, the guest descriptor (1 or
 * 2) via patina_write. The guest never dereferences the sentinel: pointer
 * identity alone selects the stream. A NON-sentinel FILE* reaching an
 * interposer means an un-interposed `fopen` leaked a real host stream through,
 * so it fails closed LOUDLY (flush + abort naming the symbol), the
 * patina_process_trap shape. Being strong defs, the guest's references bind
 * here and the libc stdio symbols drop off the import table.
 */
static FILE patina_sentinel_stdout_storage;
static FILE patina_sentinel_stderr_storage;

#ifdef __APPLE__
FILE *__stdoutp = &patina_sentinel_stdout_storage;
FILE *__stderrp = &patina_sentinel_stderr_storage;

#endif

#ifndef __APPLE__
FILE *stdout = &patina_sentinel_stdout_storage;
FILE *stderr = &patina_sentinel_stderr_storage;

#endif

/*
 * The streams buffer as glibc's libio does (libio/fileops.c, glibc 2.39), run
 * over the virtual kernel's answers:
 *
 * - stdout chooses its buffer the first time a writer needs one
 *   (`_IO_file_doallocate`): an fstat of its descriptor, `st_blksize` bytes
 *   when that answers below BUFSIZ and BUFSIZ otherwise (a closed descriptor
 *   included). A terminal would make it line buffered, which cannot happen
 *   here: no descriptor is a terminal under patina (`isatty`). Darwin's libc
 *   (`__swhatbuf`) takes `st_blksize` whenever fstat answers, its BUFSIZ
 *   (1024) otherwise.
 * - stderr is unbuffered: each call is one write (the printf family formats
 *   the whole message first, as glibc's helper buffer does).
 * - Bytes that do not fit fill the buffer, the full buffer is written, whole
 *   blocks go straight from the caller, and the rest stays buffered
 *   (`_IO_new_file_xsputn`). A write error surfaces where the bytes are
 *   written: at the flush, or at the writer whose bytes did not fit. The
 *   buffer is emptied either way (`new_do_write`).
 * - `fflush(stdout)`/`fflush(NULL)` write what is pending, and so does the
 *   end of the run on the exit paths glibc flushes on: `exit` and a return
 *   from `main` (patina_shutdown calls the flusher registered below, from the
 *   atexit finalizer or the harness's own finalize). An abort, a fatal signal
 *   or `_exit` loses the buffer, as it does under glibc. Every path on which
 *   patina itself ends the run (a deny-trap, an internal fatal, a liveness
 *   stop, a verdict) first hands the buffer to the host after the captured
 *   stdout (patina_stdio_take_pending, registered at startup), so the output
 *   leading up to it is not lost with the process.
 *
 * Each stream carries one recursive lock (glibc's `_IO_lock_t`), taken through
 * the scheduler's own mutex so concurrent guest threads queue on it and a
 * flush in progress cannot be overtaken. The flush at the end of the run takes
 * no lock, as glibc's `_IO_cleanup` takes none, and neither does a writer
 * after `main` has returned (patina_internal_lock). Nothing here is recorded:
 * the bytes and the writes they become are a function of the guest's calls.
 */
#ifdef __APPLE__
#define PATINA_STDIO_BUFSIZ ((size_t)1024)
#define PATINA_STREAM_LOCK_INIT PTHREAD_RECURSIVE_MUTEX_INITIALIZER
#else
#define PATINA_STDIO_BUFSIZ ((size_t)8192)
#define PATINA_STREAM_LOCK_INIT PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
#endif
/* The largest buffer either rule can choose. */
#define PATINA_STDIO_STORAGE ((size_t)8192)

struct patina_stream {
    int fd;
    int unbuffered;
    /* The buffer's size, 0 until a writer first needs it. */
    size_t size;
    /* The bytes waiting in it. */
    size_t used;
    pthread_mutex_t lock;
    unsigned char *bytes;
};

static unsigned char patina_stdout_bytes[PATINA_STDIO_STORAGE];
static struct patina_stream patina_stream_stdout = {1, 0, 0, 0, PATINA_STREAM_LOCK_INIT,
                                                    patina_stdout_bytes};
static struct patina_stream patina_stream_stderr = {2, 1, 0, 0, PATINA_STREAM_LOCK_INIT, NULL};

__attribute__((noreturn)) static void patina_stdio_trap(const char *symbol) {
    static const char prefix[] = "patina: stdio call on a non-sentinel FILE* reached under patina: ";
    (void)patina_stdio_write(2, prefix, sizeof prefix - 1);
    (void)patina_stdio_write(2, symbol, strlen(symbol));
    static const char suffix[] =
        "; a host FILE* means an un-interposed fopen leaked through; failing closed\n";
    (void)patina_stdio_write(2, suffix, sizeof suffix - 1);
    patina_flush_captured_stdio();
    patina_host_abort();
}

/* Map a stream to its guest descriptor NUMBER: 1 for the stdout sentinel, 2 for
 * the stderr sentinel, -1 for any other (a leaked host FILE*). The streams
 * write through patina_write on that number, so `printf` after `dup2(file, 1)`
 * lands in the file exactly as it does under a kernel; the trap diagnostic
 * goes to the captured-stderr sink directly, as every runtime diagnostic does. */
static int patina_sentinel_fd(FILE *stream) {
    if (stream == &patina_sentinel_stdout_storage) {
        return 1;
    }
    if (stream == &patina_sentinel_stderr_storage) {
        return 2;
    }
    return -1;
}

/* The stream a sentinel names; any other FILE* is a leaked host stream. */
static struct patina_stream *patina_stream_of(FILE *stream, const char *symbol) {
    switch (patina_sentinel_fd(stream)) {
        case 1:
            return &patina_stream_stdout;
        case 2:
            return &patina_stream_stderr;
        default:
            patina_stdio_trap(symbol);
    }
}

/* Take the stream's lock; whether it was taken. A lock the scheduler refuses
 * (a relock on Darwin, whose static mutexes are error-checking) leaves the
 * call unlocked, which is what a recursive lock would have allowed; so does
 * teardown (patina_internal_lock). */
static int patina_stream_lock(struct patina_stream *s) {
    return patina_internal_lock(&s->lock);
}

static void patina_stream_unlock(struct patina_stream *s, int held) {
    patina_internal_unlock(&s->lock, held);
}

/* Write `length` bytes to the stream's descriptor, retrying a short write
 * (`_IO_new_file_write`): the bytes written. A failed write leaves its errno. */
static size_t patina_stream_write_out(int fd, const unsigned char *data, size_t length) {
    size_t done = 0;
    while (done < length) {
        intptr_t written = patina_write(fd, data + done, length - done);
        if (written <= 0) {
            if (written < 0) errno = patina_errno();
            break;
        }
        done += (size_t)written;
    }
    return done;
}

/* Choose stdout's buffer (`_IO_file_doallocate`, Darwin `__swhatbuf`) from
 * the descriptor's fstat answer. The captured streams have no node, so fstat
 * answers EBADF for them where the host's pipe or terminal would answer: the
 * size falls back as for a failed fstat, and errno stays as the caller left
 * it, as it does over the host's descriptor. */
static void patina_stream_allocate(struct patina_stream *s) {
    if (s->size != 0) {
        return;
    }
    size_t size = PATINA_STDIO_BUFSIZ;
    int saved = errno;
    struct patina_metadata values;
    struct stat status;
    if (fill_stat(patina_fd_metadata_values(s->fd, &values), &values, &status) == 0) {
#ifdef __APPLE__
        if (status.st_blksize > 0) size = (size_t)status.st_blksize;
#else
        if (status.st_blksize > 0 && (size_t)status.st_blksize < size) {
            size = (size_t)status.st_blksize;
        }
#endif
    } else {
        int kind = patina_fd_kind(s->fd);
        if (kind == PATINA_FD_STDOUT || kind == PATINA_FD_STDERR) errno = saved;
    }
    s->size = size <= PATINA_STDIO_STORAGE ? size : PATINA_STDIO_STORAGE;
}

/* Write what the buffer holds and empty it: 0, or EOF when the write failed
 * (the bytes are dropped either way). */
static int patina_stream_sync(struct patina_stream *s) {
    size_t pending = s->used;
    if (pending == 0) {
        return 0;
    }
    size_t written = patina_stream_write_out(s->fd, s->bytes, pending);
    s->used = 0;
    return written == pending ? 0 : EOF;
}

/* Put `length` bytes into the stream (`_IO_new_file_xsputn`): how many it
 * took. Fewer than `length` means a write failed, with its errno. */
static size_t patina_stream_put(struct patina_stream *s, const unsigned char *data,
                                size_t length) {
    size_t to_do = length;
    if (to_do == 0) {
        return 0;
    }
    if (!s->unbuffered && s->size != 0) {
        size_t room = s->size - s->used;
        size_t count = room < to_do ? room : to_do;
        memcpy(s->bytes + s->used, data, count);
        s->used += count;
        data += count;
        to_do -= count;
        if (to_do == 0) {
            return length;
        }
    }
    /* The buffer is full (or not yet chosen): write it out. */
    if (!s->unbuffered) {
        patina_stream_allocate(s);
    }
    if (patina_stream_sync(s) != 0) {
        return length - to_do;
    }
    /* Whole blocks go straight to the descriptor; an unbuffered stream's block
     * is one byte, so everything does. */
    size_t block = s->unbuffered ? 1 : s->size;
    size_t direct = to_do - (block >= 128 ? to_do % block : 0);
    if (direct != 0) {
        size_t written = patina_stream_write_out(s->fd, data, direct);
        to_do -= written;
        if (written < direct) {
            return length - to_do;
        }
        data += direct;
    }
    /* Less than a block remains: it fits the emptied buffer. */
    if (to_do != 0) {
        memcpy(s->bytes + s->used, data, to_do);
        s->used += to_do;
    }
    return length;
}

/* Put one byte (`__overflow`): the byte, or EOF when a write failed. */
static int patina_stream_putc(struct patina_stream *s, unsigned char byte) {
    if (s->unbuffered) {
        return patina_stream_write_out(s->fd, &byte, 1) == 1 ? byte : EOF;
    }
    if (s->size == 0 || s->used == s->size) {
        patina_stream_allocate(s);
        if (patina_stream_sync(s) != 0) {
            return EOF;
        }
    }
    s->bytes[s->used++] = byte;
    return byte;
}

/* Registered with the runtime at startup (patina_register_stream_flusher):
 * the flush at the end of the run on its exit paths. */
static void patina_stdio_flush_at_exit(void) {
    (void)patina_stream_sync(&patina_stream_stdout);
}

/* Registered beside the flush: hand over what stdout's buffer holds and empty
 * it, writing nothing. The runtime writes the bytes itself on the paths where
 * patina ends the run (a refusal, a fatal, a verdict), after the captured
 * stdout, and only while descriptor 1 is still the capture. It takes no lock:
 * those paths abort right after, and the stream may be mid-call. */
static size_t patina_stdio_take_pending(const void **bytes) {
    struct patina_stream *s = &patina_stream_stdout;
    size_t used = s->used;
    *bytes = s->bytes;
    s->used = 0;
    return used;
}

/* Put a whole message (`_IO_sputn` under the stream's lock): whether all of
 * it was taken. */
static int patina_stream_put_all(struct patina_stream *s, const void *data, size_t length) {
    int held = patina_stream_lock(s);
    size_t taken = patina_stream_put(s, (const unsigned char *)data, length);
    patina_stream_unlock(s, held);
    return taken == length;
}

int fputs(const char *string, FILE *stream) {
    struct patina_stream *s = patina_stream_of(stream, "fputs");
    /* `string` is declared nonnull by libc (a NULL compare is -Werror under
     * gcc), so the contract is trusted, the gethostname/getpwuid_r precedent.
     * glibc answers 1 (libio/iofputs.c). */
    return patina_stream_put_all(s, string, strlen(string)) ? 1 : EOF;
}

size_t fwrite(const void *pointer, size_t size, size_t count, FILE *stream) {
    struct patina_stream *s = patina_stream_of(stream, "fwrite");
    size_t request = size * count;
    if (request == 0) {
        return 0;
    }
    int held = patina_stream_lock(s);
    size_t taken = patina_stream_put(s, (const unsigned char *)pointer, request);
    patina_stream_unlock(s, held);
    return taken == request ? count : taken / size;
}

/* Shared printf-family engine: format once into a stack buffer (heap fallback
 * for the rare long message, sized from the vsnprintf length probe), then put
 * the message into the stream: its length, or -1 when a write failed. */
static int patina_stream_vprintf(struct patina_stream *s, const char *format,
                                 va_list arguments) {
    char stack[512];
    va_list second;
    va_copy(second, arguments);
    int needed = vsnprintf(stack, sizeof stack, format, arguments);
    if (needed < 0) {
        va_end(second);
        return needed;
    }
    if ((size_t)needed < sizeof stack) {
        va_end(second);
        return patina_stream_put_all(s, stack, (size_t)needed) ? needed : -1;
    }
    char *heap = malloc((size_t)needed + 1);
    if (heap == NULL) {
        va_end(second);
        errno = ENOMEM;
        return -1;
    }
    int written = vsnprintf(heap, (size_t)needed + 1, format, second);
    va_end(second);
    if (written > 0 && !patina_stream_put_all(s, heap, (size_t)written)) {
        written = -1;
    }
    free(heap);
    return written;
}

int vfprintf(FILE *stream, const char *format, va_list arguments) {
    return patina_stream_vprintf(patina_stream_of(stream, "vfprintf"), format, arguments);
}

int fprintf(FILE *stream, const char *format, ...) {
    struct patina_stream *s = patina_stream_of(stream, "fprintf");
    va_list arguments;
    va_start(arguments, format);
    int written = patina_stream_vprintf(s, format, arguments);
    va_end(arguments);
    return written;
}

/* `printf`/`puts`/`putchar` bind implicitly to the stdout sentinel, so no
 * sentinel check is needed: they can never see a leaked host FILE*. On ELF this
 * family is also what keeps glibc's own printf away from the sentinel globals —
 * a probe or guest calling printf must reach the shim, never glibc's stdio
 * (whose vtable hardening aborts on a foreign FILE). */
int printf(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    int written = patina_stream_vprintf(&patina_stream_stdout, format, arguments);
    va_end(arguments);
    return written;
}

/* glibc's puts answers the bytes written, the newline included
 * (libio/ioputs.c); POSIX asks only for a non-negative number. */
int puts(const char *string) {
    struct patina_stream *s = &patina_stream_stdout;
    size_t length = strlen(string);
    int held = patina_stream_lock(s);
    int result = EOF;
    if (patina_stream_put(s, (const unsigned char *)string, length) == length &&
        patina_stream_putc(s, '\n') != EOF) {
        result = length < (size_t)INT_MAX ? (int)(length + 1) : INT_MAX;
    }
    patina_stream_unlock(s, held);
    return result;
}

static int patina_stream_put_byte(struct patina_stream *s, int character) {
    int held = patina_stream_lock(s);
    int result = patina_stream_putc(s, (unsigned char)character);
    patina_stream_unlock(s, held);
    return result;
}

int putchar(int character) {
    return patina_stream_put_byte(&patina_stream_stdout, character);
}

int fputc(int character, FILE *stream) {
    return patina_stream_put_byte(patina_stream_of(stream, "fputc"), character);
}

static int patina_stream_flush(struct patina_stream *s) {
    int held = patina_stream_lock(s);
    int result = patina_stream_sync(s);
    patina_stream_unlock(s, held);
    return result;
}

/* NULL flushes every stream (`_IO_flush_all`): EOF when any write failed. */
int fflush(FILE *stream) {
    if (stream == NULL) {
        int out = patina_stream_flush(&patina_stream_stdout);
        int err = patina_stream_flush(&patina_stream_stderr);
        return out == 0 && err == 0 ? 0 : EOF;
    }
    return patina_stream_flush(patina_stream_of(stream, "fflush"));
}
