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
 * The streams are glibc 2.39's libio write path (libio/fileops.c, genops.c,
 * iosetvbuf.c, stdio-common/printf_buffer_to_file.c) run over the virtual
 * kernel's answers, with libio's own state: a buffer (`_IO_buf_base`/`_end`),
 * the write area inside it (`_IO_write_ptr`/`_end`) and the flags
 * `_IO_UNBUFFERED`, `_IO_LINE_BUF`, `_IO_CURRENTLY_PUTTING` and
 * `_IO_ERR_SEEN`. The functions below are libio's, named after them.
 *
 * - A stream chooses its buffer the first time a writer needs one
 *   (`_IO_file_doallocate`): an fstat of its descriptor, `st_blksize` bytes
 *   when that answers below BUFSIZ and BUFSIZ otherwise (a closed descriptor
 *   included), or libio's one-byte `_shortbuf` when it is unbuffered. A
 *   terminal would make it line buffered, which cannot happen here: no
 *   descriptor is a terminal under patina (`isatty`). Darwin's libc
 *   (`__swhatbuf`) takes `st_blksize` whenever fstat answers, its BUFSIZ
 *   (1024) otherwise.
 * - stdout starts fully buffered, stderr unbuffered. `setvbuf`, `setbuf`,
 *   `setbuffer` and `setlinebuf` change that as glibc's do (Linux): the mode
 *   and a caller's buffer take effect for the writes that follow, the buffer
 *   pending is written first when the buffer changes, and a mode glibc does
 *   not know is EOF.
 * - A fully buffered write fills the buffer, writes it full, writes whole
 *   blocks straight from the caller and keeps the rest; a line-buffered one
 *   writes through its last newline; an unbuffered one writes at once
 *   (`_IO_new_file_xsputn`). The printf family puts its message the way
 *   glibc's printf buffer does: straight into the stream's buffer while it
 *   has room, otherwise in 128-byte stages through the same put. A write
 *   error surfaces where the bytes are written, sets the stream's error flag
 *   (`ferror`), and empties the buffer (`new_do_write`).
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
 * Each stream carries one recursive lock (glibc's `_IO_lock_t`, which
 * `flockfile` takes too), taken through the scheduler's own mutex so
 * concurrent guest threads queue on it and a flush in progress cannot be
 * overtaken. The flush at the end of the run takes no lock, as glibc's
 * `_IO_cleanup` takes none, and neither does a writer after `main` has
 * returned (patina_internal_lock). Nothing here is recorded: the bytes and
 * the writes they become are a function of the guest's calls.
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
/* glibc's printf staging buffer (`PRINTF_BUFFER_SIZE_TO_FILE_STAGE`). */
#define PATINA_PRINTF_STAGE ((size_t)128)
/* What a put answers when the flush it had to make failed with nothing left
 * to put (libio's EOF through a `size_t`). */
#define PATINA_PUT_EOF ((size_t)-1)

struct patina_stream {
    int fd;
    int unbuffered;  /* _IO_UNBUFFERED */
    int line;        /* _IO_LINE_BUF */
    int putting;     /* _IO_CURRENTLY_PUTTING */
    int error;       /* _IO_ERR_SEEN */
    /* The buffer (`_IO_buf_base`), NULL until one is chosen, and its size. */
    unsigned char *bytes;
    size_t size;
    /* The write area, as offsets into the buffer: whether it is set up
     * (`_IO_write_base` non-NULL), the bytes waiting (`_IO_write_ptr`) and its
     * end (`_IO_write_end`: the buffer's end while fully buffered, its start
     * while line buffered or unbuffered, so every write takes the slow path). */
    int area;
    size_t used;
    size_t end;
    pthread_mutex_t lock;
    unsigned char *storage; /* the buffer `_IO_file_doallocate` gives it */
    unsigned char shortbuf; /* `_shortbuf`, the unbuffered stream's one byte */
};

static unsigned char patina_stdout_bytes[PATINA_STDIO_STORAGE];
static unsigned char patina_stderr_bytes[PATINA_STDIO_STORAGE];
static struct patina_stream patina_stream_stdout = {
    .fd = 1, .lock = PATINA_STREAM_LOCK_INIT, .storage = patina_stdout_bytes};
static struct patina_stream patina_stream_stderr = {
    .fd = 2, .unbuffered = 1, .lock = PATINA_STREAM_LOCK_INIT, .storage = patina_stderr_bytes};

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
 * (`_IO_new_file_write`): the bytes written. A failed write leaves its errno
 * and sets the stream's error flag. Each write is glibc's cancellable one, so
 * the stdio functions are cancellation points exactly where they write. */
static size_t patina_stream_write_out(struct patina_stream *s, const unsigned char *data,
                                      size_t length) {
    size_t done = 0;
    while (done < length) {
        PATINA_CANCEL_POINT("write");
        intptr_t written = patina_write(s->fd, data + done, length - done);
        if (written < 0) {
            errno = patina_errno();
            s->error = 1;
            break;
        }
        done += (size_t)written;
    }
    return done;
}

/* Choose the buffer (`_IO_file_doallocate`, Darwin `__swhatbuf`) from the
 * descriptor's fstat answer. The captured streams have no node, so fstat
 * answers EBADF for them where the host's pipe or terminal would answer: the
 * size falls back as for a failed fstat, and errno stays as the caller left
 * it, as it does over the host's descriptor. */
static void patina_stream_doallocate(struct patina_stream *s) {
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
    s->bytes = s->storage;
    s->size = size <= PATINA_STDIO_STORAGE ? size : PATINA_STDIO_STORAGE;
}

/* `_IO_doallocbuf`: the chosen buffer, or the one-byte `_shortbuf` when the
 * stream is unbuffered. */
static void patina_stream_doallocbuf(struct patina_stream *s) {
    if (s->bytes != NULL) return;
    if (!s->unbuffered) {
        patina_stream_doallocate(s);
        return;
    }
    s->bytes = &s->shortbuf;
    s->size = 1;
}

/* `new_do_write`: write `length` bytes and empty the buffer, whatever the
 * write did; the bytes written. */
static size_t patina_stream_new_do_write(struct patina_stream *s, const unsigned char *data,
                                         size_t length) {
    size_t count = patina_stream_write_out(s, data, length);
    s->area = 1;
    s->used = 0;
    s->end = s->line || s->unbuffered ? 0 : s->size;
    return count;
}

/* `_IO_do_write`: 0, or EOF when fewer than `length` bytes were written. */
static int patina_stream_do_write(struct patina_stream *s, const unsigned char *data,
                                  size_t length) {
    return length == 0 || patina_stream_new_do_write(s, data, length) == length ? 0 : EOF;
}

/* `_IO_do_flush`: write what the buffer holds. */
static int patina_stream_do_flush(struct patina_stream *s) {
    return patina_stream_do_write(s, s->bytes, s->used);
}

/* `_IO_new_file_overflow`: set up the write area if the stream is not yet
 * writing, then flush (`byte` EOF) or put one byte, writing the buffer when
 * it is full, and after the byte when the stream is unbuffered or the byte
 * ends a line of a line-buffered one. The byte, or EOF. */
static int patina_stream_overflow(struct patina_stream *s, int byte) {
    if (!s->putting || !s->area) {
        if (!s->area) patina_stream_doallocbuf(s);
        s->area = 1;
        s->used = 0;
        s->end = s->line || s->unbuffered ? 0 : s->size;
        s->putting = 1;
    }
    if (byte == EOF) return patina_stream_do_flush(s);
    if (s->used == s->size && patina_stream_do_flush(s) == EOF) return EOF;
    s->bytes[s->used++] = (unsigned char)byte;
    if ((s->unbuffered || (s->line && byte == '\n')) && patina_stream_do_flush(s) == EOF) {
        return EOF;
    }
    return (unsigned char)byte;
}

/* Room in the write area (`_IO_write_end - _IO_write_ptr`). */
static size_t patina_stream_room(const struct patina_stream *s) {
    return s->area && s->end > s->used ? s->end - s->used : 0;
}

/* `_IO_default_xsputn`: fill the write area, one byte through overflow when
 * it has no room; how many bytes it took. */
static size_t patina_stream_default_put(struct patina_stream *s, const unsigned char *data,
                                        size_t length) {
    size_t more = length;
    for (;;) {
        size_t count = patina_stream_room(s);
        if (count > more) count = more;
        memcpy(s->bytes + s->used, data, count);
        s->used += count;
        data += count;
        more -= count;
        if (more == 0 || patina_stream_overflow(s, *data++) == EOF) break;
        more--;
    }
    return length - more;
}

/* `_IO_new_file_xsputn`: how many bytes it took, or PATINA_PUT_EOF when all
 * of them were taken but the flush a line demanded failed. */
static size_t patina_stream_put(struct patina_stream *s, const unsigned char *data,
                                size_t length) {
    size_t to_do = length;
    int must_flush = 0;
    size_t count = 0;
    if (length == 0) return 0;
    if (s->line && s->putting) {
        count = s->size - s->used;
        if (count >= length) {
            for (const unsigned char *at = data + length; at > data;) {
                if (*--at == '\n') {
                    count = (size_t)(at - data) + 1;
                    must_flush = 1;
                    break;
                }
            }
        }
    } else {
        count = patina_stream_room(s);
    }
    if (count > 0) {
        if (count > to_do) count = to_do;
        memcpy(s->bytes + s->used, data, count);
        s->used += count;
        data += count;
        to_do -= count;
    }
    if (to_do + (size_t)must_flush > 0) {
        if (patina_stream_overflow(s, EOF) == EOF) {
            return to_do == 0 ? PATINA_PUT_EOF : length - to_do;
        }
        /* Whole blocks go straight to the descriptor. */
        size_t block = s->size;
        size_t direct = to_do - (block >= 128 ? to_do % block : 0);
        if (direct != 0) {
            size_t written = patina_stream_new_do_write(s, data, direct);
            to_do -= written;
            if (written < direct) return length - to_do;
        }
        if (to_do != 0) to_do -= patina_stream_default_put(s, data + direct, to_do);
    }
    return length - to_do;
}

/* `_IO_putc_unlocked`: the byte, or EOF. */
static int patina_stream_putc(struct patina_stream *s, unsigned char byte) {
    if (patina_stream_room(s) == 0) return patina_stream_overflow(s, byte);
    s->bytes[s->used++] = byte;
    return byte;
}

/* `_IO_new_file_sync`: write what is pending: 0, or EOF. */
static int patina_stream_sync(struct patina_stream *s) {
    if (s->area && s->used > 0 && patina_stream_do_flush(s) != 0) return EOF;
    return 0;
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
    size_t used = s->area ? s->used : 0;
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

/* glibc's fwrite answers every item when the put took everything, including
 * the put whose closing line flush failed: the bytes are in the buffer. */
size_t fwrite(const void *pointer, size_t size, size_t count, FILE *stream) {
    struct patina_stream *s = patina_stream_of(stream, "fwrite");
    size_t request = size * count;
    if (request == 0) {
        return 0;
    }
    int held = patina_stream_lock(s);
    size_t taken = patina_stream_put(s, (const unsigned char *)pointer, request);
    patina_stream_unlock(s, held);
    return taken == request || taken == PATINA_PUT_EOF ? count : taken / size;
}

/* Put a formatted message as glibc's printf buffer does
 * (`__printf_buffer_to_file`): straight into the stream's write area while it
 * has room (the byte after a full area going through overflow, which writes
 * the buffer), otherwise in stages of up to 128 bytes put through
 * `_IO_sputn`; whether all of it was taken. */
static int patina_stream_put_formatted(struct patina_stream *s, const unsigned char *data,
                                       size_t length) {
    size_t at = 0;
    while (at < length) {
        size_t room = patina_stream_room(s);
        if (room > 0) {
            size_t count = length - at < room ? length - at : room;
            memcpy(s->bytes + s->used, data + at, count);
            s->used += count;
            at += count;
            if (at < length && patina_stream_room(s) == 0 &&
                patina_stream_overflow(s, data[at++]) == EOF) {
                return 0;
            }
        } else {
            size_t count =
                length - at < PATINA_PRINTF_STAGE ? length - at : PATINA_PRINTF_STAGE;
            if (patina_stream_put(s, data + at, count) != count) return 0;
            at += count;
        }
    }
    return 1;
}

/* Shared printf-family engine: format once into a stack buffer (heap fallback
 * for the rare long message, sized from the vsnprintf length probe), then put
 * the message into the stream under its lock: its length, or -1 when a write
 * failed. */
static int patina_stream_vprintf(struct patina_stream *s, const char *format,
                                 va_list arguments) {
    char stack[512];
    char *message = stack;
    va_list second;
    va_copy(second, arguments);
    int needed = vsnprintf(stack, sizeof stack, format, arguments);
    if (needed >= 0 && (size_t)needed >= sizeof stack) {
        message = malloc((size_t)needed + 1);
        if (message == NULL) {
            va_end(second);
            errno = ENOMEM;
            return -1;
        }
        needed = vsnprintf(message, (size_t)needed + 1, format, second);
    }
    va_end(second);
    if (needed > 0) {
        int held = patina_stream_lock(s);
        if (!patina_stream_put_formatted(s, (const unsigned char *)message, (size_t)needed)) {
            needed = -1;
        }
        patina_stream_unlock(s, held);
    }
    if (message != stack) free(message);
    return needed;
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

#ifndef __APPLE__
/* Put a formatted message into a stream (the printf family's engine). */
static int patina_stream_printf(struct patina_stream *s, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    int written = patina_stream_vprintf(s, format, arguments);
    va_end(arguments);
    return written;
}

/*
 * glibc's `assert()` failure hook (assert/assert.c `__assert_fail_base`,
 * glibc 2.39): "PROGRAM: FILE:LINE: FUNCTION: Assertion `EXPR' failed." put
 * into stderr (one write, the stream being unbuffered), PROGRAM the basename
 * of argv[0] (`__progname`; with no program name the prefix and its separator
 * are left out, and so is FUNCTION's when there is none), then `abort()`:
 * SIGABRT through the virtual kernel, so a handler runs and the default action
 * finalizes the trace. What stdout buffered is lost, as glibc's abort loses
 * it. glibc's own hook would write through its stderr, which is not this
 * stream: the `stderr` global names the sentinel.
 */
_Noreturn void __assert_fail(const char *assertion, const char *file, unsigned int line,
                             const char *function) {
    const char *program = patina_program_path != NULL ? patina_program_path : "";
    const char *slash = strrchr(program, '/');
    if (slash != NULL) program = slash + 1;
    (void)patina_stream_printf(&patina_stream_stderr, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
                               program, program[0] != '\0' ? ": " : "", file, line,
                               function != NULL ? function : "", function != NULL ? ": " : "",
                               assertion);
    patina_abort();
}
#endif

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

/* The error flag a failed write sets (`_IO_ERR_SEEN`), read and cleared under
 * the stream's lock (libio/ferror.c, clearerr.c). The parenthesized names keep
 * a libc macro of the same name from expanding here. */
int (ferror)(FILE *stream) {
    struct patina_stream *s = patina_stream_of(stream, "ferror");
    int held = patina_stream_lock(s);
    int result = s->error;
    patina_stream_unlock(s, held);
    return result;
}

void (clearerr)(FILE *stream) {
    struct patina_stream *s = patina_stream_of(stream, "clearerr");
    int held = patina_stream_lock(s);
    s->error = 0;
    patina_stream_unlock(s, held);
}

/* The stream's own recursive lock, held across calls (`_IO_flockfile`); the
 * stream's writers take it again inside. After `main` returns neither takes
 * it (patina_internal_lock). */
void (flockfile)(FILE *stream) {
    (void)patina_stream_lock(patina_stream_of(stream, "flockfile"));
}

void (funlockfile)(FILE *stream) {
    struct patina_stream *s = patina_stream_of(stream, "funlockfile");
    patina_stream_unlock(s, !patina_in_teardown());
}

#ifndef __APPLE__
/* `_IO_new_file_setbuf`: write what is pending, then take `buffer` (NULL or
 * empty: the one-byte `_shortbuf`, unbuffered) with an empty write area. 0,
 * or EOF when the pending write failed. */
static int patina_stream_setbuf(struct patina_stream *s, unsigned char *buffer, size_t size) {
    if (patina_stream_sync(s) == EOF) return EOF;
    if (buffer == NULL || size == 0) {
        s->unbuffered = 1;
        s->bytes = &s->shortbuf;
        s->size = 1;
    } else {
        s->unbuffered = 0;
        s->bytes = buffer;
        s->size = size;
    }
    s->area = 1;
    s->used = 0;
    s->end = 0;
    return 0;
}

/* glibc's setvbuf (libio/iosetvbuf.c): `_IOFBF` clears line and unbuffered
 * mode (choosing the buffer now when there is none and no caller buffer),
 * `_IOLBF` sets line mode, `_IONBF` makes the stream unbuffered; a caller's
 * buffer (and `_IONBF`) replaces the stream's after the pending bytes are
 * written. EOF for any other mode, or when that write fails. */
static int patina_stream_setvbuf(struct patina_stream *s, unsigned char *buffer, int mode,
                                 size_t size) {
    int held = patina_stream_lock(s);
    int result = 0;
    switch (mode) {
        case _IOFBF:
            s->line = 0;
            s->unbuffered = 0;
            if (buffer == NULL) {
                if (s->bytes == NULL) patina_stream_doallocate(s);
                goto out;
            }
            break;
        case _IOLBF:
            s->unbuffered = 0;
            s->line = 1;
            if (buffer == NULL) goto out;
            break;
        case _IONBF:
            s->line = 0;
            s->unbuffered = 1;
            buffer = NULL;
            size = 0;
            break;
        default:
            result = EOF;
            goto out;
    }
    result = patina_stream_setbuf(s, buffer, size);
out:
    patina_stream_unlock(s, held);
    return result;
}

/* glibc's setbuffer (libio/iosetbuffer.c): fully buffered in `buffer`, or
 * unbuffered for NULL. */
static void patina_stream_setbuffer(struct patina_stream *s, unsigned char *buffer,
                                    size_t size) {
    int held = patina_stream_lock(s);
    s->line = 0;
    (void)patina_stream_setbuf(s, buffer, buffer == NULL ? 0 : size);
    patina_stream_unlock(s, held);
}

int setvbuf(FILE *restrict stream, char *restrict buffer, int mode, size_t size) {
    return patina_stream_setvbuf(patina_stream_of(stream, "setvbuf"), (unsigned char *)buffer,
                                 mode, size);
}

void setbuffer(FILE *stream, char *buffer, size_t size) {
    patina_stream_setbuffer(patina_stream_of(stream, "setbuffer"), (unsigned char *)buffer, size);
}

/* glibc's setbuf: setbuffer with BUFSIZ bytes. */
void setbuf(FILE *restrict stream, char *restrict buffer) {
    patina_stream_setbuffer(patina_stream_of(stream, "setbuf"), (unsigned char *)buffer, BUFSIZ);
}

/* glibc's setlinebuf: setvbuf's line mode, no caller buffer. */
void setlinebuf(FILE *stream) {
    (void)patina_stream_setvbuf(patina_stream_of(stream, "setlinebuf"), NULL, _IOLBF, 0);
}
#endif
