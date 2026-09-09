/*
 * Captured stdio: the sentinel FILE handles and the printf family.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

/*
 * libc `FILE*` stdio, deterministic sink edition. mimalloc and aws-lc write
 * warnings/errors through `fputs`/`fprintf`/`fwrite` to `stdout`/`stderr`
 * (`__stdoutp`/`__stderrp` on Darwin). Define the two stream globals as
 * shim-owned SENTINELS pointing at opaque static storage, and interpose the
 * three FILE* writers to route a sentinel stream to the deterministic captured
 * stdio (fd 1 / fd 2) via patina_stdio_write. The guest never dereferences the
 * sentinel: pointer identity alone selects the descriptor. A NON-sentinel FILE*
 * reaching an interposer means an un-interposed `fopen` leaked a real host
 * stream through, so it fails closed LOUDLY (flush + abort naming the symbol),
 * the patina_process_trap shape. Being strong defs, the guest's references bind
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

/* Map a stream to its guest descriptor NUMBER: 1 for the stdout sentinel, 2 for
 * the stderr sentinel, -1 for any other (a leaked host FILE*). The writers go
 * through patina_write on that number, so `printf` after `dup2(file, 1)` lands
 * in the file exactly as it does under a kernel; the trap diagnostic below goes
 * to the captured-stderr sink directly, as every runtime diagnostic does. */
static int patina_sentinel_fd(FILE *stream) {
    if (stream == &patina_sentinel_stdout_storage) {
        return 1;
    }
    if (stream == &patina_sentinel_stderr_storage) {
        return 2;
    }
    return -1;
}

__attribute__((noreturn)) static void patina_stdio_trap(const char *symbol) {
    static const char prefix[] = "patina: stdio call on a non-sentinel FILE* reached under patina: ";
    (void)patina_stdio_write(2, prefix, sizeof prefix - 1);
    (void)patina_stdio_write(2, symbol, strlen(symbol));
    static const char suffix[] =
        "; a host FILE* means an un-interposed fopen leaked through; failing closed\n";
    (void)patina_stdio_write(2, suffix, sizeof suffix - 1);
    patina_flush_captured_stdio();
    abort();
}

int fputs(const char *string, FILE *stream) {
    int fd = patina_sentinel_fd(stream);
    if (fd < 0) {
        patina_stdio_trap("fputs");
    }
    /* `string` is declared nonnull by libc (a NULL compare is -Werror under
     * gcc), so the contract is trusted, the gethostname/getpwuid_r precedent. */
    if (patina_write(fd, string, strlen(string)) < 0) {
        return EOF;
    }
    return 0;
}

size_t fwrite(const void *pointer, size_t size, size_t count, FILE *stream) {
    int fd = patina_sentinel_fd(stream);
    if (fd < 0) {
        patina_stdio_trap("fwrite");
    }
    if (size == 0 || count == 0) {
        return 0;
    }
    intptr_t written = patina_write(fd, pointer, size * count);
    if (written < 0) {
        return 0;
    }
    return (size_t)written / size;
}

/* Shared printf-family engine: format once into a stack buffer (heap fallback
 * for the rare long message, sized from the vsnprintf length probe), then write
 * once to the captured descriptor. */
static int patina_stream_vprintf(int fd, const char *format, va_list arguments) {
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
        (void)patina_write(fd, stack, (size_t)needed);
        return needed;
    }
    char *heap = malloc((size_t)needed + 1);
    if (heap == NULL) {
        va_end(second);
        errno = ENOMEM;
        return -1;
    }
    int written = vsnprintf(heap, (size_t)needed + 1, format, second);
    va_end(second);
    if (written > 0) {
        (void)patina_write(fd, heap, (size_t)written);
    }
    free(heap);
    return written;
}

int vfprintf(FILE *stream, const char *format, va_list arguments) {
    int fd = patina_sentinel_fd(stream);
    if (fd < 0) {
        patina_stdio_trap("vfprintf");
    }
    return patina_stream_vprintf(fd, format, arguments);
}

int fprintf(FILE *stream, const char *format, ...) {
    int fd = patina_sentinel_fd(stream);
    if (fd < 0) {
        patina_stdio_trap("fprintf");
    }
    va_list arguments;
    va_start(arguments, format);
    int written = patina_stream_vprintf(fd, format, arguments);
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
    int written = patina_stream_vprintf(1, format, arguments);
    va_end(arguments);
    return written;
}

int puts(const char *string) {
    if (patina_write(1, string, strlen(string)) < 0) {
        return EOF;
    }
    static const char newline = '\n';
    if (patina_write(1, &newline, 1) < 0) {
        return EOF;
    }
    return 0;
}

int putchar(int character) {
    unsigned char byte = (unsigned char)character;
    if (patina_write(1, &byte, 1) < 0) {
        return EOF;
    }
    return byte;
}

int fputc(int character, FILE *stream) {
    int fd = patina_sentinel_fd(stream);
    if (fd < 0) {
        patina_stdio_trap("fputc");
    }
    unsigned char byte = (unsigned char)character;
    if (patina_write(fd, &byte, 1) < 0) {
        return EOF;
    }
    return byte;
}

/* The sentinel streams are unbuffered (every write goes straight to the
 * descriptor), so a flush is always trivially satisfied. NULL means
 * "flush everything" and is equally a no-op. */
int fflush(FILE *stream) {
    if (stream != NULL && patina_sentinel_fd(stream) < 0) {
        patina_stdio_trap("fflush");
    }
    return 0;
}
