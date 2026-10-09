/* The assertion abort door stays C: formatting returns before guest SIGABRT
 * delivery, and guest panic ownership must reach patina_abort unchanged. */
#ifndef __APPLE__
/* The shim's stdout and stderr objects (src/posix/stdio.rs `Sentinel`) are
 * FILE-sized, so a guest's inline putc_unlocked/getc_unlocked bodies read
 * zeroed buffer pointers inside them and fall to __overflow/__uflow. */
_Static_assert(sizeof(FILE) == 216, "the stream sentinels are sized for glibc's FILE");

extern int patina_stream_printf(FILE *stream, const char *format, ...);
/* The program's argv[0] (src/posix/lifecycle/linux.rs). */
extern __attribute__((visibility("hidden"))) const char *patina_program_path;

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
    (void)patina_stream_printf(stderr, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
                               program, program[0] != '\0' ? ": " : "", file, line,
                               function != NULL ? function : "", function != NULL ? ": " : "",
                               assertion);
    patina_abort();
}
#endif

