/* BTI: built with -mbranch-protection=standard and without the C library's start files (Ubuntu
 * 24.04's are not BTI-marked, so a program linked with them is not marked either): every function
 * starts with a landing pad, and the file is marked. Built static (bti-static) and dynamic
 * (bti-dyn: linked against libc, whose loader maps it, and makes its text PROT_BTI where the CPU
 * has BTI). System calls are made directly.
 * bti: an indirect call to `spin`, whose `isb` is a pause site; prints "spin 45".
 * bti violate: an indirect call to `bare`, written without a landing pad, which starts with an
 *   `isb`: in a guarded page that is a branch-target fault (SIGILL) before the `isb` runs,
 *   patched or not; elsewhere it prints "bare 07". */
__asm__(".text\n"
        ".balign 4\n"
        ".global _start\n"
        ".type _start, %function\n"
        "_start:\n"
        "\tbti jc\n"
        "\tmov x0, sp\n"
        "\tbl cmain\n"
        "\tbrk #0\n"
        ".global bare\n"
        ".type bare, %function\n"
        "bare:\n"
        "\tisb\n"
        "\tmov x0, #7\n"
        "\tret\n"
        ".size bare, .-bare\n");
long bare(void);

static long sys3(long n, long a, long b, long c) {
    register long x8 __asm__("x8") = n, x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

static void say(const char *what, long v) {
    char b[32];
    int n = 0;
    while (what[n]) b[n] = what[n], n++;
    b[n++] = ' ';
    b[n++] = '0' + v / 10 % 10;
    b[n++] = '0' + v % 10;
    b[n++] = '\n';
    sys3(64, 1, (long)b, n);
}

__attribute__((noinline)) static long spin(long n) {
    long s = 0;
    for (long i = 0; i < n; i++) {
        __asm__ volatile("isb");
        s += i;
    }
    return s;
}

__attribute__((noreturn, used)) void cmain(long *sp) {
    long argc = sp[0];
    char **argv = (char **)(sp + 1);
    long (*volatile f)(long) = spin;
    long (*volatile g)(void) = bare;
    if (argc > 1 && argv[1][0] == 'v')
        say("bare", g());
    else
        say("spin", f(10));
    sys3(94, 0, 0, 0); /* exit_group */
    __builtin_unreachable();
}
