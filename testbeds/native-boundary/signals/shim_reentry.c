/* Class pairing: shim code reaching the shim's own boundary from inside a
 * dispatch, planted (the shim built with `planted-faults`). The program arms
 * the plant, then makes a system call of its own whose dispatch makes one of
 * the shim's own: through syscall(2), a held libc door (`held`), or through
 * prctl(2), an entry that dispatches with no hold around it (`unheld`). In
 * `door` the shim's call is syscall(2), which binds to the shim's own door,
 * as std's futex-based locks and once-cells do when they wait or wake; in
 * `trap` (x86_64, under syscall-user-dispatch) it is a raw syscall
 * instruction, which traps. Either way the shim's call is a named stop before
 * it is serviced: serviced, it would write PATINA_PLANTED_SERVICED, and the
 * program would exit 98. */
#define _GNU_SOURCE
#include <assert.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

unsigned char patina_planted_reentry(int kind);

int main(int argc, char **argv) {
    assert(argc == 3);
    static const char *const kinds[] = {"door", "trap"};
    int kind = 0;
    while (strcmp(argv[1], kinds[kind]) != 0) {
        kind++;
        assert(kind < (int)(sizeof kinds / sizeof kinds[0]));
    }
    patina_planted_reentry(kind);
    if (strcmp(argv[2], "held") == 0) {
        syscall(SYS_getpid);
    } else {
        assert(strcmp(argv[2], "unheld") == 0);
        prctl(PR_GET_DUMPABLE);
    }
    return 98;
}
