/* The plants of a shim built with `planted-faults`, by argv[1].
 *
 * A fault in the shim's own code, planted in a shim entry, while the guest has
 * its own handler for the signal. The fault is the shim's: a named stop that
 * takes the default action, never the guest's handler (which would exit 97).
 * Cases: `segv` (an unmapped address), `bus` (a file mapping past the file's
 * end) and `ill` (an illegal instruction), on every Linux arch.
 *
 * Shim code reaching the shim's own boundary from inside a dispatch: the
 * program arms the plant, then makes a system call of its own whose dispatch
 * makes one of the shim's own: through syscall(2), a held libc door
 * (argv[2] `held`), or through prctl(2), an entry that dispatches with no
 * hold around it (`unheld`). In `door` the shim's call is syscall(2), which
 * binds to the shim's own door, as std's futex-based locks and once-cells do
 * when they wait or wake. The shim's call is a named stop before it is
 * serviced: serviced, it would write PATINA_PLANTED_SERVICED, and the program
 * would exit 98.
 *
 * `budget` runs the private signal stack's budget report, linked in from
 * `private_budget.c`. */
#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

unsigned char patina_planted_fault(int kind);
unsigned char patina_planted_reentry(int kind);
int private_budget(void);

static int reentry(const char *door, const char *outer) {
    assert(strcmp(door, "door") == 0);
    patina_planted_reentry(0);
    if (strcmp(outer, "held") == 0) {
        syscall(SYS_getpid);
    } else {
        assert(strcmp(outer, "unheld") == 0);
        prctl(PR_GET_DUMPABLE);
    }
    return 98;
}

static void hijacked(int sig) {
    (void)sig;
    _exit(97);
}

int main(int argc, char **argv) {
    assert(argc >= 2);
    if (strcmp(argv[1], "budget") == 0) return private_budget();
    if (argc == 3) return reentry(argv[1], argv[2]);
    static const struct {
        const char *name;
        int sig;
    } kinds[] = {{"segv", SIGSEGV}, {"bus", SIGBUS}, {"ill", SIGILL}};
    int kind = 0;
    while (strcmp(argv[1], kinds[kind].name) != 0) {
        kind++;
        assert(kind < (int)(sizeof kinds / sizeof kinds[0]));
    }
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = hijacked;
    sigemptyset(&action.sa_mask);
    assert(sigaction(kinds[kind].sig, &action, NULL) == 0);
    patina_planted_fault(kind);
    return 98;
}
