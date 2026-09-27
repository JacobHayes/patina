/* Class pairing: a fault in the shim's own code, planted in a shim entry (the
 * shim built with `planted-faults`), while the guest has its own handler for
 * the signal. The fault is the shim's: a named stop that takes the default
 * action, never the guest's handler (which would exit 97). Cases: `segv` (an
 * unmapped address), `bus` (a file mapping past the file's end) and `ill` (an
 * illegal instruction), on every Linux arch. */
#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

unsigned char patina_planted_fault(int kind);

static void hijacked(int sig) {
    (void)sig;
    _exit(97);
}

int main(int argc, char **argv) {
    assert(argc == 2);
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
