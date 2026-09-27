/* Class pairing: the synchronous signals an instruction raises (SIGBUS,
 * SIGFPE, SIGILL, SIGTRAP), whose host disposition is the shim's fault front
 * handler while the guest's action is virtual. Named cases, run natively as
 * the oracle and under the shim, each printing what the guest saw:
 *
 *   swap-escape  a raised trap signal is dequeued in one delivery batch with
 *                two SA_NODEFER SIGUSR1s whose handler, run first, installs
 *                a new action for it; its frame still runs the action it was
 *                dequeued with, which leaves by siglongjmp. A genuine trap
 *                right after, before anything else, runs the new action,
 *                under the new action's mask;
 *   die-bus      a read past the end of a mapped file (SIGBUS),
 *   die-trap     __builtin_trap,
 *   die-fpe      (x86_64) an integer division by zero (SIGFPE),
 *   die-int3     (x86_64) int3 (SIGTRAP, which resumes past itself): each
 *                under the default action, after the guest wrote a line to
 *                each of its descriptors 1 and 2 and left one in C stdout's
 *                buffer, which a fatal signal loses;
 *   die-blocked  die-bus on a thread that blocks every signal first, whose
 *                fault the kernel takes with no handler at all;
 *   host-pipe    (the supervisor's side is the subject) a SIGPIPE handler
 *                that exits 3, then lines written to descriptor 1 and
 *                "SURVIVED" to 2: natively a stdout whose reader is gone
 *                runs the handler, under the shim that reader is the host's.
 *
 * The trap signal is what __builtin_trap raises: SIGILL on x86_64 (ud2),
 * SIGTRAP on arm64 (brk). */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__x86_64__)
#define TRAP_SIG SIGILL
#else
#define TRAP_SIG SIGTRAP
#endif

static sigjmp_buf first, second, *jump;
static char seen[16];
static volatile sig_atomic_t count;
static void note(char c) {
    seen[count++] = c;
}

static void on_trap_new(int sig) {
    sigset_t now;
    (void)sig;
    note('N');
    assert(sigprocmask(SIG_BLOCK, NULL, &now) == 0);
    note(sigismember(&now, SIGUSR2) ? 'M' : '-');
    siglongjmp(*jump, 1);
}

static void on_trap_old(int sig) {
    (void)sig;
    note('O');
    siglongjmp(*jump, 1);
}

static void install(int sig, void (*handler)(int), int flags, int masked) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = handler;
    action.sa_flags = flags;
    sigemptyset(&action.sa_mask);
    if (masked) sigaddset(&action.sa_mask, SIGUSR2);
    assert(sigaction(sig, &action, NULL) == 0);
}

static void on_usr1(int sig) {
    (void)sig;
    note('u');
    install(TRAP_SIG, on_trap_new, 0, 0);
}

static void swap_escape(void) {
    install(SIGUSR1, on_usr1, SA_NODEFER, 0);
    install(TRAP_SIG, on_trap_old, 0, 1);
    sigset_t both;
    sigemptyset(&both);
    sigaddset(&both, SIGUSR1);
    sigaddset(&both, TRAP_SIG);
    jump = &first;
    if (sigsetjmp(first, 1) == 0) {
        assert(sigprocmask(SIG_BLOCK, &both, NULL) == 0);
        assert(pthread_kill(pthread_self(), SIGUSR1) == 0);
        assert(kill(getpid(), SIGUSR1) == 0);
        assert(raise(TRAP_SIG) == 0);
        assert(sigprocmask(SIG_UNBLOCK, &both, NULL) == 0);
        note('!');
    }
    /* Nothing between the escape and the trap enters the shim. */
    jump = &second;
    if (sigsetjmp(second, 1) == 0) __builtin_trap();
    printf("SWAP %.*s\n", (int)count, seen);
}

static void say(int fd, const char *text) {
    assert(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
}

static void die(const char *how) {
    say(1, "WRITTEN\n");
    say(2, "WRITTEN TO STDERR\n");
    printf("BUFFERED\n");
    if (strcmp(how, "bus") == 0) {
        int fd = memfd_create("short", 0);
        assert(fd >= 0 && ftruncate(fd, 100) == 0);
        volatile char *view = mmap(NULL, 8192, PROT_READ, MAP_SHARED, fd, 0);
        assert(view != MAP_FAILED);
        (void)view[4096];
    } else if (strcmp(how, "trap") == 0) {
        __builtin_trap();
#if defined(__x86_64__)
    } else if (strcmp(how, "fpe") == 0) {
        int low = 1, high = 0, zero = 0;
        __asm__ volatile("idivl %2" : "+a"(low), "+d"(high) : "r"(zero));
    } else if (strcmp(how, "int3") == 0) {
        __asm__ volatile("int3");
#endif
    }
    say(1, "SURVIVED\n");
}

static void on_pipe(int sig) {
    (void)sig;
    say(2, "GUEST SIGPIPE\n");
    _exit(3);
}

static void host_pipe(void) {
    install(SIGPIPE, on_pipe, 0, 0);
    for (int i = 0; i < 4; i++) say(1, "LINE\n");
    say(2, "SURVIVED\n");
}

static void *die_blocked(void *unused) {
    (void)unused;
    sigset_t all;
    sigfillset(&all);
    assert(pthread_sigmask(SIG_BLOCK, &all, NULL) == 0);
    die("bus");
    return NULL;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    if (strcmp(argv[1], "swap-escape") == 0) {
        swap_escape();
    } else if (strcmp(argv[1], "host-pipe") == 0) {
        host_pipe();
    } else if (strcmp(argv[1], "die-blocked") == 0) {
        pthread_t thread;
        assert(pthread_create(&thread, NULL, die_blocked, NULL) == 0);
        assert(pthread_join(thread, NULL) == 0);
    } else if (strncmp(argv[1], "die-", 4) == 0) {
        die(argv[1] + 4);
    } else {
        fprintf(stderr, "unknown case %s\n", argv[1]);
        return 2;
    }
    puts("FAULT_ROUTING_OK");
    return 0;
}
