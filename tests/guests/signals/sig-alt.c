// The guest's alternate stack. A handler with SA_ONSTACK runs on the stack the
// guest set with sigaltstack and sees SS_ONSTACK; without SA_ONSTACK it runs on the
// thread's stack; the query returns what was set; changing it while on it is EPERM;
// SS_AUTODISARM disarms it during the handler. Also in a second thread with its own stack.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef SS_AUTODISARM
#define SS_AUTODISARM (1U << 31)
#endif

#define ALT (64 * 1024)
static char *alt_main, *alt_thr;
static volatile uintptr_t h_sp;
static volatile int h_flags, h_eperm, h_autodisarm_flags;

static void on_sig(int sig) {
    char local;
    h_sp = (uintptr_t)&local;
    stack_t cur;
    sigaltstack(NULL, &cur);
    h_flags = cur.ss_flags;
    h_eperm = 0;
    if (cur.ss_flags & SS_ONSTACK) {
        stack_t other = {.ss_sp = malloc(ALT), .ss_size = ALT, .ss_flags = 0};
        h_eperm = sigaltstack(&other, NULL) == -1 && errno == EPERM;
    }
    (void)sig;
}

static void on_autodisarm(int sig) {
    stack_t cur;
    sigaltstack(NULL, &cur);
    h_autodisarm_flags = cur.ss_flags;
    (void)sig;
}

static void set(int sig, void (*h)(int), int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
}

static int inside(uintptr_t p, char *base, size_t n) {
    return p >= (uintptr_t)base && p < (uintptr_t)base + n;
}

static void probe(const char *who, char *alt) {
    char here;
    // Query before anything is set: disabled.
    stack_t q;
    sigaltstack(NULL, &q);
    printf("%s initial disabled=%d\n", who, (q.ss_flags & SS_DISABLE) != 0);
    stack_t ss = {.ss_sp = alt, .ss_size = ALT, .ss_flags = 0};
    sigaltstack(&ss, NULL);
    sigaltstack(NULL, &q);
    printf("%s query sp_ok=%d size=%zu flags=%d\n", who, q.ss_sp == alt, q.ss_size, q.ss_flags);

    set(SIGUSR1, on_sig, SA_ONSTACK);
    raise(SIGUSR1);
    printf("%s onstack in_alt=%d ss_onstack=%d eperm=%d\n", who, inside(h_sp, alt, ALT), (h_flags & SS_ONSTACK) != 0, h_eperm);

    set(SIGUSR1, on_sig, 0);
    raise(SIGUSR1);
    long d = (long)((uintptr_t)&here - h_sp);
    printf("%s plain in_alt=%d on_thread_stack=%d ss_onstack=%d\n", who, inside(h_sp, alt, ALT), d > 0 && d < 65536,
           (h_flags & SS_ONSTACK) != 0);

    // SS_AUTODISARM: inside the handler the stack reads as disabled; restored afterwards.
    stack_t ad = {.ss_sp = alt, .ss_size = ALT, .ss_flags = SS_AUTODISARM};
    sigaltstack(&ad, NULL);
    set(SIGUSR2, on_autodisarm, SA_ONSTACK);
    raise(SIGUSR2);
    sigaltstack(NULL, &q);
    printf("%s autodisarm in_handler_disabled=%d after_sp_ok=%d after_autodisarm=%d\n", who,
           (h_autodisarm_flags & SS_DISABLE) != 0, q.ss_sp == alt, (q.ss_flags & SS_AUTODISARM) != 0);
}

static void *thr(void *a) {
    (void)a;
    probe("thread", alt_thr);
    return NULL;
}

int main(void) {
    alt_main = malloc(ALT);
    alt_thr = malloc(ALT);
    probe("main", alt_main);
    pthread_t t;
    pthread_create(&t, NULL, thr, NULL);
    pthread_join(t, NULL);
    return 0;
}
