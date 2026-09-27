/* Class pairing: counter containment must not depend on the host's xsave
 * frame size. One kernel frame plus 1536 bytes fits a native handler, but
 * cannot also hold a nested kernel frame below the counter trap's frames.
 * The native leg proves the registered stack actually takes a signal.
 * The shim leg checks both counter instructions and exact stack restoration,
 * then restores the default action and takes a genuine access fault. */
#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static stack_t registered;
static volatile sig_atomic_t on_stack;
static void handler(int sig) {
    char here;
    (void)sig;
    on_stack = (uintptr_t)&here - (uintptr_t)registered.ss_sp < registered.ss_size;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t size = getauxval(AT_MINSIGSTKSZ) + 1536;
    size_t rounded = (size + page - 1) / page * page;
    char *mapping = mmap(NULL, rounded + page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mapping != MAP_FAILED);
    assert(mprotect(mapping + page, rounded, PROT_READ | PROT_WRITE) == 0);
    int autodisarm = strcmp(argv[1], "read-fault-autodisarm") == 0;
    registered = (stack_t){.ss_sp = mapping + page, .ss_size = size,
                           .ss_flags = autodisarm ? (int)(1U << 31) : 0};
    assert(sigaltstack(&registered, NULL) == 0);
    struct sigaction action = {.sa_handler = handler, .sa_flags = SA_ONSTACK};
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGSEGV, &action, NULL) == 0);
    if (strcmp(argv[1], "native-frame") == 0) {
        assert(raise(SIGSEGV) == 0);
        assert(on_stack);
        return 0;
    }
    assert(autodisarm || strcmp(argv[1], "read-fault") == 0);
    struct timespec delay = {.tv_nsec = 5000000};
    assert(nanosleep(&delay, NULL) == 0);
    for (int i = 0; i < 3; ++i) {
        uint32_t lo, hi, aux;
        __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
        assert((((uint64_t)hi << 32) | lo) == 5000000);
        __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
        assert((((uint64_t)hi << 32) | lo) == 5000000 && aux == 0);
        stack_t now;
        assert(sigaltstack(NULL, &now) == 0);
        assert(now.ss_sp == registered.ss_sp && now.ss_size == registered.ss_size &&
               now.ss_flags == registered.ss_flags);
        assert(!on_stack);
    }
    assert(write(1, "COUNTERS ANSWERED\n", 18) == 18);
    action.sa_handler = SIG_DFL;
    action.sa_flags = 0;
    assert(sigaction(SIGSEGV, &action, NULL) == 0);
    *(volatile char *)mapping = 1;
    return 99;
}
