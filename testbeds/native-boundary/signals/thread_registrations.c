/* Class pairing: the per-thread kernel registrations the virtual kernel keeps
 * (thread/robust_list conformance covers the rows' answers). Named cases:
 *
 *   robust-exit  a thread registers a robust list holding a futex word it
 *                owns (its tid, with FUTEX_WAITERS) and one another thread
 *                owns, then exits: the kernel walk marks only its own word
 *                FUTEX_OWNER_DIED, keeps the waiters bit, and leaves the other.
 *   robust-wake  a thread exits owning two words with FUTEX_WAITERS, one
 *                waited on with FUTEX_WAIT and one with FUTEX_WAIT_PRIVATE,
 *                and with a pending operation on a zero word another thread
 *                waits on. The walk wakes the shared waiters, which see
 *                FUTEX_OWNER_DIED, and leaves the private one waiting: the
 *                kernel wakes a dead owner's futexes by their shared key.
 *                It prints what each waiter saw.
 *   robust-dtor  a thread-local destructor releases the robust lock its
 *                thread holds: it runs before the thread's exit walks the
 *                list, so it still finds the word its thread owns. It prints
 *                whether it did.
 *   robust-new   get_robust_list of a thread just created, before it has
 *                run, names glibc's head for it (its thread descriptor plus
 *                the offset the main thread's head sits at), as the new
 *                thread itself finds. It prints, per thread, whether both
 *                agree.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define FUTEX_WAITERS 0x80000000u
#define FUTEX_OWNER_DIED 0x40000000u
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_WAIT_PRIVATE (FUTEX_WAIT | 128)
#define FUTEX_WAKE_PRIVATE (FUTEX_WAKE | 128)

struct robust_list {
    struct robust_list *next;
};
struct robust_list_head {
    struct robust_list list;
    long futex_offset;
    struct robust_list *list_op_pending;
};
/* A robust lock as the list links it: the entry, then its futex word. */
struct lock {
    struct robust_list link;
    uint32_t word;
};

static struct lock owned, foreign;
static struct robust_list_head head;
static uint32_t foreign_word;

static void *robust_thread(void *arg) {
    (void)arg;
    uint32_t tid = (uint32_t)syscall(SYS_gettid);
    owned.word = tid | FUTEX_WAITERS;
    foreign.word = foreign_word;
    head.futex_offset = (long)offsetof(struct lock, word);
    head.list_op_pending = NULL;
    head.list.next = &owned.link;
    owned.link.next = &foreign.link;
    foreign.link.next = &head.list;
    assert(syscall(SYS_set_robust_list, &head, sizeof head) == 0);
    return NULL;
}

static long futex(uint32_t *word, int op, uint32_t value) {
    return syscall(SYS_futex, word, op, value, NULL, NULL, 0);
}

/* robust-wake: the owner's list holds two owned words; a third, zero, word
 * is its pending operation. */
static struct lock waited_shared, waited_private, waited_pending;
static struct robust_list_head wake_head;
static uint32_t owner_ready, owner_go;

static void *wake_owner(void *arg) {
    (void)arg;
    uint32_t tid = (uint32_t)syscall(SYS_gettid);
    waited_shared.word = tid | FUTEX_WAITERS;
    waited_private.word = tid | FUTEX_WAITERS;
    waited_pending.word = 0;
    wake_head.futex_offset = (long)offsetof(struct lock, word);
    wake_head.list.next = &waited_shared.link;
    waited_shared.link.next = &waited_private.link;
    waited_private.link.next = &wake_head.list;
    wake_head.list_op_pending = &waited_pending.link;
    assert(syscall(SYS_set_robust_list, &wake_head, sizeof wake_head) == 0);
    __atomic_store_n(&owner_ready, 1, __ATOMIC_SEQ_CST);
    futex(&owner_ready, FUTEX_WAKE_PRIVATE, 1);
    while (!__atomic_load_n(&owner_go, __ATOMIC_SEQ_CST)) futex(&owner_go, FUTEX_WAIT_PRIVATE, 0);
    return NULL;
}

struct waiter {
    uint32_t *word;
    int op;
    uint32_t expected;
    long result;
    uint32_t seen;
};

static void *wait_on(void *arg) {
    struct waiter *waiter = arg;
    waiter->result = futex(waiter->word, waiter->op, waiter->expected);
    waiter->seen = __atomic_load_n(waiter->word, __ATOMIC_SEQ_CST);
    return NULL;
}

static int robust_wake(void) {
    pthread_t owner;
    assert(pthread_create(&owner, NULL, wake_owner, NULL) == 0);
    while (!__atomic_load_n(&owner_ready, __ATOMIC_SEQ_CST)) futex(&owner_ready, FUTEX_WAIT_PRIVATE, 0);
    uint32_t owned_value = waited_shared.word;
    struct waiter waiters[3] = {
        {&waited_shared.word, FUTEX_WAIT, owned_value, 0, 0},
        {&waited_private.word, FUTEX_WAIT_PRIVATE, owned_value, 0, 0},
        {&waited_pending.word, FUTEX_WAIT, 0, 0, 0},
    };
    pthread_t threads[3];
    for (int i = 0; i < 3; i++) assert(pthread_create(&threads[i], NULL, wait_on, &waiters[i]) == 0);
    /* Let every waiter park before the owner exits. */
    struct timespec settle = {0, 20 * 1000 * 1000};
    assert(nanosleep(&settle, NULL) == 0);
    __atomic_store_n(&owner_go, 1, __ATOMIC_SEQ_CST);
    futex(&owner_go, FUTEX_WAKE_PRIVATE, 1);
    assert(pthread_join(owner, NULL) == 0);
    assert(pthread_join(threads[0], NULL) == 0);
    assert(pthread_join(threads[2], NULL) == 0);
    /* The death left the private waiter parked: this wake finds it. */
    long private_left = futex(&waited_private.word, FUTEX_WAKE_PRIVATE, 1);
    assert(pthread_join(threads[1], NULL) == 0);
    printf("shared woken=%d owner_died=%d waiters=%d\n", waiters[0].result == 0,
           (waiters[0].seen & FUTEX_OWNER_DIED) != 0, (waiters[0].seen & FUTEX_WAITERS) != 0);
    printf("pending woken=%d\n", waiters[2].result == 0);
    printf("private left waiting=%ld owner_died=%d\n", private_left,
           (waited_private.word & FUTEX_OWNER_DIED) != 0);
    return 0;
}

/* robust-dtor: the thread holds `held` through its list and releases it in a
 * thread-local destructor, as a C++ `thread_local` guard would. */
extern int __cxa_thread_atexit_impl(void (*destructor)(void *), void *object, void *dso);
extern void *__dso_handle;
static struct lock held;
static struct robust_list_head held_head;
static uint32_t held_owner, released_seen;

static void release_held(void *arg) {
    (void)arg;
    released_seen = held.word;
    held_head.list.next = &held_head.list;
    held.word = 0;
}

static void *dtor_thread(void *arg) {
    (void)arg;
    held_owner = (uint32_t)syscall(SYS_gettid);
    held.word = held_owner;
    held_head.futex_offset = (long)offsetof(struct lock, word);
    held_head.list_op_pending = NULL;
    held_head.list.next = &held.link;
    held.link.next = &held_head.list;
    assert(syscall(SYS_set_robust_list, &held_head, sizeof held_head) == 0);
    assert(__cxa_thread_atexit_impl(release_held, NULL, &__dso_handle) == 0);
    return NULL;
}

static int robust_dtor(void) {
    pthread_t thread;
    assert(pthread_create(&thread, NULL, dtor_thread, NULL) == 0);
    assert(pthread_join(thread, NULL) == 0);
    printf("destructor found its lock held=%d, released=%d\n", released_seen == held_owner,
           held.word == 0);
    return 0;
}

/* robust-new: glibc's head sits at one offset in every thread descriptor. */
#define NEW_THREADS 4
static uintptr_t own_heads[NEW_THREADS];
static uint32_t new_go;

static void *new_thread(void *slot) {
    void *head = NULL;
    size_t len = 0;
    assert(syscall(SYS_get_robust_list, 0, &head, &len) == 0);
    *(uintptr_t *)slot = (uintptr_t)head;
    while (!__atomic_load_n(&new_go, __ATOMIC_SEQ_CST)) futex(&new_go, FUTEX_WAIT_PRIVATE, 0);
    return NULL;
}

static int robust_new(void) {
    void *main_head = NULL;
    size_t len = 0;
    assert(syscall(SYS_get_robust_list, 0, &main_head, &len) == 0);
    uintptr_t offset = (uintptr_t)main_head - (uintptr_t)pthread_self();
    pthread_t threads[NEW_THREADS];
    uintptr_t seen[NEW_THREADS];
    long results[NEW_THREADS];
    for (int i = 0; i < NEW_THREADS; i++) {
        assert(pthread_create(&threads[i], NULL, new_thread, &own_heads[i]) == 0);
        /* Asked at once: the new thread's id is the next one. */
        void *head = NULL;
        results[i] = syscall(SYS_get_robust_list, getpid() + 1 + i, &head, &len);
        seen[i] = (uintptr_t)head;
    }
    __atomic_store_n(&new_go, 1, __ATOMIC_SEQ_CST);
    futex(&new_go, FUTEX_WAKE_PRIVATE, NEW_THREADS);
    for (int i = 0; i < NEW_THREADS; i++) assert(pthread_join(threads[i], NULL) == 0);
    for (int i = 0; i < NEW_THREADS; i++) {
        printf("thread %d: result=%ld glibc_head=%d own_view=%d\n", i, results[i],
               seen[i] == (uintptr_t)threads[i] + offset, seen[i] == own_heads[i]);
    }
    return 0;
}

static int robust_exit(void) {
    /* A tid no thread of the guest has: the main thread's is the pid. */
    foreign_word = (uint32_t)getpid() + 1000;
    pthread_t thread;
    assert(pthread_create(&thread, NULL, robust_thread, NULL) == 0);
    assert(pthread_join(thread, NULL) == 0);
    assert(owned.word == (FUTEX_WAITERS | FUTEX_OWNER_DIED));
    assert(foreign.word == foreign_word);
    puts("ROBUST_EXIT_OK");
    return 0;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    if (strcmp(argv[1], "robust-exit") == 0) return robust_exit();
    if (strcmp(argv[1], "robust-wake") == 0) return robust_wake();
    if (strcmp(argv[1], "robust-dtor") == 0) return robust_dtor();
    if (strcmp(argv[1], "robust-new") == 0) return robust_new();
    fprintf(stderr, "unknown case %s\n", argv[1]);
    return 2;
}
