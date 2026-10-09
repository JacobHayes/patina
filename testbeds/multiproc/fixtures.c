#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/futex.h>
#include <sys/syscall.h>
#endif

#define CHECK(condition) do { if (!(condition)) { \
    ssize_t diagnostic = write(2, "process invariant failed\n", 25); (void)diagnostic; \
    return 1; } } while (0)
#define CHILD(condition) do { if (!(condition)) _exit(91); } while (0)
#define HELPER static __attribute__((unused))

HELPER int reaped(pid_t child, int code) {
    int status = 0;
    return waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == code;
}
HELPER volatile sig_atomic_t delivered;
HELPER void note_signal(int sig) { (void)sig; delivered = 1; }
HELPER volatile sig_atomic_t group_pid, reaped_pid, reaped_status, timed_out;
HELPER void child_notice(int sig) {
    (void)sig;
    int saved = errno, status;
    pid_t child;
    while ((child = waitpid(-1, &status, WNOHANG)) > 0) {
        reaped_pid = child;
        reaped_status = status;
    }
    errno = saved;
}
HELPER void group_timeout(int sig) {
    (void)sig;
    int saved = errno;
    if (kill(-group_pid, SIGKILL) == 0) timed_out = 1;
    errno = saved;
}
HELPER pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
HELPER void prepare(void) {}
HELPER void unlock(void) { if (pthread_mutex_unlock(&lock) != 0) _exit(92); }
struct exec_peer { int request, reply; };
HELPER int peer_completed;
HELPER void *exec_sibling(void *opaque) {
    struct exec_peer *peer = opaque;
    char byte;
    CHILD(read(peer->request, &byte, 1) == 1 && byte == 'p');
    CHILD(write(peer->reply, "r", 1) == 1);
    CHILD(read(peer->request, &byte, 1) == 1 && byte == 'v');
    CHILD(write(peer->reply, "t", 1) == 1);
    return &peer_completed;
}

int multiproc_fixture(const char *dir) {
    (void)dir;
#if defined(PATINA_MP_FIXTURE_FORKWAIT_C)
    for (int test = 0; test < 2; ++test) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            if (test == 0) _exit(37);
            struct rlimit core = {0, 0};
            CHILD(setrlimit(RLIMIT_CORE, &core) == 0);
            abort();
        }
        int status;
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(test == 0 ? WIFEXITED(status) && WEXITSTATUS(status) == 37
                        : WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    }
#elif defined(PATINA_MP_FIXTURE_SIGCHLD)
    struct sigaction action = {0};
    CHECK(sigemptyset(&action.sa_mask) == 0);
    action.sa_handler = child_notice;
    CHECK(sigaction(SIGCHLD, &action, NULL) == 0);
    action.sa_handler = group_timeout;
    CHECK(sigaction(SIGALRM, &action, NULL) == 0);
    sigset_t blocked, previous;
    CHECK(sigemptyset(&blocked) == 0 && sigaddset(&blocked, SIGCHLD) == 0);
    CHECK(sigaddset(&blocked, SIGALRM) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &blocked, &previous) == 0);
    int ready[2];
    CHECK(pipe(ready) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        CHILD(setpgid(0, 0) == 0 && close(ready[0]) == 0);
        CHILD(write(ready[1], "r", 1) == 1 && close(ready[1]) == 0);
        for (;;) pause();
    }
    CHECK(close(ready[1]) == 0);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && close(ready[0]) == 0);
    group_pid = child;
    alarm(1);
    while (reaped_pid != child) sigsuspend(&previous);
    CHECK(timed_out == 1 && WIFSIGNALED(reaped_status) && WTERMSIG(reaped_status) == SIGKILL);
    CHECK(sigprocmask(SIG_SETMASK, &previous, NULL) == 0);
#elif defined(PATINA_MP_FIXTURE_FAILED_EXEC_ENOENT) || defined(PATINA_MP_FIXTURE_FAILED_EXEC_EACCES) || defined(PATINA_MP_FIXTURE_FAILED_EXEC_E2BIG)
    int preserved[2], request[2], reply[2];
    CHECK(pipe(preserved) == 0 && pipe(request) == 0 && pipe(reply) == 0);
    CHECK(fcntl(preserved[0], F_SETFD, FD_CLOEXEC) == 0);
    CHECK(fcntl(preserved[1], F_SETFD, FD_CLOEXEC) == 0);
    struct sigaction action = {0}, previous;
    action.sa_handler = note_signal;
    action.sa_flags = SA_RESTART;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaddset(&action.sa_mask, SIGUSR2) == 0);
    CHECK(sigaction(SIGUSR1, &action, &previous) == 0);
    struct exec_peer peer = {.request = request[0], .reply = reply[1]};
    pthread_t sibling;
    CHECK(pthread_create(&sibling, NULL, exec_sibling, &peer) == 0);
    char byte;
    CHECK(write(request[1], "p", 1) == 1 && read(reply[0], &byte, 1) == 1 && byte == 'r');
    char path[4096];
    CHECK(snprintf(path, sizeof(path), "%s/exec-image", dir) > 0);
#if !defined(PATINA_MP_FIXTURE_FAILED_EXEC_E2BIG)
    char *argv[] = {path, NULL};
#endif
#if defined(PATINA_MP_FIXTURE_FAILED_EXEC_ENOENT)
    CHECK(unlink(path) == 0 || errno == ENOENT);
    CHECK(execvp(path, argv) == -1 && errno == ENOENT);
#elif defined(PATINA_MP_FIXTURE_FAILED_EXEC_EACCES)
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    CHECK(fd >= 0 && write(fd, "not executable", 14) == 14 && close(fd) == 0);
    CHECK(chmod(path, 0600) == 0);
    CHECK(execvp(path, argv) == -1 && errno == EACCES);
    CHECK(unlink(path) == 0);
#else
    // Linux MAX_ARG_STRLEN and Darwin ARG_MAX both sit below this single arg.
    char *huge = malloc(8 * 1024 * 1024);
    CHECK(huge != NULL);
    memset(huge, 'x', 8 * 1024 * 1024 - 1);
    huge[8 * 1024 * 1024 - 1] = 0;
    char *big_argv[] = {"/proc/self/exe", huge, NULL};
    CHECK(execvp(big_argv[0], big_argv) == -1 && errno == E2BIG);
    free(huge);
#endif
    // Failed exec must preserve the old image, not perform destructive commit
    // preparation: CLOEXEC fds, caught dispositions and a parked sibling survive.
    CHECK(fcntl(preserved[0], F_GETFD) == FD_CLOEXEC);
    CHECK(fcntl(preserved[1], F_GETFD) == FD_CLOEXEC);
    CHECK(write(preserved[1], "f", 1) == 1 && read(preserved[0], &byte, 1) == 1 && byte == 'f');
    CHECK(sigaction(SIGUSR1, NULL, &action) == 0 && action.sa_handler == note_signal);
    CHECK((action.sa_flags & SA_RESTART) != 0 && sigismember(&action.sa_mask, SIGUSR2) == 1);
    CHECK(raise(SIGUSR1) == 0 && delivered == 1);
    CHECK(write(request[1], "v", 1) == 1);
    void *joined = NULL;
    CHECK(pthread_join(sibling, &joined) == 0 && joined == &peer_completed);
    CHECK(read(reply[0], &byte, 1) == 1 && byte == 't');
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
    CHECK(close(preserved[0]) == 0 && close(preserved[1]) == 0);
    CHECK(close(request[0]) == 0 && close(request[1]) == 0);
    CHECK(close(reply[0]) == 0 && close(reply[1]) == 0);
    CHECK(pthread_mutex_lock(&lock) == 0 && pthread_mutex_unlock(&lock) == 0);
#elif defined(PATINA_MP_FIXTURE_EARLY_DEATH)
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) _exit(42); // no handshake: death can precede parent bookkeeping
    CHECK(reaped(child, 42));
    int status;
    CHECK(waitpid(child, &status, WNOHANG) == -1 && errno == ECHILD);
#elif defined(PATINA_MP_FIXTURE_ATFORK_LOCK)
    CHECK(pthread_atfork(prepare, unlock, unlock) == 0);
    CHECK(pthread_mutex_lock(&lock) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        CHILD(pthread_mutex_trylock(&lock) == 0);
        CHILD(pthread_mutex_unlock(&lock) == 0);
        _exit(0);
    }
    CHECK(pthread_mutex_trylock(&lock) == 0 && pthread_mutex_unlock(&lock) == 0);
    CHECK(reaped(child, 0));
#elif defined(PATINA_MP_FIXTURE_FD_SHARING)
    char path[4096];
    CHECK(snprintf(path, sizeof(path), "%s/shared-offset", dir) > 0);
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    CHECK(fd >= 0 && write(fd, "abcdef", 6) == 6 && lseek(fd, 0, SEEK_SET) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        char bytes[2];
        CHILD(read(fd, bytes, 2) == 2 && memcmp(bytes, "ab", 2) == 0);
        int flags = fcntl(fd, F_GETFL);
        CHILD(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
        _exit(0);
    }
    CHECK(reaped(child, 0));
    char bytes[2];
    CHECK(read(fd, bytes, 2) == 2 && memcmp(bytes, "cd", 2) == 0);
    CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) != 0);
    CHECK(close(fd) == 0 && unlink(path) == 0);
#elif defined(PATINA_MP_FIXTURE_LAST_WRITER_EOF)
    int fds[2];
    CHECK(pipe(fds) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        CHILD(close(fds[0]) == 0 && write(fds[1], "done", 4) == 4);
        _exit(0); // writer closes by death rather than by a close call
    }
    CHECK(close(fds[1]) == 0);
    char bytes[4];
    size_t got = 0;
    while (got < sizeof(bytes)) {
        ssize_t n = read(fds[0], bytes + got, sizeof(bytes) - got);
        CHECK(n > 0);
        got += (size_t)n;
    }
    CHECK(memcmp(bytes, "done", 4) == 0 && read(fds[0], bytes, 1) == 0);
    CHECK(reaped(child, 0) && close(fds[0]) == 0);
#elif defined(PATINA_MP_FIXTURE_EPIPE_SIGPIPE)
    struct sigaction action = {0};
    action.sa_handler = note_signal;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    int fds[2];
    CHECK(pipe(fds) == 0 && close(fds[0]) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        CHILD(write(fds[1], "x", 1) == -1 && errno == EPIPE && delivered == 1);
        _exit(0);
    }
    CHECK(close(fds[1]) == 0 && reaped(child, 0));
#elif defined(PATINA_MP_FIXTURE_QUEUED_SIGNALS)
    sigset_t blocked;
    CHECK(sigemptyset(&blocked) == 0 && sigaddset(&blocked, SIGRTMIN) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &blocked, NULL) == 0);
    int ready[2], release[2];
    CHECK(pipe(ready) == 0 && pipe(release) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        CHILD(close(ready[0]) == 0 && close(release[1]) == 0);
        CHILD(write(ready[1], "r", 1) == 1);
        char byte;
        CHILD(read(release[0], &byte, 1) == 1); // parked while the parent queues signals
        for (int value = 100; value < 102; ++value) {
            siginfo_t info;
            CHILD(sigwaitinfo(&blocked, &info) == SIGRTMIN);
            CHILD(info.si_code == SI_QUEUE && info.si_value.sival_int == value);
            CHILD(info.si_pid == getppid());
        }
        _exit(0);
    }
    CHECK(close(ready[1]) == 0 && close(release[0]) == 0);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1);
    for (int value = 100; value < 102; ++value) {
        union sigval payload = {.sival_int = value};
        CHECK(sigqueue(child, SIGRTMIN, payload) == 0);
    }
    CHECK(write(release[1], "g", 1) == 1 && reaped(child, 0));
    CHECK(close(ready[0]) == 0 && close(release[1]) == 0);
#elif defined(PATINA_MP_FIXTURE_SHARED_FUTEX)
#ifdef __linux__
    int *word = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    CHECK(word != MAP_FAILED);
    *word = 0;
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        // The parent keeps the word zero until the kernel acknowledges a wake.
        long status;
        do {
            status = syscall(SYS_futex, word, FUTEX_WAIT, 0, NULL, NULL, 0);
        } while (status == -1 && errno == EINTR);
        CHILD(status == 0);
        while (__atomic_load_n(word, __ATOMIC_SEQ_CST) == 0) sched_yield();
        _exit(0);
    }
    // A successful wake proves the child actually joined the kernel wait queue.
    long woke;
    do {
        woke = syscall(SYS_futex, word, FUTEX_WAKE, 1, NULL, NULL, 0);
        CHECK(woke >= 0);
        if (woke == 0) sched_yield();
    } while (woke == 0);
    __atomic_store_n(word, 1, __ATOMIC_SEQ_CST);
    CHECK(reaped(child, 0) && munmap(word, 4096) == 0);
#else
    fprintf(stderr, "fixture requires Linux\n");
    return 77;
#endif
#else
#error Unknown multiproc fixture selection
#endif
    return 0;
}
