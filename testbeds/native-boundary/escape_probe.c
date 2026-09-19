#include <pthread.h>

__attribute__((noinline, used)) static void direct_syscall(void) {
#if defined(__aarch64__)
    __asm__ volatile("svc #0");
#elif defined(__x86_64__)
    __asm__ volatile("syscall");
#endif
}

static void *thread(void *value) { return value; }
int main(void) {
    pthread_t value;
    return pthread_create(&value, NULL, thread, NULL);
}
