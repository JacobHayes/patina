// A weak reference to glibc's thread-exit registration, as Rust's std makes:
// libc defines it, so it binds there rather than staying NULL.
#include <stdio.h>

extern int __cxa_thread_atexit_impl(void (*dtor)(void *), void *object, void *dso)
    __attribute__((weak));

int main(void) {
    puts(__cxa_thread_atexit_impl == NULL ? "THREAD_ATEXIT absent" : "THREAD_ATEXIT bound");
    return 0;
}
