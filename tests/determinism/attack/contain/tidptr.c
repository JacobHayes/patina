/* Containment: a thread's clear-tid pointer (set_tid_address) aimed at the control region's
 * published address. The kernel ignores a clear-tid store it cannot make; the runtime used
 * to make it itself and fault. glibc's join then waits for ever, natively too. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
static void *t(void *a) { syscall(SYS_set_tid_address, 0x602000000000l); return a; }
int main(void) {
    pthread_t th;
    pthread_create(&th, 0, t, 0);
    pthread_join(th, 0);
    printf("joined\n");
    return 0;
}
