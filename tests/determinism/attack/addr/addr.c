/* Address-dependent behaviour: 10,000 malloc, mmap, brk, stack and TLS addresses hashed;
 * pointer-keyed hash table iteration order; /proc/self/maps. */
#define _GNU_SOURCE
#include "../common.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
static __thread int tls_var;
static void *thr(void *a) { (void)a; int local; static __thread char big[100]; uintptr_t v[3] = {(uintptr_t)&local, (uintptr_t)&tls_var, (uintptr_t)big}; return (void *)(v[0] ^ (v[1] << 1) ^ (v[2] << 2)); }
int main(void) {
    uint64_t h = FNV0;
    for (int i = 0; i < 10000; i++) { void *p = malloc(1 + (i * 37) % 70000); h = fnv_add(h, &p, sizeof p); if (i % 3) free(p); }
    printf("malloc %016llx\n", (unsigned long long)h);
    h = FNV0;
    for (int i = 0; i < 2000; i++) { void *p = mmap(0, 4096 * (1 + i % 17), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); h = fnv_add(h, &p, sizeof p); if (i % 2) munmap(p, 4096); }
    printf("mmap %016llx\n", (unsigned long long)h);
    void *b0 = sbrk(0); sbrk(12345); void *b1 = sbrk(0);
    int local; printf("brk %p %p stack %p tls %p main %p\n", b0, b1, (void *)&local, (void *)&tls_var, (void *)main);
    h = FNV0;
    for (int i = 0; i < 64; i++) { pthread_t t; void *r; pthread_create(&t, 0, thr, 0); pthread_join(t, &r); h = fnv_add(h, &r, sizeof r); }
    printf("threads %016llx\n", (unsigned long long)h);
    char buf[65536]; int fd = open("/proc/self/maps", O_RDONLY); ssize_t n = read(fd, buf, sizeof buf); close(fd);
    printf("maps len %zd hash %016llx\n", n, (unsigned long long)fnv_add(FNV0, buf, n > 0 ? n : 0));
    if (n > 0) fwrite(buf, 1, n, stdout);
    return 0;
}
