/* Shared helpers for the determinism hardening attack guests: an FNV-1a hash and hex printing. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
static inline uint64_t fnv_add(uint64_t h, const void *p, size_t n) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 0x100000001b3ull; }
    return h;
}
#define FNV0 0xcbf29ce484222325ull
static inline void hexline(const char *tag, const void *p, size_t n) {
    const unsigned char *b = p;
    printf("%s ", tag);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}
