/* OpenSSL RAND_bytes (64 bytes, twice), and RAND_priv_bytes. */
#include <openssl/rand.h>
#include <stdio.h>

static void show(const char *what, int (*f)(unsigned char *, int)) {
    unsigned char b[64];
    if (f(b, sizeof b) != 1) {
        printf("%s failed\n", what);
        return;
    }
    printf("%s ", what);
    for (unsigned i = 0; i < sizeof b; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    show("RAND_bytes", RAND_bytes);
    show("RAND_bytes", RAND_bytes);
    show("RAND_priv_bytes", RAND_priv_bytes);
    return 0;
}
