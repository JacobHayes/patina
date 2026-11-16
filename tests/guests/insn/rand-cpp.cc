// instruction channels item 2: std::random_device with each token libstdc++ offers on x86 ("default",
// "rdrand", "rdseed", "hw"); 8 values each. A token the library refuses is reported as such.
#include <cstdio>
#include <random>
#include <string>

int main() {
    for (const char *tok : {"default", "rdrand", "rdseed", "hw"}) {
        try {
            std::random_device rd(tok);
            std::printf("%s entropy=%g", tok, rd.entropy());
            for (int i = 0; i < 8; i++) std::printf(" %08x", rd());
            std::printf("\n");
        } catch (const std::exception &e) {
            std::printf("%s unavailable\n", tok);
        }
    }
    return 0;
}
