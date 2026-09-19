#include <sys/prctl.h>
#ifndef PR_GET_TSC
#define PR_GET_TSC 25
#endif
int main(void) {
    int mode = 0;
    return prctl(PR_GET_TSC, &mode, 0, 0, 0) == 0 ? 0 : 1;
}
