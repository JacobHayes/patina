#include <sys/prctl.h>
#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
int main(void) {
    return prctl(PR_SET_SYSCALL_USER_DISPATCH, 0, 0, 0, 0) == 0 ? 0 : 1;
}
