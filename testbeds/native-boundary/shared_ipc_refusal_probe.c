#include <fcntl.h>
#include <sys/mman.h>
int main(void) { return shm_open("/patina-refused", O_RDONLY, 0) < 0; }
