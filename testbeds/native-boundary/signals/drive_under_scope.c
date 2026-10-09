/* Class pairing: the caller check of the delivery steps
 * (src/thread/signals/delivery.rs). A delivery driven from inside a shim
 * entry (patina_planted_drive_under_scope, a shim built with planted-faults)
 * has a shim Rust frame beneath any handler it would run: its first step
 * stops the run by name, so nothing after the call runs. */
#include <unistd.h>

void patina_planted_drive_under_scope(void);

int main(void) {
    patina_planted_drive_under_scope();
    /* Straight to the host descriptor: reached only if the drive returned. */
    (void)!write(2, "DRIVEN\n", 7);
    return 0;
}
