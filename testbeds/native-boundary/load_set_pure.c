// A library whose code only computes: every reference it makes stays inside
// the audited images, so a guest over it runs and replays as one program.
int lib_entry(void) {
    int sum = 0;
    for (int i = 1; i <= 8; i++) {
        sum += i * i;
    }
    return sum;
}
