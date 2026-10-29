// The first library of a chain: it only forwards to the next one.
int b_call(void);

int lib_entry(void) { return b_call(); }
