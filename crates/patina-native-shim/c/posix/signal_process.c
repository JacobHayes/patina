/* Keep caller ownership visible to patina_abort before its PanicScope.
 * A Rust adapter's required first guard would reclassify guest panic=abort
 * as a shim panic and change healthy trace finalization. */
#ifdef __linux__
_Noreturn void abort(void) {
    patina_abort();
}
#endif
