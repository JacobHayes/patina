/* Only same-object GNU aliases remain C. Rust owns lookup and dlerror. */
#ifdef __linux__
#define PATINA_ROUTE_ALIAS(name) \
    extern __typeof__(name) patina_route_##name \
        __attribute__((alias(#name), visibility("hidden")));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#if !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmissing-attributes"
#endif
PATINA_ROUTED(PATINA_ROUTE_ALIAS)
#ifdef __x86_64__
PATINA_ROUTED_X86_64(PATINA_ROUTE_ALIAS)
#endif
#pragma GCC diagnostic pop
#undef PATINA_ROUTE_ALIAS
#endif
