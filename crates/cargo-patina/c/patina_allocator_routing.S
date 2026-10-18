/* The allocator routing's two names for each Rust allocator entry point
 * (`src/allocator_routing.rs`), as code rather than linker symbol
 * assignments, so every linker that implements `--wrap` (GNU ld, gold, lld,
 * mold) links it alike.
 *
 * The link wraps each entry point: Rust's calls to it reach `__wrap_<name>`,
 * which jumps to the shim's router, and `__real_<name>` is the entry point
 * itself, which the shim reaches as `patina_guest_*`. The entry points' names
 * carry the compiler's hash, so `PATINA_RUST_ALLOC_PREFIX` arrives as a
 * define. Linux only.
 */

#ifndef PATINA_RUST_ALLOC_PREFIX
#error "PATINA_RUST_ALLOC_PREFIX names the compiler's allocator entry points"
#endif

#define PATINA_CAT2(a, b) a##b
#define PATINA_CAT(a, b) PATINA_CAT2(a, b)
#define PATINA_ENTRY(suffix) PATINA_CAT(PATINA_RUST_ALLOC_PREFIX, suffix)

/* Each entry is a landing pad, so an indirect call may reach it under
 * control-flow enforcement (`endbr64` for x86_64 IBT, `bti c` for aarch64
 * BTI), and then a tail jump, which pushes no return address (the shadow
 * stack) and signs none (pointer authentication). The property note below
 * says so, so the link keeps the program's marking. */
#if defined(__x86_64__)
#define PATINA_LANDING endbr64
#define PATINA_JUMP(target) jmp target@PLT
/* GNU_PROPERTY_X86_FEATURE_1_AND: IBT | SHSTK. */
#define PATINA_PROPERTY_TYPE 0xc0000002
#define PATINA_PROPERTY_FEATURES 0x3
#elif defined(__aarch64__)
#define PATINA_LANDING hint 34
#define PATINA_JUMP(target) b target
/* GNU_PROPERTY_AARCH64_FEATURE_1_AND: BTI | PAC. */
#define PATINA_PROPERTY_TYPE 0xc0000000
#define PATINA_PROPERTY_FEATURES 0x3
#else
#error "the allocator routing has no jump for this architecture"
#endif

#define PATINA_FUNCTION(name) \
    .globl name;              \
    .hidden name;             \
    .type name, %function;    \
    name:                     \
    PATINA_LANDING;

#define PATINA_ROUTE(suffix, route, guest)                   \
    PATINA_FUNCTION(PATINA_CAT(__wrap_, PATINA_ENTRY(suffix))) \
    PATINA_JUMP(route);                                      \
    PATINA_FUNCTION(guest)                                   \
    PATINA_JUMP(PATINA_CAT(__real_, PATINA_ENTRY(suffix)))

    .text
PATINA_ROUTE(12___rust_alloc, patina_route_alloc, patina_guest_alloc)
PATINA_ROUTE(14___rust_dealloc, patina_route_dealloc, patina_guest_dealloc)
PATINA_ROUTE(14___rust_realloc, patina_route_realloc, patina_guest_realloc)
PATINA_ROUTE(19___rust_alloc_zeroed, patina_route_alloc_zeroed, patina_guest_alloc_zeroed)

    .section .note.GNU-stack, "", %progbits

    /* NT_GNU_PROPERTY_TYPE_0: one 4-byte property, padded to 8 bytes. */
    .section .note.gnu.property, "a"
    .p2align 3
    .long 4
    .long 16
    .long 5
    .asciz "GNU"
    .long PATINA_PROPERTY_TYPE
    .long 4
    .long PATINA_PROPERTY_FEATURES
    .long 0
