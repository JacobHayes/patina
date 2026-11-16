/* patina.h: Patina's SDK for C and C++, and the reference for the wire every other SDK speaks.
 *
 * One reserved system call carries everything:  syscall(PATINA_SYSCALL, op, ptr, len).
 * Outside Patina the kernel answers ENOSYS (a container may answer EPERM); the first call
 * learns that, and from then on every macro is a load and a branch. No build flag, no link.
 *
 *   PATINA_ALWAYS(cond, "label", detail)   invariant; a failure ends the run as `violation`
 *   PATINA_SOMETIMES(cond, "label")        should hold on some runs
 *   PATINA_REACHABLE("label")              should be reached on some runs
 *   PATINA_UNREACHABLE("label", detail)    must not be reached: reaching it is a violation
 *   PATINA_BUGGIFY("label")                fault point: 1 on seed-chosen evaluations (--buggify)
 *   PATINA_BUGGIFY_WITH_PROB("label", p)   the same at p per mille instead of the run default
 *   PATINA_KNOB("label", def, lo, hi)      def, or a seed-chosen value in [lo, hi] (--buggify)
 *   PATINA_DELAY("label", max_ns)          maybe sleep a seeded virtual time (0: default range)
 *   patina_mark(label), patina_setup_complete(), patina_is_simulated()
 *
 * Labels of the macros are string literals: each expansion declares its site in the ELF section
 * `patina_sites` (so a site never reached is still reported) and keeps one static byte, so a
 * passing assertion traps only the first time it is evaluated (a `sometimes` also the first
 * time it holds). `detail` is a `const char *` (or NULL), evaluated only when the call traps.
 * Needs GCC or Clang (statement expressions); C++ can include it. Not thread-safe beyond what Patina serialises;
 * natively, a race only repeats a no-op.
 *
 * Wire (proto::sdk in the Patina repository): payload = 32-byte header, label, text.
 *   0 u8 kind | 1 u8 cond | 2 u16 label_len | 4 u32 text_len | 8 i64 a | 16 i64 b | 24 i64 c
 * Ops 8 and 9 take no payload: compute points, made only by patina_compute.c (the hooks of a
 * program rebuilt with coverage flags):
 *   8 COMPUTE_HELLO  arg = version 1 | kinds << 8 (1 edge, 2 access, 4 compare) -> cell address
 *   9 COMPUTE_POINT  arg = 0: the cell reached 0 -> 0, the cell refilled
 */
#ifndef PATINA_H
#define PATINA_H

#include <stdint.h>
#include <string.h>

#define PATINA_SYSCALL 0x7061
#define PATINA_VERSION 1
#define PATINA_HELLO_BUGGIFY (1L << 16)

enum { PATINA_OP_HELLO = 1, PATINA_OP_ASSERT, PATINA_OP_BUGGIFY, PATINA_OP_KNOB,
       PATINA_OP_DELAY, PATINA_OP_MARK, PATINA_OP_DECLARE };
enum { PATINA_KIND_ALWAYS = 1, PATINA_KIND_SOMETIMES, PATINA_KIND_REACHABLE,
       PATINA_KIND_BUGGIFY, PATINA_KIND_KNOB, PATINA_KIND_DELAY, PATINA_KIND_UNREACHABLE };

#define PATINA_NEVER 2 /* a point's answer: no, and never in this run */
#define PATINA_LABEL_MAX 255
#define PATINA_TEXT_MAX 4096

/* Site byte bits: reported evaluated, reported held, point never fires. */
#define PATINA__EVAL 1
#define PATINA__HELD 2
#define PATINA__NEVER 4

/* 0: not asked yet; 1: under Patina; 2: not. Shared by every translation unit. */
__attribute__((weak)) int patina__state;
__attribute__((weak)) int patina__buggify;

static inline long patina__sys(long op, const void *p, unsigned long len) {
#if defined(__x86_64__) && defined(__linux__)
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"((long)PATINA_SYSCALL), "D"(op), "S"(p), "d"(len)
                     : "rcx", "r11", "memory");
    return r;
#else
    (void)op; (void)p; (void)len;
    return -38;
#endif
}

static inline int patina_is_simulated(void) {
    if (__builtin_expect(patina__state == 0, 0)) {
        long r = patina__sys(PATINA_OP_HELLO, 0, 0);
        int ok = r >= 0 && (r & 0xffff) == PATINA_VERSION;
        if (r >= 0 && !ok) {
            static const char m[] = "patina: unknown SDK protocol version; the SDK is inert\n";
#if defined(__x86_64__) && defined(__linux__)
            long w;
            __asm__ volatile("syscall" : "=a"(w) : "a"(1L), "D"(2L), "S"(m), "d"(sizeof m - 1)
                             : "rcx", "r11", "memory");
            (void)w;
#endif
        }
        patina__buggify = ok && (r & PATINA_HELLO_BUGGIFY) != 0;
        patina__state = ok ? 1 : 2;
    }
    return patina__state == 1;
}

/* One call: header, label, text. Returns the answer, or -errno. `a` is read back (a knob). */
static inline long patina__call(long op, int kind, int cond, const char *label, const char *text,
                                int64_t *a, int64_t b, int64_t c) {
    unsigned char buf[32 + PATINA_LABEL_MAX + PATINA_TEXT_MAX];
    size_t ll = strlen(label), tl = text ? strlen(text) : 0;
    if (ll > PATINA_LABEL_MAX) ll = PATINA_LABEL_MAX;
    if (tl > PATINA_TEXT_MAX) tl = PATINA_TEXT_MAX;
    int64_t w[3] = {a ? *a : 0, b, c};
    uint16_t l16 = (uint16_t)ll;
    uint32_t t32 = (uint32_t)tl;
    buf[0] = (unsigned char)kind;
    buf[1] = (unsigned char)(cond != 0);
    memcpy(buf + 2, &l16, 2);
    memcpy(buf + 4, &t32, 4);
    memcpy(buf + 8, w, 24);
    memcpy(buf + 32, label, ll);
    if (tl) memcpy(buf + 32 + ll, text, tl);
    long r = patina__sys(op, buf, 32 + ll + tl);
    if (a && r == 0) memcpy(a, buf + 8, 8);
    return r;
}

static inline void patina__assert(unsigned char *site, int kind, int cond, const char *label,
                                  const char *detail) {
    if (!patina_is_simulated()) return;
    *site |= PATINA__EVAL | (cond ? PATINA__HELD : 0);
    patina__call(PATINA_OP_ASSERT, kind, cond, label, cond ? 0 : detail, 0, 0, 0);
}

static inline int patina__point(unsigned char *site, int op, int kind, const char *label,
                                int64_t a) {
    if (!patina_is_simulated() || !patina__buggify || (*site & PATINA__NEVER)) return 0;
    long r = patina__call(op, kind, 0, label, 0, &a, 0, 0);
    if (r == PATINA_NEVER) *site |= PATINA__NEVER;
    return r == 1;
}

static inline int64_t patina__knob(const char *label, int64_t def, int64_t lo, int64_t hi) {
    if (!patina_is_simulated() || !patina__buggify) return def;
    int64_t v = def;
    return patina__call(PATINA_OP_KNOB, PATINA_KIND_KNOB, 0, label, 0, &v, lo, hi) == 0 ? v : def;
}

/* A named point in the run's log; "setup-complete" ends setup (faults-after-setup). */
static inline void patina_mark(const char *label) {
    if (patina_is_simulated())
        patina__call(PATINA_OP_MARK, PATINA_KIND_REACHABLE, 0, label, 0, 0, 0, 0);
}
static inline void patina_setup_complete(void) { patina_mark("setup-complete"); }

/* Declare a site whose label is not a literal (the macros declare theirs in the ELF section). */
static inline void patina_declare(int kind, const char *label, const char *where) {
    if (patina_is_simulated()) patina__call(PATINA_OP_DECLARE, kind, 0, label, where, 0, 0, 0);
}

#define PATINA__STR2(x) #x
#define PATINA__STR(x) PATINA__STR2(x)
#define PATINA__LOC __FILE__ ":" PATINA__STR(__LINE__)

/* The site's record in `patina_sites`: 0xb7, kind, label length, location length, label,
 * location. No pointers, so it needs no relocation; the runtime reads it from the file. C only:
 * C++ cannot initialise an array with a string literal minus its NUL, so C++ sites are not
 * declared ahead (call patina_declare for one that must be reported unreached). */
#if defined(__has_attribute)
#if __has_attribute(nonstring)
#define PATINA__NONSTRING __attribute__((nonstring))
#endif
#endif
#ifndef PATINA__NONSTRING
#define PATINA__NONSTRING
#endif
#ifdef __cplusplus
#define PATINA__SITE(kind, label)                                                              \
    static_assert(sizeof(label) > 1 && sizeof(label) - 1 <= PATINA_LABEL_MAX,                  \
                  "a Patina label is a string literal of 1 to 255 bytes")
#else
#define PATINA__SITE(kind, label)                                                              \
    _Static_assert(sizeof(label) > 1 && sizeof(label) - 1 <= PATINA_LABEL_MAX,                 \
                   "a Patina label is a string literal of 1 to 255 bytes");                    \
    _Static_assert(sizeof(PATINA__LOC) - 1 <= 255, "source path too long for a site record"); \
    __attribute__((used, section("patina_sites"))) static const struct {                      \
        unsigned char h[4];                                                                    \
        char l[sizeof(label) - 1] PATINA__NONSTRING;                                           \
        char s[sizeof(PATINA__LOC) - 1] PATINA__NONSTRING;                                     \
    } patina__rec = {{0xb7, kind, sizeof(label) - 1, sizeof(PATINA__LOC) - 1}, label, PATINA__LOC}
#endif

#define PATINA_ALWAYS(cond, label, detail)                                                     \
    do {                                                                                       \
        PATINA__SITE(PATINA_KIND_ALWAYS, label);                                               \
        static unsigned char patina__b;                                                        \
        int patina__c = !!(cond);                                                              \
        if (__builtin_expect(!patina__c || !(patina__b & PATINA__EVAL), 0) && patina__state != 2) \
            patina__assert(&patina__b, PATINA_KIND_ALWAYS, patina__c, label, (detail));        \
    } while (0)

#define PATINA_UNREACHABLE(label, detail)                                                      \
    do {                                                                                       \
        PATINA__SITE(PATINA_KIND_UNREACHABLE, label);                                          \
        static unsigned char patina__b;                                                        \
        if (patina__state != 2)                                                                \
            patina__assert(&patina__b, PATINA_KIND_UNREACHABLE, 0, label, (detail));           \
    } while (0)

#define PATINA_SOMETIMES(cond, label)                                                          \
    do {                                                                                       \
        PATINA__SITE(PATINA_KIND_SOMETIMES, label);                                            \
        static unsigned char patina__b;                                                        \
        int patina__c = !!(cond);                                                              \
        if (__builtin_expect(!(patina__b & (patina__c ? PATINA__HELD : PATINA__EVAL)), 0) &&   \
            patina__state != 2)                                                                \
            patina__assert(&patina__b, PATINA_KIND_SOMETIMES, patina__c, label, 0);            \
    } while (0)

#define PATINA_REACHABLE(label)                                                                \
    do {                                                                                       \
        PATINA__SITE(PATINA_KIND_REACHABLE, label);                                            \
        static unsigned char patina__b;                                                        \
        if (__builtin_expect(!(patina__b & PATINA__EVAL), 0) && patina__state != 2)            \
            patina__assert(&patina__b, PATINA_KIND_REACHABLE, 1, label, 0);                    \
    } while (0)

#define PATINA__POINT(op, kind, label, a)                                                      \
    __extension__({                                                                            \
        PATINA__SITE(kind, label);                                                             \
        static unsigned char patina__b;                                                        \
        patina__state == 2 ? 0 : patina__point(&patina__b, op, kind, label, (a));              \
    })

#define PATINA_BUGGIFY(label) PATINA__POINT(PATINA_OP_BUGGIFY, PATINA_KIND_BUGGIFY, label, -1)
#define PATINA_BUGGIFY_WITH_PROB(label, permille)                                              \
    PATINA__POINT(PATINA_OP_BUGGIFY, PATINA_KIND_BUGGIFY, label, (int64_t)(permille))
#define PATINA_DELAY(label, max_ns)                                                            \
    PATINA__POINT(PATINA_OP_DELAY, PATINA_KIND_DELAY, label, (int64_t)(max_ns))

#define PATINA_KNOB(label, def, lo, hi)                                                        \
    __extension__({                                                                            \
        PATINA__SITE(PATINA_KIND_KNOB, label);                                                 \
        patina__state == 2 ? (int64_t)(def) : patina__knob(label, (def), (lo), (hi));          \
    })

#endif
