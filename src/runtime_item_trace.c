/* Item-hit diagnostics (net12): which PC decides that a dropped potion hit a kart, and on which PC
 * the kart's damage starts. Logged lines start with "[ITEM]" and carry the game's corrected wall
 * clock (all PCs within ~20 ms of each other), so the logs of two players line up.
 *
 * The game's potion (eboot USA 1.21, image offsets; +0x400000 for PS4 addresses):
 * - CSpawnedBeakerComponent::setState 0xf14500 (state at component +0xc0: 0 disabled, 1 waiting,
 *   2 dropped, 3 thrown, 4 idle, 5 exploding, 6 removed). The network sets it through the
 *   registered method netSetBeakerState, a jmp at 0xf5c790.
 * - The potion's touch callback 0xf163a0 (component, entity touched, flag): created only on the PC
 *   that owns the potion (entity bit _netHasAuthority, byte +0x3b bit 0). It sends the touched
 *   entity a COnPowerUpImpact through 0xe3c670 (impactable component, kind, potion entity, owner)
 *   and sets the potion exploding.
 * - CKartDamageComponent start 0xe34850 (component, damage type: 6 poisoned, 10 green potion...).
 * Each function starts with a frame prologue without rip-relative operands: its first instructions
 * are copied to a stub that jumps back, and the function's entry jumps to a logging wrapper that
 * calls the stub (as runtime_itemless.c does). Any byte that differs leaves that hook out.
 * BB_ITEM_TRACE=0 turns all of it off. */
#define _GNU_SOURCE
#include "runtime.h"
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

typedef uint64_t (ABI *Fn6)(void *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef void *(ABI *FindRacer)(void *, void *);

static unsigned char *g_image;
static Fn6 orig_touch, orig_impact, orig_state, orig_damage;
static FindRacer find_racer;
static void **racers;
static _Thread_local int from_network;

#define OFF_TOUCH 0xf163a0u
#define OFF_IMPACT 0xe3c670u
#define OFF_STATE 0xf14500u
#define OFF_NET_STATE 0xf5c790u
#define OFF_DAMAGE 0xe34850u
#define OFF_FIND_RACER 0xfd4230u
#define OFF_RACERS 0x2ad4b70u

static const unsigned char frame17_38[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x83,0xec,0x38};
static const unsigned char frame17_28[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x83,0xec,0x28};
static const unsigned char state_code[] = {0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x49,0x89,0xfe,0x89,0xf3,
                                           0x41,0x8b,0x86,0xc0,0x00,0x00,0x00};
static const unsigned char net_state_code[] = {0xe9,0x6b,0x7d,0xfb,0xff,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
static const unsigned char find_racer_code[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x50};

static const char *const beaker_state[] = {"disabled", "waiting", "dropped", "thrown", "idle", "exploding", "removed"};
static const char *const damage_type[] = {"spin-out", "wall hit", "explosion", "eaten", "fire", "electrified",
                                          "poisoned", "N.Tropy", "crushed", "crushed and stopped", "green potion"};

static void *ptr_at(const void *p, size_t off) {
    void *v;
    memcpy(&v, (const unsigned char *)p + off, sizeof v);
    return v;
}

static int has_authority(const void *entity) {
    return entity ? (((const unsigned char *)entity)[0x3b] & 1) : -1;
}

/* An entity's position (CEntity _parentSpacePosition, +0x20). */
static void position(const void *entity, float out[3]) {
    if (entity) memcpy(out, (const unsigned char *)entity + 0x20, 3 * sizeof(float));
    else out[0] = out[1] = out[2] = 0.0f;
}

static float distance(const float a[3], const float b[3]) {
    const float x = a[0] - b[0], y = a[1] - b[1], z = a[2] - b[2];
    return sqrtf(x * x + y * y + z * z);
}

/* "your kart" / "player 3's kart (on another PC)" / "an AI kart (run by this PC)" / "an object ...". */
static void describe(void *entity, char *out, size_t cap) {
    if (!entity) {
        snprintf(out, cap, "nothing");
        return;
    }
    /* find_racer reads the entity's component list (CEntity _components, +0x18): an entity being
     * torn down has none, and the game's lookup would read through a null pointer. */
    void *racer = find_racer && racers && *racers && ptr_at(entity, 0x18) ? find_racer(*racers, entity) : NULL;
    const int auth = has_authority(entity);
    if (!racer) {
        snprintf(out, cap, "an object (owned by %s)", auth ? "this PC" : "another PC");
        return;
    }
    const unsigned char *r = racer;
    int id;
    memcpy(&id, r + 0x164, sizeof id);                       /* _playerId */
    if (r[0x40]) snprintf(out, cap, "AI kart %d (run by %s)", id, auth ? "this PC" : "another PC");  /* _isAiControlled */
    else if (r[0xb0]) snprintf(out, cap, "YOUR kart (player %d)", id);                                 /* _hasLocalAuthority */
    else snprintf(out, cap, "player %d's kart (driven on another PC)", id);
}

static void item_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void item_log(const char *fmt, ...) {
    static uint64_t window_start;
    static unsigned lines;
    const int64_t us = runtime_wall_now_us();
    const uint64_t second = (uint64_t)us / 1000000u;
    if (second != __atomic_load_n(&window_start, __ATOMIC_RELAXED)) {
        __atomic_store_n(&window_start, second, __ATOMIC_RELAXED);
        __atomic_store_n(&lines, 0, __ATOMIC_RELAXED);
    }
    if (__atomic_fetch_add(&lines, 1, __ATOMIC_RELAXED) >= 60) return; /* at most 60 lines a second */
    const time_t t = (time_t)second;
    struct tm tm;
    memset(&tm, 0, sizeof tm);
#ifdef _WIN32
    const struct tm *l = localtime(&t);
    if (l) tm = *l;
#else
    localtime_r(&t, &tm);
#endif
    char line[512];
    int at = snprintf(line, sizeof line, "[ITEM] %02d:%02d:%02d.%03d ", tm.tm_hour, tm.tm_min, tm.tm_sec,
                      (int)((us / 1000) % 1000));
    va_list ap;
    va_start(ap, fmt);
    if (at > 0 && at < (int)sizeof line) vsnprintf(line + at, sizeof line - (size_t)at, fmt, ap);
    va_end(ap);
    puts(line);
    fflush(stdout);
}

static const char *state_name(int s) { return s >= 0 && s < 7 ? beaker_state[s] : "?"; }

/* The potion's touch callback, on the PC that owns the potion. */
static uint64_t ABI touch(void *self, uint64_t other, uint64_t flag, uint64_t a3, uint64_t a4, uint64_t a5) {
    void *potion = self ? ptr_at(self, 0x18) : NULL;
    int before = -1;
    if (self) memcpy(&before, (unsigned char *)self + 0xc0, sizeof before);
    float p[3], k[3];
    position(potion, p);
    position((void *)(uintptr_t)other, k);
    char who[96];
    describe((void *)(uintptr_t)other, who, sizeof who); /* before: the touch may remove what it touched */
    const int owner = has_authority(potion);
    const uint64_t r = orig_touch(self, other, flag, a3, a4, a5);
    int after = -1;
    if (self) memcpy(&after, (unsigned char *)self + 0xc0, sizeof after);
    item_log("potion touch check on this PC: potion %p (owned by %s, %s -> %s) at (%.1f %.1f %.1f); touched by %s at (%.1f %.1f %.1f), %.1f apart; flag %d",
             potion, owner == 1 ? "this PC" : "another PC", state_name(before), state_name(after),
             p[0], p[1], p[2], who, k[0], k[1], k[2], distance(p, k), (int)flag);
    return r;
}

/* COnPowerUpImpact sent to an entity (the potion's touch, or another power-up's hit). */
static uint64_t ABI impact(void *impactable, uint64_t kind, uint64_t powerup, uint64_t owner, uint64_t a4, uint64_t a5) {
    void *target = impactable ? ptr_at(impactable, 0x18) : NULL;
    char who[96];
    describe(target, who, sizeof who);
    float t[3], p[3];
    position(target, t);
    position((void *)(uintptr_t)powerup, p);
    const int powerup_owner = has_authority((void *)(uintptr_t)powerup);
    const uint64_t r = orig_impact(impactable, kind, powerup, owner, a4, a5);
    item_log("power-up impact sent on this PC: kind %d to %s at (%.1f %.1f %.1f), power-up %p (owned by %s) %.1f away -> %s",
             (int)kind, who, t[0], t[1], t[2], (void *)(uintptr_t)powerup,
             powerup_owner == 1 ? "this PC" : "another PC", distance(t, p),
             (r & 0xff) ? "accepted" : "ignored");
    return r;
}

static uint64_t ABI set_state(void *self, uint64_t state, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    int before = -1;
    if (self) memcpy(&before, (unsigned char *)self + 0xc0, sizeof before);
    const int net = from_network;
    from_network = 0;
    void *potion = self ? ptr_at(self, 0x18) : NULL;
    const uint64_t r = orig_state(self, state, a2, a3, a4, a5);
    if (before != (int)state && self) {
        float p[3], e[3];
        position(potion, p);
        memcpy(e, (unsigned char *)self + 0xa8, sizeof e); /* _explosionPosition */
        if ((int)state == 5)
            item_log("potion %p (owned by %s): %s -> exploding, set %s; explodes at (%.1f %.1f %.1f)", potion,
                     has_authority(potion) == 1 ? "this PC" : "another PC", state_name(before),
                     net ? "by the owner's PC over the network" : "on this PC", e[0], e[1], e[2]);
        else
            item_log("potion %p (owned by %s): %s -> %s, set %s; at (%.1f %.1f %.1f)", potion,
                     has_authority(potion) == 1 ? "this PC" : "another PC", state_name(before),
                     state_name((int)state), net ? "by the owner's PC over the network" : "on this PC", p[0], p[1], p[2]);
    }
    return r;
}

/* netSetBeakerState: the state received from the potion's owner. */
static uint64_t ABI net_set_state(void *self, uint64_t state, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    from_network = 1;
    const uint64_t r = ((Fn6)(g_image + OFF_STATE))(self, state, a2, a3, a4, a5);
    from_network = 0;
    return r;
}

static uint64_t ABI damage(void *self, uint64_t type, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    void *kart = self ? ptr_at(self, 0x18) : NULL;
    const int t = (int)type;
    char who[96];
    float k[3];
    if (t >= 0 && t <= 10) {
        describe(kart, who, sizeof who);
        position(kart, k);
    }
    const uint64_t r = orig_damage(self, type, a2, a3, a4, a5);
    if (t >= 0 && t <= 10) {
        item_log("damage starts on this PC: %s for %s at (%.1f %.1f %.1f)", damage_type[t], who, k[0], k[1], k[2]);
    }
    return r;
}

static void jump(unsigned char *at, const void *target) {
    memcpy(at, "\xff\x25\0\0\0\0", 6);
    memcpy(at + 6, &target, 8);
}

static int writable(void *address, size_t length) {
#ifdef _WIN32
    DWORD old;
    return VirtualProtect(address, length, PAGE_EXECUTE_READWRITE, &old) != 0;
#else
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *start = (void *)((uintptr_t)address & ~(uintptr_t)(page - 1));
    return !mprotect(start, (size_t)((unsigned char *)address + length - (unsigned char *)start),
                     PROT_READ | PROT_WRITE | PROT_EXEC);
#endif
}

static unsigned char *g_stubs;
static size_t g_stub_used;

/* Points the function at offset to replacement; returns a stub that runs the original. */
static Fn6 hook(uint32_t offset, const unsigned char *code, size_t n, void *replacement, const char *name) {
    unsigned char *at = g_image + offset;
    if (memcmp(at, code, n) || g_stub_used + n + 14 > 4096 || !writable(at, 14)) {
        printf("Item trace: %s not hooked (unexpected code at %#x)\n", name, offset);
        return NULL;
    }
    unsigned char *stub = g_stubs + g_stub_used;
    memcpy(stub, at, n);
    jump(stub + n, at + n);
    g_stub_used += (n + 14 + 15) & ~(size_t)15;
    jump(at, replacement);
    return (Fn6)stub;
}

int runtime_item_trace_start(unsigned char *image, size_t size) {
    const char *on = getenv("BB_ITEM_TRACE");
    if (on && strcmp(on, "0") == 0) return 0;
    if (size < OFF_RACERS + 8) return 0;
    g_image = image;
#ifdef _WIN32
    g_stubs = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#else
    g_stubs = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_stubs == MAP_FAILED) g_stubs = NULL;
#endif
    if (!g_stubs) return 0;
    if (!memcmp(image + OFF_FIND_RACER, find_racer_code, sizeof find_racer_code)) {
        find_racer = (FindRacer)(image + OFF_FIND_RACER);
        racers = (void **)(image + OFF_RACERS);
    }
    orig_touch = hook(OFF_TOUCH, frame17_38, sizeof frame17_38, (void *)touch, "potion touch");
    orig_impact = hook(OFF_IMPACT, frame17_28, sizeof frame17_28, (void *)impact, "power-up impact");
    orig_state = hook(OFF_STATE, state_code, sizeof state_code, (void *)set_state, "potion state");
    orig_damage = hook(OFF_DAMAGE, frame17_28, sizeof frame17_28, (void *)damage, "kart damage");
    int net = 0;
    if (orig_state && !memcmp(image + OFF_NET_STATE, net_state_code, sizeof net_state_code) &&
        writable(image + OFF_NET_STATE, 14)) {
        jump(image + OFF_NET_STATE, (void *)net_set_state);
        net = 1;
    }
#ifdef _WIN32
    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
#endif
    printf("Item trace: potion touch %s, power-up impact %s, potion state %s (network %s), kart damage %s, racers %s\n",
           orig_touch ? "on" : "off", orig_impact ? "on" : "off", orig_state ? "on" : "off", net ? "on" : "off",
           orig_damage ? "on" : "off", find_racer ? "known" : "unknown");
    return 1;
}
