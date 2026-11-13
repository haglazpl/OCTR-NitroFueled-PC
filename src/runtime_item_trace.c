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
 * BB_ITEM_TRACE=0 turns all of it off.
 *
 * net14: the dropped potion's kart touch, and the potion fix.
 * - A potion's start (0xf16eb0) registers, on EVERY PC, the callback 0xf17570 (component, ?, entity
 *   that entered) on the potion's trigger volume (CTriggerVolumeComponent, type at 0x2adb578). The
 *   callback takes the potion's network authority when the entity belongs to a local player, and for
 *   any kart sets _victim (+0xb8) and state 5: so every PC decides on its own, from what its screen
 *   shows, that a kart driven on ANOTHER PC touched a potion, and the potion's owner sends that
 *   decision to everyone. The fix: this PC leaves the touch of a human kart that is driven on another
 *   PC to that PC (the callback returns at once); the kart's own PC still detects it, takes the
 *   authority and tells the others. Karts this PC drives and AI karts are handled as before. It only
 *   changes what this PC decides, so players with and without it can share a room.
 *   On: the patch "Online: each PC decides potion hits only for its own kart" writes 0xCC into the unused
 *   padding byte at 0xf1773f (after the 5-byte jmp at 0xf17730), read here after the patches are
 *   applied; BB_POTION_FIX=1/0 overrides it.
 * - The trigger volume tests an entity only if its bit is set in the mask at trigger +0x450
 *   (bit = entity id (+0x88) & 0xfff; 0xddae20 clears the dropper's bit, 0xe0bc10 sets it back after
 *   _timeBeforeCanHitUser).
 * - The potion's CEntityUpdateMessage handler 0xf14020 (42 bytes, no frame, short jumps: it cannot
 *   be copied) is replaced by potion_update below, which runs the same instructions after calling
 *   potion_watch: each frame that measures the distance between this PC's own kart and the potion
 *   and logs a pass closer than PASS_REPORT that the game's touch callback did not see.
 * - Racers (manager at *0x2ad4b70, list at +0x10: count +0xc, array +0x20): a racer's _kart handle
 *   is at +0x20, _isAiControlled +0x40, _hasLocalAuthority +0xb0. A handle's target is at +0x28
 *   unless its flags (first dword) have 0x10000000 (not resolved yet) or 0x20000000 (a redirection).
 * - CKartDamageComponent (type at 0x2ac5018): the damage state in progress at +0x40 (-1: none);
 *   0xe346f0 (component, 0) is the game's "can this kart be damaged now" test, which the potion's
 *   explosion (0xf14750) asks before it damages its victim. */
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
typedef void *(ABI *GetComponent)(void *, void *, uint64_t);
typedef uint64_t (ABI *CanDamage)(void *, uint64_t);

static unsigned char *g_image;
static Fn6 orig_touch, orig_impact, orig_state, orig_damage, orig_kart_touch;
static FindRacer find_racer;
static GetComponent get_component_fn;
static CanDamage can_damage_fn;
static void **racers;
static int potion_fix;                          /* 1: leave other players' potion touches to their PCs */
static __attribute__((used)) void *g_thrown_update; /* 0xf16c60, the thrown potion's flight (potion_update) */
static _Thread_local int from_network;
static _Thread_local void *touch_kart;          /* the kart whose potion touch is being handled */
static _Thread_local int touch_damage;          /* 1 + the damage type that started for it meanwhile */

#define OFF_TOUCH 0xf163a0u
#define OFF_IMPACT 0xe3c670u
#define OFF_STATE 0xf14500u
#define OFF_NET_STATE 0xf5c790u
#define OFF_DAMAGE 0xe34850u
#define OFF_FIND_RACER 0xfd4230u
#define OFF_RACERS 0x2ad4b70u
#define OFF_KART_TOUCH 0xf17570u
#define OFF_UPDATE 0xf14020u
#define OFF_THROWN_UPDATE 0xf16c60u
#define OFF_GET_COMPONENT 0x3dbf90u
#define OFF_CAN_DAMAGE 0xe346f0u
#define OFF_T_KART_DAMAGE 0x2ac5018u
#define OFF_T_TRIGGER 0x2adb578u
#define OFF_FIX_THUNK 0xf17730u
#define OFF_FIX_FLAG 0xf1773fu
#define OFF_END (OFF_T_TRIGGER + 8u)

#define PASS_NEAR 600.0f   /* a pass is followed while the kart is this close (a touch happens at about 100) */
#define PASS_REPORT 200.0f /* and logged if it came this close without a touch */

static const unsigned char frame17_38[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x83,0xec,0x38};
static const unsigned char frame17_28[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x83,0xec,0x28};
static const unsigned char state_code[] = {0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x49,0x89,0xfe,0x89,0xf3,
                                           0x41,0x8b,0x86,0xc0,0x00,0x00,0x00};
static const unsigned char net_state_code[] = {0xe9,0x6b,0x7d,0xfb,0xff,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
static const unsigned char find_racer_code[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x50};
static const unsigned char kart_touch_code[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x54,0x53,0x48,0x83,0xec,0x30};
static const unsigned char thrown_update_code[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x54,0x53,0x48,0x83,0xec,0x20};
static const unsigned char update_code[] = {0x80,0x7f,0x38,0x00,0x75,0x19,0x48,0x8b,0x47,0x18,0x48,0x85,0xc0,0x74,0x06,
                                            0xf6,0x40,0x3b,0x01,0x74,0x09,0x83,0xbf,0xc0,0x00,0x00,0x00,0x03,0x74,0x07,
                                            0xc3,0xc6,0x47,0x38,0x00,0xeb,0xe1,0xe9,0x16,0x2c,0x00,0x00};
static const unsigned char fix_thunk_code[] = {0xe9,0x9b,0x00,0x00,0x00,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};

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

static int int_at(const void *p, size_t off) {
    int v;
    memcpy(&v, (const unsigned char *)p + off, sizeof v);
    return v;
}

/* What a handle points to, without the game's resolver (NULL if the handle still needs it). */
static void *handle_entity(void *h) {
    for (int i = 0; h && i < 8; i++) {
        const uint32_t flags = (uint32_t)int_at(h, 0);
        if (flags & 0x10000000u) return NULL;
        void *target = ptr_at(h, 0x28);
        if (!(flags & 0x20000000u)) return target;
        if (!target) return NULL;
        h = ptr_at(target, 0x10);
    }
    return NULL;
}

/* The game's racer for a kart; NULL for anything else. The lookup reads the entity's component
 * list (CEntity _components, +0x18): an entity being torn down has none, and the game's lookup
 * would read through a null pointer. */
static void *racer_of(void *entity) {
    return entity && find_racer && racers && *racers && ptr_at(entity, 0x18) ? find_racer(*racers, entity) : NULL;
}

static void *component(void *entity, uint32_t type_offset) {
    void *type = ptr_at(g_image, type_offset);
    return entity && type && get_component_fn && ptr_at(entity, 0x18) ? get_component_fn(entity, type, 0) : NULL;
}

/* The kart this PC's player drives (NULL outside a race, and once the player has finished: the
 * game then drives the kart). */
static const char *my_kart_missing = "no race"; /* why the last my_kart() found none (for the log) */
static void *my_kart(void) {
    void *manager = racers ? *racers : NULL;
    void *list = manager ? ptr_at(manager, 0x10) : NULL;
    my_kart_missing = "no race";
    if (!list) return NULL;
    const int count = int_at(list, 0xc);
    void **racer = ptr_at(list, 0x20);
    if (!racer || count <= 0 || count > 64) return NULL;
    my_kart_missing = "no racer driven by this PC's player";
    for (int i = 0; i < count; i++) {
        const unsigned char *r = racer[i];
        if (r && r[0xb0] && !r[0x40]) { /* _hasLocalAuthority, not AI */
            void *kart = handle_entity(ptr_at(r, 0x20)); /* _kart */
            if (!kart) my_kart_missing = "its handle is not resolved";
            return kart;
        }
    }
    return NULL;
}

/* The damage state in progress on a kart (-1: none; -2: not known). */
static int kart_damage_state(void *kart, void **damage_component) {
    void *c = component(kart, OFF_T_KART_DAMAGE);
    if (damage_component) *damage_component = c;
    return c ? int_at(c, 0x40) : -2;
}

/* 1 if the potion's trigger volume tests this kart, 0 if the kart is masked out, -1 if not known. */
static int trigger_tests(void *potion, void *kart) {
    const unsigned char *trigger = component(potion, OFF_T_TRIGGER);
    if (!trigger || !kart) return -1;
    const uint32_t id = (uint32_t)int_at(kart, 0x88);
    return ((uint32_t)int_at(trigger, 0x450 + ((id >> 5) & 0x7f) * 4) >> (id & 0x1f)) & 1;
}

static unsigned entity_id(const void *entity) { return entity ? (unsigned)int_at(entity, 0x88) : 0; }

/* "your kart" / "player 3's kart (on another PC)" / "an AI kart (run by this PC)" / "an object ...". */
static void describe(void *entity, char *out, size_t cap) {
    if (!entity) {
        snprintf(out, cap, "nothing");
        return;
    }
    void *racer = racer_of(entity);
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
    char line[768];
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
static const char *damage_name(int t) { return t >= 0 && t <= 10 ? damage_type[t] : "?"; }

/* This PC's own kart near a potion: followed from PASS_NEAR until it leaves or the potion goes. */
typedef struct {
    void *self;          /* the potion's component; NULL: free */
    int64_t seen_us, closest_us;
    float closest, kart[3], potion[3];
    int state, tested, mine, kart_damage, touched, frames;
} Pass;
static Pass passes[32];

static Pass *pass_find(const void *self) {
    for (size_t i = 0; i < sizeof passes / sizeof *passes; i++)
        if (passes[i].self == self) return &passes[i];
    return NULL;
}

static Pass *pass_new(void *self, int64_t now) {
    Pass *free_slot = NULL;
    for (size_t i = 0; i < sizeof passes / sizeof *passes && !free_slot; i++)
        if (!passes[i].self || now - passes[i].seen_us > 2000000) free_slot = &passes[i]; /* its potion is gone */
    if (!free_slot) return NULL;
    memset(free_slot, 0, sizeof *free_slot);
    free_slot->self = self;
    free_slot->closest = 1e30f;
    free_slot->tested = -1;
    free_slot->kart_damage = -2;
    return free_slot;
}

static void pass_end(Pass *p, void *potion, int64_t now) {
    if (!p->touched && p->closest < PASS_REPORT)
        item_log("YOUR kart passed potion %p (id %u, owned by %s, %s%s) WITHOUT a touch on this PC: closest %.0f, %.2f s ago, "
                 "potion at (%.1f %.1f %.1f), your kart at (%.1f %.1f %.1f); the potion's trigger %s your kart; "
                 "your kart's damage state then: %d; %d frames watched",
                 potion, entity_id(potion), has_authority(potion) == 1 ? "this PC" : "another PC", state_name(p->state),
                 p->mine ? ", dropped by you" : "", (double)p->closest, (double)(now - p->closest_us) / 1e6,
                 (double)p->potion[0], (double)p->potion[1], (double)p->potion[2],
                 (double)p->kart[0], (double)p->kart[1], (double)p->kart[2],
                 p->tested == 1 ? "tests" : p->tested == 0 ? "does NOT test (masks out)" : "(unknown if it tests)",
                 p->kart_damage, p->frames);
    p->self = NULL;
}

/* Each frame, for each potion (from the potion's update below; only reads the game's memory). */
static __attribute__((used)) ABI void potion_watch(void *self) {
    static int announced;
    if (!self) return;
    if (!announced) {
        announced = 1;
        item_log("potion pass check is running (the game updates potions every frame)");
    }
    const int state = int_at(self, 0xc0);
    Pass *p = pass_find(self);
    if (state != 2 && state != 3 && state != 4) { /* not lying on the track (any more) */
        if (p) p->self = NULL;
        return;
    }
    void *potion = ptr_at(self, 0x18);
    void *kart = my_kart();
    if (!potion || !kart) return;
    float k[3], q[3];
    position(kart, k);
    position(potion, q);
    const float d = distance(k, q);
    if (d >= PASS_NEAR) {
        if (p) pass_end(p, potion, runtime_wall_now_us());
        return;
    }
    const int64_t now = runtime_wall_now_us();
    if (!p && !(p = pass_new(self, now))) return;
    p->seen_us = now;
    p->frames++;
    if (d < p->closest) {
        p->closest = d;
        p->closest_us = now;
        p->state = state;
        memcpy(p->kart, k, sizeof k);
        memcpy(p->potion, q, sizeof q);
        if (d < PASS_REPORT) {
            p->tested = trigger_tests(potion, kart);
            p->mine = handle_entity(ptr_at(self, 0x28)) == kart;
            p->kart_damage = kart_damage_state(kart, NULL);
        }
    }
}

/* Replaces the potion's CEntityUpdateMessage handler (0xf14020): potion_watch, then the handler's own
 * instructions with every argument register as it came in. */
__attribute__((naked)) static void potion_update(void) {
    __asm__ volatile(
        "push %rdi\n\t" "push %rsi\n\t" "push %rdx\n\t" "push %rcx\n\t" "push %r8\n\t" "push %r9\n\t"
        "sub $136, %rsp\n\t"
        "movups %xmm0, 0(%rsp)\n\t" "movups %xmm1, 16(%rsp)\n\t" "movups %xmm2, 32(%rsp)\n\t" "movups %xmm3, 48(%rsp)\n\t"
        "movups %xmm4, 64(%rsp)\n\t" "movups %xmm5, 80(%rsp)\n\t" "movups %xmm6, 96(%rsp)\n\t" "movups %xmm7, 112(%rsp)\n\t"
        "call potion_watch\n\t"
        "movups 0(%rsp), %xmm0\n\t" "movups 16(%rsp), %xmm1\n\t" "movups 32(%rsp), %xmm2\n\t" "movups 48(%rsp), %xmm3\n\t"
        "movups 64(%rsp), %xmm4\n\t" "movups 80(%rsp), %xmm5\n\t" "movups 96(%rsp), %xmm6\n\t" "movups 112(%rsp), %xmm7\n\t"
        "add $136, %rsp\n\t"
        "pop %r9\n\t" "pop %r8\n\t" "pop %rcx\n\t" "pop %rdx\n\t" "pop %rsi\n\t" "pop %rdi\n\t"
        "cmpb $0, 0x38(%rdi)\n\t"          /* the game's handler from here */
        "je 1f\n\t"
        "movb $0, 0x38(%rdi)\n\t"
        "1:\n\t"
        "mov 0x18(%rdi), %rax\n\t"         /* the potion's entity */
        "test %rax, %rax\n\t"
        "je 2f\n\t"
        "testb $1, 0x3b(%rax)\n\t"         /* _netHasAuthority */
        "je 3f\n\t"
        "2:\n\t"
        "cmpl $3, 0xc0(%rdi)\n\t"          /* thrown */
        "je 4f\n\t"
        "3:\n\t"
        "ret\n\t"
        "4:\n\t"
        "jmp *g_thrown_update(%rip)\n\t");
}

/* A kart entered a dropped potion's trigger volume (the game calls this on every PC). */
static uint64_t ABI kart_touch(void *self, uint64_t a1, uint64_t other, uint64_t a3, uint64_t a4, uint64_t a5) {
    static void *skipped_self, *skipped_kart;
    static int64_t skipped_us;
    void *toucher = (void *)(uintptr_t)other;
    if (!self || !toucher) return orig_kart_touch(self, a1, other, a3, a4, a5);
    void *potion = ptr_at(self, 0x18);
    const unsigned char *racer = racer_of(toucher);
    const int mine = racer && racer[0xb0] && !racer[0x40];
    /* A human's kart that another PC drives: not AI, no local authority in the racer or the entity. */
    const int elsewhere = racer && !racer[0x40] && !racer[0xb0] && has_authority(toucher) == 0;
    const int before = int_at(self, 0xc0);
    const int owner = has_authority(potion);
    float p[3], k[3];
    position(potion, p);
    position(toucher, k);
    char who[96];
    describe(toucher, who, sizeof who); /* before: the touch may remove what it touched */
    if (potion_fix && elsewhere) {
        const int64_t now = runtime_wall_now_us();
        if (skipped_self != self || skipped_kart != toucher || now - skipped_us > 1000000)
            item_log("potion %p (id %u, owned by %s, %s) at (%.1f %.1f %.1f) touched on this PC's screen by %s at (%.1f %.1f %.1f), %.0f apart "
                     "-> left to that player's PC (potion fix)",
                     potion, entity_id(potion), owner == 1 ? "this PC" : "another PC", state_name(before),
                     (double)p[0], (double)p[1], (double)p[2], who, (double)k[0], (double)k[1], (double)k[2],
                     (double)distance(p, k));
        skipped_self = self;
        skipped_kart = toucher;
        skipped_us = now;
        return 0;
    }
    void *damage_component = NULL;
    int kart_damage = -2, can = -1;
    if (mine) {
        kart_damage = kart_damage_state(toucher, &damage_component);
        if (damage_component && can_damage_fn) can = (int)(can_damage_fn(damage_component, 0) & 0xff); /* as the explosion asks */
        Pass *pass = pass_find(self);
        if (pass) pass->touched = 1;
    }
    void *outer_kart = touch_kart;
    const int outer_damage = touch_damage;
    touch_kart = toucher;
    touch_damage = 0;
    const uint64_t r = orig_kart_touch(self, a1, other, a3, a4, a5);
    const int started = touch_damage;
    touch_kart = outer_kart;
    touch_damage = outer_damage;
    const int after = int_at(self, 0xc0);
    char result[192];
    if (after == before)
        snprintf(result, sizeof result, "the game ignored the touch (the potion stays %s)", state_name(after));
    else if (after != 5)
        snprintf(result, sizeof result, "the potion is now %s", state_name(after));
    else if (started)
        snprintf(result, sizeof result, "exploded, damage started (%s)", damage_name(started - 1));
    else if (!mine)
        snprintf(result, sizeof result, "exploded, no damage started on this PC");
    else if (kart_damage >= 0)
        snprintf(result, sizeof result, "exploded, NO DAMAGE to your kart: it was already in damage state %d (%s)",
                 kart_damage, damage_name(kart_damage));
    else if (can == 0)
        snprintf(result, sizeof result, "exploded, NO DAMAGE to your kart: it was protected (mask, shield or invulnerable)");
    else
        snprintf(result, sizeof result, "exploded, NO DAMAGE to your kart: reason not known (damage state %d, can be damaged %d)",
                 kart_damage, can);
    item_log("potion %p (id %u, owned by %s, %s) at (%.1f %.1f %.1f) touched on this PC by %s at (%.1f %.1f %.1f), %.0f apart -> %s",
             potion, entity_id(potion), owner == 1 ? "this PC" : "another PC", state_name(before),
             (double)p[0], (double)p[1], (double)p[2], who, (double)k[0], (double)k[1], (double)k[2],
             (double)distance(p, k), result);
    return r;
}

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
    const int owner = has_authority(potion);
    const unsigned id = entity_id(potion);
    char victim[96] = "";
    float p[3] = {0}, mine[3];
    float away = -1.0f;
    const char *missing = "";
    if (self && before != (int)state && (int)state == 5) { /* before: the explosion may remove things */
        describe(handle_entity(ptr_at(self, 0xb8)), victim, sizeof victim);
        void *kart = my_kart();
        position(potion, p);
        if (kart && potion) {
            position(kart, mine);
            away = distance(p, mine);
        } else missing = my_kart_missing;
    }
    const uint64_t r = orig_state(self, state, a2, a3, a4, a5);
    if (self && ((int)state == 5 || (int)state == 6)) {
        Pass *pass = pass_find(self);
        if (pass) pass->self = NULL;
    }
    if (before != (int)state && self) {
        float e[3];
        memcpy(e, (unsigned char *)self + 0xa8, sizeof e); /* _explosionPosition */
        if ((int)state == 5) {
            char mine_text[80];
            if (away >= 0.0f) snprintf(mine_text, sizeof mine_text, "your kart was %.0f away", (double)away);
            else snprintf(mine_text, sizeof mine_text, "your kart: not found (%s)", missing);
            item_log("potion %p (id %u, owned by %s): %s -> exploding, set %s; at (%.1f %.1f %.1f), explodes at (%.1f %.1f %.1f); victim: %s; %s",
                     potion, id, owner == 1 ? "this PC" : "another PC", state_name(before),
                     net ? "by the owner's PC over the network" : "on this PC", (double)p[0], (double)p[1], (double)p[2],
                     (double)e[0], (double)e[1], (double)e[2], victim, mine_text);
        } else {
            position(potion, p);
            item_log("potion %p (id %u, owned by %s): %s -> %s, set %s; at (%.1f %.1f %.1f)", potion, id,
                     owner == 1 ? "this PC" : "another PC", state_name(before), state_name((int)state),
                     net ? "by the owner's PC over the network" : "on this PC", (double)p[0], (double)p[1], (double)p[2]);
        }
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
    if (kart && kart == touch_kart) touch_damage = t + 1;
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
    if (on && strcmp(on, "0") == 0) {
        puts("Item trace and potion fix: off (BB_ITEM_TRACE=0)");
        return 0;
    }
    if (size < OFF_END) return 0;
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
    if (!memcmp(image + OFF_GET_COMPONENT, find_racer_code, sizeof find_racer_code))
        get_component_fn = (GetComponent)(image + OFF_GET_COMPONENT);
    if (!memcmp(image + OFF_CAN_DAMAGE, find_racer_code, sizeof find_racer_code))
        can_damage_fn = (CanDamage)(image + OFF_CAN_DAMAGE);
    if (find_racer) /* the touch log and the fix both need to know whose kart it is */
        orig_kart_touch = hook(OFF_KART_TOUCH, kart_touch_code, sizeof kart_touch_code, (void *)kart_touch, "potion kart touch");
    int watch = 0;
    if (find_racer && !memcmp(image + OFF_UPDATE, update_code, sizeof update_code) &&
        !memcmp(image + OFF_THROWN_UPDATE, thrown_update_code, sizeof thrown_update_code) && writable(image + OFF_UPDATE, 14)) {
        g_thrown_update = image + OFF_THROWN_UPDATE;
        jump(image + OFF_UPDATE, (void *)potion_update);
        watch = 1;
    }
    /* The Mods page's patch marks the padding after the thunk at 0xf17730 (see the top of this file). */
    const char *fix = getenv("BB_POTION_FIX");
    const int marked = !memcmp(image + OFF_FIX_THUNK, fix_thunk_code, sizeof fix_thunk_code) && image[OFF_FIX_FLAG] == 0xcc;
    potion_fix = orig_kart_touch && (fix && *fix ? strcmp(fix, "0") != 0 : marked);
    int net = 0;
    if (orig_state && !memcmp(image + OFF_NET_STATE, net_state_code, sizeof net_state_code) &&
        writable(image + OFF_NET_STATE, 14)) {
        jump(image + OFF_NET_STATE, (void *)net_set_state);
        net = 1;
    }
#ifdef _WIN32
    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
#endif
    printf("Item trace: potion touch %s, power-up impact %s, potion state %s (network %s), kart damage %s, racers %s, "
           "potion kart touch %s, potion pass check %s\n",
           orig_touch ? "on" : "off", orig_impact ? "on" : "off", orig_state ? "on" : "off", net ? "on" : "off",
           orig_damage ? "on" : "off", find_racer ? "known" : "unknown", orig_kart_touch ? "on" : "off", watch ? "on" : "off");
    printf("Potion fix (other players' potion touches are left to their own PCs): %s%s\n", potion_fix ? "ON" : "off",
           potion_fix ? "" : !orig_kart_touch ? " (the game's code was not recognised)" :
           fix && *fix ? " (BB_POTION_FIX)" : " (turn it on in the Mods page)");
    return 1;
}
