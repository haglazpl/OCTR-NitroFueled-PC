#include "runtime_net.h"
#include "runtime_net_overrides.h"
#include "runtime_net_tunnel.h"
#include "runtime_net_ping.h"
#include "runtime_friends.h"
#include "runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <stdatomic.h>
#include <pthread.h>

#define ORBIS_OK 0
#define ORBIS_NET_ENETUNREACH ((int32_t)0x80410133)
#define ORBIS_NET_EINVAL      ((int32_t)0x80410116)
#define ORBIS_NET_EWOULDBLOCK ((int32_t)0x80410123)
#define ORBIS_NET_EBADF       ((int32_t)0x80410109)
#define ORBIS_NET_EHOSTUNREACH ((int32_t)0x80410141)

#define NET_CTL_NOT_CONNECTED ((int32_t)0x80412108)
#define NET_CTL_INVALID_ADDR  ((int32_t)0x80412107)

static int g_net_initialized = 0;
static void clock_check_start(void); /* the PC clock check (below) */
/* sceNetErrnoLoc is per thread on the PS4. One value shared by every thread let a thread read
 * another one's error (a failure in place of its own EWOULDBLOCK, for example). */
static _Thread_local int32_t g_net_errno = 0;

/* A Winsock error as the PS4's BSD errno (WSAExxx is 10000 + the BSD value). */
static int32_t net_errno_from(int err) {
#ifdef _WIN32
    if (err > 10000 && err < 10100) return err - 10000;
#endif
    return err;
}

int runtime_net_is_online(void) {
    const char *val = getenv("BB_ONLINE");
    return (val && strcmp(val, "1") == 0);
}

static int net_trace_level(void) {
    static int trace_checked = 0;
    static int level = 0;
    if (!trace_checked) {
        trace_checked = 1;
        const char *t = getenv("BB_NET_TRACE");
        if (t && strcmp(t, "2") == 0) level = 2; /* 2 = full per-packet trace */
        else if ((t && strcmp(t, "1") == 0) || runtime_net_is_online()) level = 1; /* 1 = setup/events only */
    }
    return level;
}

void runtime_net_trace(const char *fmt, ...) {
    if (net_trace_level() < 1) return;

    va_list ap;
    va_start(ap, fmt);
    printf("[NET] ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    fflush(stdout);
}

/* High-frequency packet trace: only runs if BB_NET_TRACE=2 so races never stall on stdout I/O */
static void runtime_net_pkt_trace(const char *fmt, ...) {
    if (net_trace_level() < 2) return;

    va_list ap;
    va_start(ap, fmt);
    printf("[NET] ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    fflush(stdout);
}

int32_t runtime_net_init(void) {
    if (!g_net_initialized) {
#ifdef _WIN32
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            printf("[NET] WSAStartup failed\n");
            return -1;
        }
#endif
        net_overrides_init();
        g_net_initialized = 1;
        runtime_net_trace("sceNetInit completed (NET-PATCH v8: peeks kept, per-player summary, one copy per datagram, one player per address, corrected and slewed wall clock, clock, sender and send-chain diagnostics)");
        clock_check_start();
    }
    runtime_friends_start();
    return ORBIS_OK;
}

int32_t runtime_net_term(void) {
    if (g_net_initialized) {
#ifdef _WIN32
        WSACleanup();
#endif
        g_net_initialized = 0;
        runtime_net_trace("sceNetTerm completed");
    }
    return ORBIS_OK;
}

int32_t *runtime_net_errno_loc(void) {
    return &g_net_errno;
}

/* Socket table management */
#define MAX_VIRTUAL_SOCKETS 256

typedef struct {
    SOCKET s;
    int in_use;
    int is_stream;
    int non_blocking;
    int tunnel; /* the game's UDP socket (port 3074): runtime_net_tunnel.h */
    char name[32];
} VSocket;

static VSocket g_sockets[MAX_VIRTUAL_SOCKETS];

/* The game socket reads into a buffer with room for a tunnel header, which is stripped, so a
 * peek there takes the datagram out of the OS socket: it is kept here, unwrapped, for the next
 * read, and epoll reports the socket readable while it waits. fd 0: none. */
static struct { int fd; int len; struct sockaddr_in from; uint8_t data[2048]; } g_peeked;
static uint64_t now_ms(void);
static int tunnel_server(struct sockaddr_in *out);
/* The WebAPI invitation session can remain active in Arcade. A private race
 * with another player has game UDP traffic to that peer before track assets
 * load; Arcade has only server traffic. Let old peer activity expire when the
 * player leaves the lobby. */
static uint64_t g_last_game_peer_ms;

int runtime_net_private_lobby_active(void) {
    const uint64_t last = __atomic_load_n(&g_last_game_peer_ms, __ATOMIC_ACQUIRE);
    const uint64_t now = now_ms();
    return last && now >= last && now - last < 5000;
}

static void note_game_peer(const VSocket *vs, const struct sockaddr_in *peer) {
    struct sockaddr_in server;
    if (!vs->tunnel || !peer || !tunnel_server(&server) ||
        peer->sin_addr.s_addr == server.sin_addr.s_addr) return;
    const uint64_t now = now_ms();
    const uint64_t old = __atomic_exchange_n(&g_last_game_peer_ms, now, __ATOMIC_RELEASE);
    if (!old || now - old >= 5000) runtime_net_trace("Speed: game peer active");
}

static int vsocket_alloc(SOCKET s, int is_stream, const char *name) {
    for (int i = 0; i < MAX_VIRTUAL_SOCKETS; i++) {
        if (!g_sockets[i].in_use) {
            g_sockets[i].s = s;
            g_sockets[i].in_use = 1;
            g_sockets[i].is_stream = is_stream;
            g_sockets[i].non_blocking = 0;
            g_sockets[i].tunnel = 0;
            if (name) strncpy(g_sockets[i].name, name, sizeof(g_sockets[i].name) - 1);
            else g_sockets[i].name[0] = '\0';
            return i + 1; /* 1-based handle */
        }
    }
    return -1;
}

static VSocket *vsocket_get(int fd) {
    int idx = fd - 1;
    if (idx < 0 || idx >= MAX_VIRTUAL_SOCKETS || !g_sockets[idx].in_use) return NULL;
    return &g_sockets[idx];
}

static void vsocket_free(int fd) {
    int idx = fd - 1;
    if (idx >= 0 && idx < MAX_VIRTUAL_SOCKETS) {
        g_sockets[idx].in_use = 0;
        g_sockets[idx].s = INVALID_SOCKET;
    }
}

int32_t runtime_net_socket(const char *name, int domain, int type, int protocol) {
    runtime_net_trace("sceNetSocket(name='%s', dom=%d, type=0x%x, proto=%d)",
                      name ? name : "", domain, type, protocol);

    if (!runtime_net_is_online()) {
        g_net_errno = 51;
        runtime_net_trace("sceNetSocket (offline) -> ENETUNREACH");
        return ORBIS_NET_ENETUNREACH;
    }
    runtime_net_init();

    int win_domain = domain;
    if (domain == 28) {
#ifdef AF_INET6
        win_domain = AF_INET6;
#else
        win_domain = 23;
#endif
    }

    int base_type = type & 0xF;
    int is_stream = (base_type == SOCK_STREAM);
    int is_nonblock = ((type & 0x20000000) != 0) || ((type & 0x04000000) != 0);

    SOCKET s = socket(win_domain, base_type, protocol);
    if (s == INVALID_SOCKET) {
        g_net_errno = net_errno_from(WSAGetLastError());
        runtime_net_trace("sceNetSocket failed: %d (win_domain=%d, base_type=%d, proto=%d)",
                          g_net_errno, win_domain, base_type, protocol);
        return -1;
    }

    if (!is_stream) {
        /* Room for bursts from 6-8 players (UDP only; TCP keeps Windows' auto-tuning). */
        int buf_size = 1048576;
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&buf_size, sizeof(buf_size));
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char *)&buf_size, sizeof(buf_size));
    }

    if (is_nonblock) {
        unsigned long on = 1;
        ioctlsocket(s, FIONBIO, &on);
    }

#ifdef _WIN32
    if (!is_stream) {
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
        BOOL bNewBehavior = FALSE;
        DWORD dwBytesReturned = 0;
        WSAIoctl(s, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), NULL, 0, &dwBytesReturned, NULL, NULL);
    } else {
        int flag = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&flag, sizeof(flag));
    }
#endif

    int vfd = vsocket_alloc(s, is_stream, name);
    if (vfd > 0 && is_nonblock) {
        VSocket *vs = vsocket_get(vfd);
        if (vs) vs->non_blocking = 1;
    }

    int actual_rcv = 0;
    NativeSockLen opt_len = sizeof(actual_rcv);
    getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&actual_rcv, &opt_len);
    runtime_net_trace("[NET-PATCH] sceNetSocket '%s' -> fd=%d (sock=%llu, nonblock=%d, SO_RCVBUF=%d)",
                      name ? name : "", vfd, (unsigned long long)s, is_nonblock, actual_rcv);
    return vfd;
}

int32_t runtime_net_socket_close(int s) {
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;

    runtime_net_trace("sceNetSocketClose(fd=%d)", s);
    if (g_peeked.fd == s) g_peeked.fd = 0;
    closesocket(vs->s);
    vsocket_free(s);
    return ORBIS_OK;
}

int32_t runtime_net_socket_abort(int s, int flags) {
    (void)flags;
    return runtime_net_socket_close(s);
}

int32_t runtime_net_connect(int s, const OrbisNetSockaddr *addr, uint32_t addrlen) {
    (void)addrlen;
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;
    if (!addr) return ORBIS_NET_EINVAL;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    const OrbisNetSockaddrIn *in = (const OrbisNetSockaddrIn *)addr;
    sin.sin_family = in->sin_family;
    sin.sin_port = in->sin_port;
    memcpy(&sin.sin_addr, &in->sin_addr, sizeof(sin.sin_addr));

    char ip_str[32] = {0};
    inet_ntop(AF_INET, &sin.sin_addr, ip_str, sizeof(ip_str));
    runtime_net_trace("sceNetConnect(fd=%d, to=%s:%u)", s, ip_str, ntohs(sin.sin_port));

    int ret = connect(vs->s, (struct sockaddr *)&sin, sizeof(sin));
    if (ret != 0) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
            g_net_errno = 36; /* EINPROGRESS */
            runtime_net_trace("sceNetConnect -> EINPROGRESS");
            return -1;
        }
        g_net_errno = net_errno_from(err);
        runtime_net_trace("sceNetConnect failed: %d", err);
        return -1;
    }
    return ORBIS_OK;
}

/* Whether the RyuNET server runs on this machine: no server set, loopback, or one of this
 * PC's own addresses (a Radmin/ZeroTier/LAN IP its friends also use). Only an address that
 * belongs to this machine can be bound, which is how it is told apart. The game then must not
 * take the server's UDP 3074: Windows lets both sockets bind it, and the game's NAT probes
 * came back to the game itself instead of the server ("could not start the network"). */
static int server_is_this_machine(void) {
    static int cached = -1;
    if (cached >= 0) return cached;
    const char *srv = getenv("BB_ONLINE_SERVER");
    if (!srv || !*srv || strcmp(srv, "127.0.0.1") == 0 || _stricmp(srv, "localhost") == 0) return cached = 1;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(srv, NULL, &hints, &res) != 0 || !res) return cached = 0;
    struct sockaddr_in addr = *(const struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    if ((ntohl(addr.sin_addr.s_addr) >> 24) == 127) return cached = 1;
    SOCKET probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (probe == INVALID_SOCKET) return cached = 0;
    addr.sin_port = 0;
    cached = bind(probe, (struct sockaddr *)&addr, sizeof(addr)) == 0;
    closesocket(probe);
    runtime_net_trace("RyuNET server %s is %s", srv, cached ? "this machine: the game avoids UDP 3074" : "another machine");
    return cached;
}

/* This PC's address on the network it reaches the RyuNET server through (the LAN, or a
 * Radmin/ZeroTier one). The game puts it in its host address as the local address, which
 * players behind the same router (same public IP) connect through, as two PS4s at home do.
 * 127.0.0.1 there made each of them connect to itself, so they could never join each other.
 * Connecting a UDP socket sends nothing: it only asks the OS which route and source it uses. */
static const char *local_ipv4(void) {
    static char cached[16];
    if (cached[0]) return cached;
    snprintf(cached, sizeof(cached), "127.0.0.1");
    const char *srv = getenv("BB_ONLINE_SERVER");
    if (!srv || !*srv) return cached;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(srv, NULL, &hints, &res) != 0 || !res) return cached;
    struct sockaddr_in to = *(const struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    to.sin_port = htons(3074);
    SOCKET probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (probe == INVALID_SOCKET) return cached;
    struct sockaddr_in me;
    socklen_t me_len = sizeof(me);
    memset(&me, 0, sizeof(me));
    if (connect(probe, (struct sockaddr *)&to, sizeof(to)) == 0 &&
        getsockname(probe, (struct sockaddr *)&me, &me_len) == 0 && me.sin_addr.s_addr != 0) {
        const unsigned char *b = (const unsigned char *)&me.sin_addr.s_addr;
        snprintf(cached, sizeof(cached), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    }
    closesocket(probe);
    runtime_net_trace("Local address for other players on this network: %s", cached);
    return cached;
}

/* --- RyuNET tunnel (runtime_net_tunnel.h): the game socket's path through the server ------ */

static uint64_t now_ms(void) {
#ifdef _WIN32
    /* QueryPerformanceCounter: GetTickCount64 moves in 15.6 ms steps, too coarse for the relay
     * pings and the per-player summary. */
    static LARGE_INTEGER freq;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    const uint64_t f = (uint64_t)freq.QuadPart, t = (uint64_t)c.QuadPart;
    return (t / f) * 1000u + (t % f) * 1000u / f;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

/* The server's NAT port (UDP 3074, BB_ONLINE_NAT_PORT); 0 when the tunnel is off
 * (BB_ONLINE_TUNNEL=0, offline, or the server's address does not resolve). */
static int tunnel_server(struct sockaddr_in *out) {
    static int state = -1;
    static struct sockaddr_in server;
    if (state < 0) {
        state = 0;
        const char *off = getenv("BB_ONLINE_TUNNEL");
        const char *srv = getenv("BB_ONLINE_SERVER");
        if (runtime_net_is_online() && !(off && strcmp(off, "0") == 0) && srv && *srv) {
            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            if (getaddrinfo(srv, NULL, &hints, &res) == 0 && res) {
                server = *(const struct sockaddr_in *)res->ai_addr;
                freeaddrinfo(res);
                const char *p = getenv("BB_ONLINE_NAT_PORT");
                server.sin_port = htons((uint16_t)(p && atoi(p) > 0 ? atoi(p) : 3074));
                state = 1;
                runtime_net_trace("Tunnel: through %s:%u for peers without a direct path",
                                  inet_ntoa(server.sin_addr), ntohs(server.sin_port));
            }
        }
    }
    if (state == 1 && out) *out = server;
    return state == 1;
}

static int from_server(const struct sockaddr_in *from, const struct sockaddr_in *server) {
    return from->sin_addr.s_addr == server->sin_addr.s_addr && from->sin_port == server->sin_port;
}

static struct sockaddr_in addr_of(uint32_t ip, uint16_t port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = ip;
    a.sin_port = htons(port);
    return a;
}

/* Keeps this socket's paths open: to the server (asking for a pass for the regional relays
 * unless BB_ONLINE_RELAYS=0) and, registered with that pass, to every relay. */
static void tunnel_keepalive(VSocket *vs, const struct sockaddr_in *server) {
    static int relays_wanted = -1;
    if (relays_wanted < 0) {
        const char *v = getenv("BB_ONLINE_RELAYS");
        relays_wanted = !(v && strcmp(v, "0") == 0);
        if (relays_wanted && v && *v && strcmp(v, "1") != 0) {
            tun_force_relay(v);
            runtime_net_trace("Tunnel: relay %s chosen (BB_ONLINE_RELAYS)", v);
        }
    }
    const uint64_t now = now_ms();
    if (tun_keepalive_due(now)) {
        uint8_t request[TUN_REQUEST_LEN];
        const size_t n = relays_wanted ? tun_pass_request(request, sizeof(request), now) : 0;
        if (n) sendto(vs->s, (const char *)request, (int)n, 0, (const struct sockaddr *)server, sizeof(*server));
        else sendto(vs->s, TUN_KEEPALIVE, TUN_KEEPALIVE_LEN, 0, (const struct sockaddr *)server, sizeof(*server));
    }
    const int relays = tun_relay_count();
    for (int i = 0; i < relays; i++) {
        uint8_t reg[6 + TUN_PASS_LEN + 4];
        uint32_t ip;
        uint16_t port;
        const size_t n = tun_relay_register(i, now, reg, sizeof(reg), &ip, &port);
        if (!n) continue;
        const struct sockaddr_in to = addr_of(ip, port);
        sendto(vs->s, (const char *)reg, (int)n, 0, (const struct sockaddr *)&to, sizeof(to));
    }
}

/* RyuNET ping (runtime_net_ping.h): the round trip to the players in the room, on the game
 * socket of a port with the tunnel. Off with BB_ONLINE_PING=0. */
static int ping_enabled(void) {
    static int state = -1;
    if (state < 0) {
        const char *v = getenv("BB_ONLINE_PING");
        state = !(v && strcmp(v, "0") == 0) && tunnel_server(NULL);
        if (state) ping_set_name(getenv("BB_ONLINE_NAME"));
    }
    return state;
}

int runtime_net_ping_view(PingPeer *out, int max) {
    return ping_view(now_ms(), out, max);
}

static int tunnel_copy(VSocket *vs, const void *msg, size_t len, const struct sockaddr_in *to);

/* A ping packet the way the game's packets to that peer go: direct, and through the tunnel
 * while the direct path is not proven. */
static void ping_send(VSocket *vs, const uint8_t *packet, size_t n, const struct sockaddr_in *to) {
    sendto(vs->s, (const char *)packet, (int)n, 0, (const struct sockaddr *)to, sizeof(*to));
    tunnel_copy(vs, packet, n, to);
}

/* After the game's send to a peer: the pings that are due. */
static void ping_after_send(VSocket *vs, const struct sockaddr_in *to) {
    struct sockaddr_in server;
    if (!ping_enabled() || !tunnel_server(&server)) return;
    if (!tun_candidate(to->sin_addr.s_addr, server.sin_addr.s_addr) ||
        tun_relay_index(to->sin_addr.s_addr, ntohs(to->sin_port)) >= 0)
        return;
    const uint64_t now = now_ms();
    ping_on_game_send(to->sin_addr.s_addr, ntohs(to->sin_port), now);
    uint8_t packet[PING_PACKET_MAX];
    uint32_t ip;
    uint16_t port;
    for (size_t n; (n = ping_next(now, packet, sizeof(packet), &ip, &port));) {
        const struct sockaddr_in peer = addr_of(ip, port);
        ping_send(vs, packet, n, &peer);
    }
}

/* A datagram from a peer (unwrapped): 1 when it was a ping packet, answered here. */
static int ping_take(VSocket *vs, const uint8_t *data, int len, const struct sockaddr_in *from) {
    if (len < PING_MAGIC_LEN || memcmp(data, PING_MAGIC, PING_MAGIC_LEN) != 0 || !ping_enabled()) return 0;
    uint8_t reply[PING_PACKET_MAX];
    size_t reply_len = 0;
    if (!ping_on_packet(data, (size_t)len, from->sin_addr.s_addr, ntohs(from->sin_port), now_ms(), reply,
                        sizeof(reply), &reply_len))
        return 0;
    if (reply_len) ping_send(vs, reply, reply_len, from);
    return 1;
}

/* After the game's own send to a peer: a wrapped copy through the nearest relay and/or the
 * server while the direct path is not proven both ways. Returns the routes the copy took
 * (TUN_VIA_SERVER, TUN_VIA_RELAY; 0: none), for the per-player summary. */
static int tunnel_copy(VSocket *vs, const void *msg, size_t len, const struct sockaddr_in *to) {
    struct sockaddr_in server;
    if (!vs->tunnel || !tunnel_server(&server)) return 0;
    tunnel_keepalive(vs, &server);
    if (!tun_candidate(to->sin_addr.s_addr, server.sin_addr.s_addr) || len > 2048) return 0;
    if (tun_relay_index(to->sin_addr.s_addr, ntohs(to->sin_port)) >= 0) return 0;
    uint8_t flags;
    int relay = -1;
    int route = tun_on_send(to->sin_addr.s_addr, ntohs(to->sin_port), now_ms(), &flags, &relay);
    if (!route) return 0;
    if (ping_enabled()) flags |= TUN_FLAG_PING;
    uint8_t wrapped[2048 + TUN_HEADER_LEN];
    size_t n = tun_wrap(wrapped, sizeof(wrapped), flags, to->sin_addr.s_addr, ntohs(to->sin_port), msg, len);
    if (!n) return 0;
    if (route & TUN_VIA_SERVER)
        sendto(vs->s, (const char *)wrapped, (int)n, 0, (const struct sockaddr *)&server, sizeof(server));
    uint32_t ip;
    uint16_t port;
    if ((route & TUN_VIA_RELAY) && tun_relay_addr(relay, &ip, &port)) {
        static int traced = -2;
        if (relay != traced) {
            traced = relay;
            runtime_net_trace("Tunnel: through relay %s (%u ms) for peers without a direct path",
                              tun_relay_name(relay), tun_relay_ping(relay));
        }
        const struct sockaddr_in via = addr_of(ip, port);
        sendto(vs->s, (const char *)wrapped, (int)n, 0, (const struct sockaddr *)&via, sizeof(via));
    } else {
        route &= ~TUN_VIA_RELAY;
    }
    return route;
}

int32_t runtime_net_bind(int s, const OrbisNetSockaddr *addr, uint32_t addrlen) {
    (void)addrlen;
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;
    if (!addr) return ORBIS_NET_EINVAL;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    const OrbisNetSockaddrIn *in = (const OrbisNetSockaddrIn *)addr;
    sin.sin_family = in->sin_family;
    sin.sin_port = in->sin_port;
    const int game_port = ntohs(in->sin_port) == 3074;
    const char *p_env = getenv("BB_ONLINE_PORT");
    if (p_env && atoi(p_env) > 0) {
        sin.sin_port = htons((uint16_t)atoi(p_env));
    } else if (ntohs(sin.sin_port) == 3074 && server_is_this_machine()) {
        sin.sin_port = htons(3075);
    }

    /* Enable SO_REUSEADDR only for TCP streams. On UDP (Windows), SO_REUSEADDR allows port stealing
     * which breaks local multi-instance testing. Keeping it off allows WSAEADDRINUSE to trigger the retry loop. */
    if (vs->is_stream) {
        int opt = 1;
        setsockopt(vs->s, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
    }

    runtime_net_trace("sceNetBind(fd=%d, port=%u)", s, ntohs(sin.sin_port));
    int ret = bind(vs->s, (struct sockaddr *)&sin, sizeof(sin));
    if (ret != 0 && (WSAGetLastError() == WSAEADDRINUSE || WSAGetLastError() == 10048)) {
        for (int p_retry = 1; p_retry <= 10; p_retry++) {
            sin.sin_port = htons(ntohs(sin.sin_port) + 1);
            runtime_net_trace("sceNetBind: port busy, retrying port %u", ntohs(sin.sin_port));
            ret = bind(vs->s, (struct sockaddr *)&sin, sizeof(sin));
            if (ret == 0) break;
        }
    }
    if (ret != 0) {
        g_net_errno = net_errno_from(WSAGetLastError());
        runtime_net_trace("sceNetBind(fd=%d, port=%u) failed: win err %d", s, ntohs(sin.sin_port), g_net_errno);
        return -1;
    }
    struct sockaddr_in server;
    if (!vs->is_stream && game_port && tunnel_server(&server)) {
        vs->tunnel = 1;
        tunnel_keepalive(vs, &server);
    }
    return ORBIS_OK;
}

int32_t runtime_net_listen(int s, int backlog) {
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;

    runtime_net_trace("sceNetListen(fd=%d, backlog=%d)", s, backlog);
    int ret = listen(vs->s, backlog);
    if (ret != 0) {
        g_net_errno = net_errno_from(WSAGetLastError());
        return -1;
    }
    return ORBIS_OK;
}

int32_t runtime_net_accept(int s, OrbisNetSockaddr *addr, uint32_t *addrlen) {
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;

    struct sockaddr_in sin;
    NativeSockLen sin_len = sizeof(sin);
    SOCKET client = accept(vs->s, (struct sockaddr *)&sin, &sin_len);
    if (client == INVALID_SOCKET) {
        g_net_errno = net_errno_from(WSAGetLastError());
        return -1;
    }

    if (addr) {
        OrbisNetSockaddrIn *out = (OrbisNetSockaddrIn *)addr;
        out->sin_len = sizeof(OrbisNetSockaddrIn);
        out->sin_family = (uint8_t)sin.sin_family;
        out->sin_port = sin.sin_port;
        memcpy(&out->sin_addr, &sin.sin_addr, sizeof(out->sin_addr));
        memset(out->sin_zero, 0, sizeof(out->sin_zero));
    }
    if (addrlen) *addrlen = sizeof(OrbisNetSockaddrIn);

    int vfd = vsocket_alloc(client, 1, "accepted");
    runtime_net_trace("sceNetAccept(fd=%d) -> new fd=%d", s, vfd);
    return vfd;
}

/* The game opens its UDP 3074 on the router through UPnP (AddPortMapping, external port 3074 to
 * this PC's 3074). On a network with several players every PC asked for the same external port,
 * and the router gave it to the last one: the others stopped receiving their lobby's traffic
 * (kicked out of the lobby) or received another PC's (karts under the track, teleports), as the
 * logs of three PCs behind one router showed (2026-10-19). Each PC now asks for its own external
 * port, from its address on the network (3075 + the last byte), still to its local 3074; the
 * server sees that port and gives it to the peers. Same length as "3074": the request's
 * Content-Length stays right. BB_UPNP_PORT=3074 keeps the game's own. */
static int upnp_external_port(void) {
    static int port;
    if (port) return port;
    const char *env = getenv("BB_UPNP_PORT");
    if (env && atoi(env) >= 1024 && atoi(env) <= 9999) return port = atoi(env);
    unsigned a = 0, b = 0, c = 0, d = 0;
    port = sscanf(local_ipv4(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4 && a != 127 ? 3075 + (int)(d & 255) : 3074;
    return port;
}

/* A copy of a UPnP SOAP request with <NewExternalPort>3074< replaced, or NULL when there is none. */
static char *upnp_rewrite(const void *msg, size_t len) {
    static const char tag[] = "<NewExternalPort>3074<";
    const char *data = (const char *)msg;
    if (len < sizeof tag || len > 65536) return NULL;
    int found = 0;
    for (size_t at = 0; !found && at + sizeof tag - 1 <= len; ++at)
        found = data[at] == '<' && memcmp(data + at, tag, sizeof tag - 1) == 0;
    char *copy = found ? malloc(len) : NULL;
    if (!copy) return NULL;
    memcpy(copy, data, len);
    char port[8];
    snprintf(port, sizeof port, "%04d", upnp_external_port());
    int changed = 0;
    for (size_t at = 0; at + sizeof tag - 1 <= len; ++at) {
        if (copy[at] == '<' && memcmp(copy + at, tag, sizeof tag - 1) == 0) {
            memcpy(copy + at + strlen("<NewExternalPort>"), port, 4);
            ++changed;
        }
    }
    static int logged;
    if (changed && !logged) {
        logged = 1;
        printf("[NET] UPnP: external port 3074 -> %s (one per PC on this network; BB_UPNP_PORT sets it)\n", port);
        fflush(stdout);
    }
    return copy;
}

/* ---- Multipath copies ----------------------------------------------------------------------
 * While the direct path to a peer is not proven both ways, the same datagram comes from it directly
 * and through the tunnel (a relay, or the RyuNET server in Chile), up to a few hundred ms apart.
 * The game must see it once, so a copy is dropped when the same bytes already came from that peer
 * by another path within MP_WINDOW_MS. Counting per path keeps the game's own repeats (a resend
 * after a lost ack comes by every path again): each of those still reaches the game once.
 * BB_NET_MULTIPATH_DEDUP=0 turns the dropping off.
 *
 * A player's tunnelled copies can also carry another port than its direct packets: its router sends
 * to the relay from another external port than the one UPnP gave it (CWL63 in the 2026-11-02 logs:
 * direct from :3080, relayed from :3074, for the whole session). The game then saw a second,
 * unknown player, and the RyuNET ping answered that one through the tunnel, which kept telling the
 * player's PC that the direct path did not work (it copied every packet all session). So when a
 * tunnelled datagram has the same bytes as one that came direct from another port of the same
 * address, it is that player's: its port is taken (tunnel_alias), and kept for MP_ALIAS_MS after
 * each match. A port that sends direct packets itself is never taken for another. */
#define MP_PEERS 16
#define MP_RING 128
#define MP_WINDOW_MS 1500u
#define MP_ALIASES 8
#define MP_ALIAS_MS 10000u
#define MP_DIRECT_FRESH_MS 3000u

typedef struct {
    uint64_t hash;
    uint64_t at;
    uint8_t count[3]; /* arrivals by path: direct, relay, server */
} MpEntry;

typedef struct {
    uint32_t ip;
    uint16_t port; /* network order */
    int used;
    uint64_t last_use;
    uint64_t last_direct; /* when a datagram last came from it directly */
    uint32_t head;
    MpEntry e[MP_RING];
} MpPeer;

typedef struct {
    uint32_t ip;
    uint16_t from, to; /* network order */
    uint64_t at;       /* the latest match */
} MpAlias;

static MpPeer g_mp[MP_PEERS];
static MpAlias g_mp_alias[MP_ALIASES];
static uint32_t g_mp_dropped;
static atomic_flag g_mp_lock = ATOMIC_FLAG_INIT;

static int multipath_enabled(void) {
    static int on = -1;
    if (on < 0) {
        const char *v = getenv("BB_NET_MULTIPATH_DEDUP");
        on = !(v && strcmp(v, "0") == 0);
    }
    return on;
}

static uint64_t payload_hash(const uint8_t *data, int len) {
    uint64_t h = 14695981039346656037ULL ^ (uint64_t)len;
    for (int i = 0; i < len; i++) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* This peer's entry (made, in a free or the idlest slot, with create). Holds the lock. */
static MpPeer *mp_peer(uint32_t ip, uint16_t port, uint64_t now, int create) {
    MpPeer *free_slot = NULL, *idlest = NULL;
    for (int i = 0; i < MP_PEERS; i++) {
        MpPeer *p = &g_mp[i];
        if (p->used && p->ip == ip && p->port == port) return p;
        if (!p->used || now - p->last_use > 60000u) {
            if (!free_slot) free_slot = p;
        } else if (!idlest || p->last_use < idlest->last_use) {
            idlest = p;
        }
    }
    if (!create) return NULL;
    MpPeer *p = free_slot ? free_slot : idlest;
    memset(p, 0, sizeof(*p));
    p->used = 1;
    p->ip = ip;
    p->port = port;
    return p;
}

/* The recent entry of these bytes. Holds the lock. */
static MpEntry *mp_find(MpPeer *p, uint64_t h, uint64_t now) {
    for (int i = 0; i < MP_RING; i++) {
        MpEntry *c = &p->e[i];
        if (c->at && c->hash == h && now - c->at <= MP_WINDOW_MS) return c;
    }
    return NULL;
}

/* A tunnelled datagram from ip:port (port in host order) with these bytes: the port it is taken
 * from (another port of the same address when it is that player's, see above). */
static uint16_t tunnel_alias(uint32_t ip, uint16_t port, const uint8_t *data, int len) {
    if (len <= 0) return port;
    const uint16_t from = htons(port);
    const uint64_t now = now_ms(), h = payload_hash(data, len);
    uint16_t to = 0;
    int announce = 0;
    while (atomic_flag_test_and_set_explicit(&g_mp_lock, memory_order_acquire)) {}
    const MpPeer *self = mp_peer(ip, from, now, 0);
    if (!self || !self->last_direct || now - self->last_direct >= MP_DIRECT_FRESH_MS) {
        for (int i = 0; i < MP_PEERS && !to; i++) {
            MpPeer *p = &g_mp[i];
            if (!p->used || p->ip != ip || p->port == from || !p->last_direct ||
                now - p->last_direct >= MP_DIRECT_FRESH_MS)
                continue;
            const MpEntry *e = mp_find(p, h, now);
            if (e && e->count[0]) to = p->port;
        }
        MpAlias *slot = NULL, *oldest = NULL;
        for (int i = 0; i < MP_ALIASES && !slot; i++) {
            MpAlias *a = &g_mp_alias[i];
            if (a->at && a->ip == ip && a->from == from) slot = a;
            else if (!oldest || a->at < oldest->at) oldest = a;
        }
        if (to) {
            announce = !slot || slot->to != to || now - slot->at >= MP_ALIAS_MS;
            if (!slot) slot = oldest;
            slot->ip = ip;
            slot->from = from;
            slot->to = to;
            slot->at = now;
        } else if (slot && now - slot->at < MP_ALIAS_MS) {
            to = slot->to;
        }
    }
    atomic_flag_clear_explicit(&g_mp_lock, memory_order_release);
    if (announce) {
        const uint8_t *b = (const uint8_t *)&ip;
        runtime_net_trace("Tunnel: %u.%u.%u.%u's tunnelled packets come from port %u, its direct ones from %u: the same player",
                          b[0], b[1], b[2], b[3], port, ntohs(to));
    }
    return to ? ntohs(to) : port;
}

/* 1 when this datagram is a copy of one the game already got from this peer by another path. */
static int multipath_copy(const struct sockaddr_in *from, const uint8_t *data, int len, int route) {
    if (len <= 0) return 0;
    const int path = route == TUN_VIA_RELAY ? 1 : route == TUN_VIA_SERVER ? 2 : 0;
    const uint64_t h = payload_hash(data, len);
    const uint64_t now = now_ms();
    int drop = 0;
    while (atomic_flag_test_and_set_explicit(&g_mp_lock, memory_order_acquire)) {}
    MpPeer *peer = mp_peer(from->sin_addr.s_addr, from->sin_port, now, 1);
    peer->last_use = now;
    if (path == 0) peer->last_direct = now;
    MpEntry *e = mp_find(peer, h, now);
    if (!e) {
        e = &peer->e[peer->head++ % MP_RING];
        memset(e, 0, sizeof(*e));
        e->hash = h;
    }
    e->at = now;
    if (e->count[path] < 255) e->count[path]++;
    int others = 0;
    for (int k = 0; k < 3; k++)
        if (k != path && e->count[k] > others) others = e->count[k];
    drop = multipath_enabled() && e->count[path] <= others;
    atomic_flag_clear_explicit(&g_mp_lock, memory_order_release);
    if (drop) __atomic_add_fetch(&g_mp_dropped, 1, __ATOMIC_RELAXED);
    return drop;
}

/* ---- Per-player network summary ----------------------------------------------------------
 * Every 5 s (BB_NET_SUMMARY_MS; BB_NET_SUMMARY=0 turns it off) while the game socket talks to
 * other players, one line per player address: its nickname and ping (RyuNET ping), what arrived
 * from it and by which path (direct, a regional relay, the RyuNET server), the same datagram
 * arriving twice within a second (several paths at once: counted, not dropped), what was sent to
 * it and how many tunnelled copies went along, and the longest silence between two of its
 * datagrams. A silence of 500 ms or more is logged when it ends, with the wall-clock time, so a
 * glitch seen on screen can be found in the log. A header line gives the longest wait between two
 * reads of the game socket on this PC: when it is as long as a player's silence, this PC was the
 * one that stalled. */
#define NETSTAT_MAX_PEERS 16
#define NETSTAT_DUP_RING 64
#define NETSTAT_DUP_WINDOW_MS 1000u
#define NETSTAT_IDLE_MS 60000u
#define NETSTAT_SILENCE_MS 500u

typedef struct {
    uint32_t in_direct, in_relay, in_server, in_bytes, dups;
    uint32_t out_pkts, out_bytes, copies_relay, copies_server;
    uint32_t gap_max, gaps_100, gaps_250;
} NetCounts;

typedef struct {
    uint32_t ip;
    uint16_t port;
    int used;
    uint64_t last_in;
    uint64_t last_use;
    NetCounts c;
    uint64_t dup_hash[NETSTAT_DUP_RING];
    uint64_t dup_at[NETSTAT_DUP_RING];
    uint32_t dup_head;
} NetStat;

static NetStat g_netstat[NETSTAT_MAX_PEERS];
static uint64_t g_netstat_window;    /* start of the current window, 0 before the first */
static uint32_t g_netstat_peeks;
static uint32_t g_netstat_read_gap;  /* longest wait between two reads of the game socket */
static uint32_t g_netstat_read_33, g_netstat_read_50; /* waits of 33 ms and 50 ms or more */
static uint64_t g_netstat_last_read;
static atomic_flag g_netstat_lock = ATOMIC_FLAG_INIT;

static void netstat_take(void) { while (atomic_flag_test_and_set_explicit(&g_netstat_lock, memory_order_acquire)) {} }
static void netstat_give(void) { atomic_flag_clear_explicit(&g_netstat_lock, memory_order_release); }

static uint32_t netstat_interval(void) {
    static int ms = -1;
    if (ms < 0) {
        const char *off = getenv("BB_NET_SUMMARY");
        const char *v = getenv("BB_NET_SUMMARY_MS");
        ms = (off && strcmp(off, "0") == 0) ? 0 : (v && atoi(v) >= 1000 ? atoi(v) : 5000);
    }
    return (uint32_t)ms;
}

/* This peer's entry, made (in a free or the idlest slot) with create. Holds the lock. */
static NetStat *netstat_peer(uint32_t ip, uint16_t port, uint64_t now, int create) {
    NetStat *free_slot = NULL, *idlest = NULL;
    for (int i = 0; i < NETSTAT_MAX_PEERS; i++) {
        NetStat *p = &g_netstat[i];
        if (p->used && p->ip == ip && p->port == port) return p;
        if (!p->used || now - p->last_use > NETSTAT_IDLE_MS) {
            if (!free_slot) free_slot = p;
        } else if (!idlest || p->last_use < idlest->last_use) {
            idlest = p;
        }
    }
    if (!create) return NULL;
    NetStat *p = free_slot ? free_slot : idlest;
    memset(p, 0, sizeof(*p));
    p->used = 1;
    p->ip = ip;
    p->port = port;
    p->last_use = now;
    return p;
}

static void netstat_addr(uint32_t ip, uint16_t port, char *out, size_t cap) {
    const uint8_t *b = (const uint8_t *)&ip;
    snprintf(out, cap, "%u.%u.%u.%u:%u", b[0], b[1], b[2], b[3], port);
}

static void netstat_clock(char *out, size_t cap) {
    const time_t t = time(NULL);
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
#ifdef _WIN32
    const struct tm *l = localtime(&t); /* thread-local buffer in the Windows CRT */
    if (l) tm = *l;
#else
    localtime_r(&t, &tm);
#endif
    strftime(out, cap, "%H:%M:%S", &tm);
}

/* "name" from the RyuNET ping, or "?"; the ping as text. */
static void netstat_who(uint32_t ip, uint16_t port, uint64_t now, char *name, size_t name_cap, char *ping, size_t ping_cap) {
    char n[PING_NAME];
    const int ms = ping_peer(ip, port, now, n);
    snprintf(name, name_cap, "%s", n[0] ? n : "?");
    if (ms >= 0) snprintf(ping, ping_cap, "%d ms", ms);
    else if (ms == PING_NO_ANSWER) snprintf(ping, ping_cap, "no answer");
    else if (ms == PING_OLDER_PORT) snprintf(ping, ping_cap, "older port");
    else snprintf(ping, ping_cap, "n/a");
}

static const char *netstat_route(int route) {
    return route == TUN_VIA_RELAY ? "relay" : route == TUN_VIA_SERVER ? "server" : "direct";
}

/* Each read of the game socket, data or not. */
static void netstat_on_read_call(void) {
    if (!netstat_interval()) return;
    const uint64_t now = now_ms();
    const uint64_t last = __atomic_exchange_n(&g_netstat_last_read, now, __ATOMIC_RELAXED);
    if (!last || now <= last || now - last > 10000u) return; /* not reading at all: not a stall */
    const uint32_t gap = (uint32_t)(now - last);
    if (gap >= 33) __atomic_add_fetch(&g_netstat_read_33, 1, __ATOMIC_RELAXED);
    if (gap >= 50) __atomic_add_fetch(&g_netstat_read_50, 1, __ATOMIC_RELAXED);
    if (gap > __atomic_load_n(&g_netstat_read_gap, __ATOMIC_RELAXED))
        __atomic_store_n(&g_netstat_read_gap, gap, __ATOMIC_RELAXED);
}

static void netstat_on_peek(void) {
    __atomic_add_fetch(&g_netstat_peeks, 1, __ATOMIC_RELAXED);
}

static void netstat_on_send(const struct sockaddr_in *to, size_t len, int route) {
    struct sockaddr_in server;
    if (!netstat_interval() || !tunnel_server(&server) || to->sin_addr.s_addr == server.sin_addr.s_addr) return;
    const uint64_t now = now_ms();
    netstat_take();
    NetStat *p = netstat_peer(to->sin_addr.s_addr, ntohs(to->sin_port), now, 1);
    p->last_use = now;
    p->c.out_pkts++;
    p->c.out_bytes += (uint32_t)len;
    if (route & TUN_VIA_RELAY) p->c.copies_relay++;
    if (route & TUN_VIA_SERVER) p->c.copies_server++;
    netstat_give();
}

/* A game datagram from a player (unwrapped), and the path it came by. */
static void netstat_on_recv(const struct sockaddr_in *from, const uint8_t *data, int len, int route) {
    if (!netstat_interval() || len <= 0) return;
    const uint64_t now = now_ms();
    const uint32_t ip = from->sin_addr.s_addr;
    const uint16_t port = ntohs(from->sin_port);
    uint32_t silence = 0;
    netstat_take();
    NetStat *p = netstat_peer(ip, port, now, 1);
    p->last_use = now;
    if (route == TUN_VIA_RELAY) p->c.in_relay++;
    else if (route == TUN_VIA_SERVER) p->c.in_server++;
    else p->c.in_direct++;
    p->c.in_bytes += (uint32_t)len;
    if (p->last_in && now > p->last_in) {
        const uint64_t gap = now - p->last_in;
        if (gap < NETSTAT_IDLE_MS) {
            if (gap > p->c.gap_max) p->c.gap_max = (uint32_t)gap;
            if (gap >= 100) p->c.gaps_100++;
            if (gap >= 250) p->c.gaps_250++;
            if (gap >= NETSTAT_SILENCE_MS) silence = (uint32_t)gap;
        }
    }
    p->last_in = now;
    if (len >= 32) {
        uint64_t h = 14695981039346656037ULL;
        for (int i = 0; i < len; i++) {
            h ^= data[i];
            h *= 1099511628211ULL;
        }
        int dup = 0;
        for (int i = 0; i < NETSTAT_DUP_RING && !dup; i++)
            dup = p->dup_at[i] && p->dup_hash[i] == h && now - p->dup_at[i] <= NETSTAT_DUP_WINDOW_MS;
        if (dup) {
            p->c.dups++;
        } else {
            const uint32_t k = p->dup_head++ % NETSTAT_DUP_RING;
            p->dup_hash[k] = h;
            p->dup_at[k] = now;
        }
    }
    netstat_give();
    if (silence) {
        char name[PING_NAME + 2], ping[16], addr[24], clock[16];
        netstat_who(ip, port, now, name, sizeof(name), ping, sizeof(ping));
        netstat_addr(ip, port, addr, sizeof(addr));
        netstat_clock(clock, sizeof(clock));
        runtime_net_trace("Net %s: nothing from %s (%s) for %u ms, back now (%s, ping %s)",
                          clock, name, addr, silence, netstat_route(route), ping);
    }
}

/* ---- Senders and clocks (net3 diagnostics) ---------------------------------------------------
 * Which of the game's code sends to the players (its address in the game image), how much, and
 * the timer between its rounds of sends: the start for changing the game's ~13 updates/s. And the
 * game's use of clocks: how often it reads each one, which code reads the "network" clock (on a
 * PS4 a time all consoles share, here this PC's own clock), and how far the CPU timer speed the
 * game was given is from the speed measured over the whole session. */
#define SENDSITE_MAX 8

typedef struct {
    uintptr_t caller;
    uint32_t packets, bytes, max_len, rounds, gap_min, gap_max;
    uint64_t gap_sum;
    uint64_t last_send, round_start;
} SendSite;

static SendSite g_sendsites[SENDSITE_MAX];
static atomic_flag g_sendsite_lock = ATOMIC_FLAG_INIT;
static const unsigned char *g_image;
static size_t g_image_size;

void runtime_net_set_image(const unsigned char *image, size_t size) {
    g_image = image;
    g_image_size = size;
}

/* "game +0x..." for an address in the game's image, the address itself otherwise. */
static void code_where(uintptr_t address, char *out, size_t cap) {
    if (g_image && address >= (uintptr_t)g_image && address < (uintptr_t)g_image + g_image_size)
        snprintf(out, cap, "game +0x%llx", (unsigned long long)(address - (uintptr_t)g_image));
    else
        snprintf(out, cap, "0x%llx", (unsigned long long)address);
}

/* The call chain of each send to a player: the return addresses up the game's frame-pointer chain
 * (its code keeps rbp frames), each frame checked against this thread's stack and the game image,
 * so the walk stops at the first frame that is not one. Each distinct chain is logged once in full
 * and then counted per summary: the way from the game's network update to sendto, to find what
 * paces it (~13 rounds a second). */
#define STACK_DEPTH 16
#define STACKS_MAX 16

typedef struct {
    uint64_t hash;
    uint32_t count;
    int depth, printed;
    uintptr_t ret[STACK_DEPTH];
} SendStack;

static SendStack g_stacks[STACKS_MAX];

static int stack_bounds(uintptr_t *lo, uintptr_t *hi) {
#ifdef _WIN32
    typedef VOID (WINAPI *Limits)(PULONG_PTR, PULONG_PTR);
    static Limits limits;
    static int looked;
    if (!looked) {
        limits = (Limits)(void (*)(void))GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCurrentThreadStackLimits");
        looked = 1;
    }
    if (!limits) return 0;
    ULONG_PTR low = 0, high = 0;
    limits(&low, &high);
    *lo = (uintptr_t)low;
    *hi = (uintptr_t)high;
    return high > low;
#else
    pthread_attr_t a;
    void *base = NULL;
    size_t size = 0;
    if (pthread_getattr_np(pthread_self(), &a)) return 0;
    const int ok = !pthread_attr_getstack(&a, &base, &size);
    pthread_attr_destroy(&a);
    if (!ok) return 0;
    *lo = (uintptr_t)base;
    *hi = (uintptr_t)base + size;
    return 1;
#endif
}

/* The return addresses above frame (the caller's rbp), at most max. */
static int guest_chain(const void *frame, uintptr_t *out, int max) {
    uintptr_t lo, hi;
    if (!frame || !g_image || !stack_bounds(&lo, &hi)) return 0;
    const uintptr_t code_lo = (uintptr_t)g_image, code_hi = (uintptr_t)g_image + g_image_size;
    uintptr_t fp = (uintptr_t)frame;
    int n = 0;
    while (n < max && !(fp & 7) && fp >= lo && fp + 16 <= hi) {
        const uintptr_t next = ((const uintptr_t *)fp)[0], ret = ((const uintptr_t *)fp)[1];
        if (ret < code_lo || ret >= code_hi) break;
        out[n++] = ret;
        if (next <= fp) break;
        fp = next;
    }
    return n;
}

/* Holds g_sendsite_lock. */
static void stack_note(const uintptr_t *ret, int depth) {
    uint64_t h = 14695981039346656037ULL ^ (uint64_t)depth;
    for (int i = 0; i < depth; i++) {
        h ^= ret[i];
        h *= 1099511628211ULL;
    }
    SendStack *slot = NULL;
    for (int i = 0; i < STACKS_MAX && !slot; i++)
        if (!g_stacks[i].depth || (g_stacks[i].hash == h && g_stacks[i].depth == depth)) slot = &g_stacks[i];
    if (!slot) return;
    if (!slot->depth) {
        slot->hash = h;
        slot->depth = depth;
        memcpy(slot->ret, ret, sizeof(*ret) * (size_t)depth);
    }
    slot->count++;
}

static void report_stacks(void) {
    char line[1400], counts[400];
    size_t used = 0;
    counts[0] = '\0';
    for (int i = 0; i < STACKS_MAX; i++) {
        SendStack s;
        while (atomic_flag_test_and_set_explicit(&g_sendsite_lock, memory_order_acquire)) {}
        s = g_stacks[i];
        g_stacks[i].count = 0;
        if (g_stacks[i].depth && !g_stacks[i].printed && s.count) g_stacks[i].printed = 1;
        atomic_flag_clear_explicit(&g_sendsite_lock, memory_order_release);
        if (!s.depth || !s.count) continue;
        if (!s.printed) {
            size_t at = (size_t)snprintf(line, sizeof(line), "Net   send chain #%d:", i + 1);
            for (int k = 0; k < s.depth && at < sizeof(line) - 40; k++) {
                char where[40];
                code_where(s.ret[k], where, sizeof(where));
                at += (size_t)snprintf(line + at, sizeof(line) - at, "%s %s", k ? " <" : "", where);
            }
            runtime_net_trace("%s", line);
        }
        if (used < sizeof(counts) - 24)
            used += (size_t)snprintf(counts + used, sizeof(counts) - used, "%s#%d x%u", used ? ", " : "", i + 1, s.count);
    }
    if (used) runtime_net_trace("Net   send chains: %s", counts);
}

static void sendsite_on_send(const void *caller, const void *frame, const struct sockaddr_in *to, size_t len) {
    struct sockaddr_in server;
    if (!caller || !netstat_interval() || !tunnel_server(&server) || to->sin_addr.s_addr == server.sin_addr.s_addr) return;
    const uint64_t now = now_ms();
    uintptr_t chain[STACK_DEPTH];
    chain[0] = (uintptr_t)caller;
    const int depth = 1 + guest_chain(frame, chain + 1, STACK_DEPTH - 1);
    while (atomic_flag_test_and_set_explicit(&g_sendsite_lock, memory_order_acquire)) {}
    stack_note(chain, depth);
    SendSite *s = NULL;
    for (int i = 0; i < SENDSITE_MAX && !s; i++)
        if (!g_sendsites[i].caller || g_sendsites[i].caller == (uintptr_t)caller) s = &g_sendsites[i];
    if (s) {
        s->caller = (uintptr_t)caller;
        s->packets++;
        s->bytes += (uint32_t)len;
        if (len > s->max_len) s->max_len = (uint32_t)len;
        /* Sends more than 5 ms apart start a new round (a round sends to every player at once). */
        if (!s->last_send || now - s->last_send > 5) {
            if (s->round_start && now > s->round_start && now - s->round_start < 10000) {
                const uint32_t gap = (uint32_t)(now - s->round_start);
                s->rounds++;
                s->gap_sum += gap;
                if (!s->gap_min || gap < s->gap_min) s->gap_min = gap;
                if (gap > s->gap_max) s->gap_max = gap;
            }
            s->round_start = now;
        }
        s->last_send = now;
    }
    atomic_flag_clear_explicit(&g_sendsite_lock, memory_order_release);
}

static void report_senders(double secs) {
    SendSite snap[SENDSITE_MAX];
    int n = 0;
    while (atomic_flag_test_and_set_explicit(&g_sendsite_lock, memory_order_acquire)) {}
    for (int i = 0; i < SENDSITE_MAX; i++) {
        SendSite *s = &g_sendsites[i];
        if (!s->caller || !s->packets) continue;
        snap[n++] = *s;
        s->packets = s->bytes = s->max_len = s->rounds = s->gap_min = s->gap_max = 0;
        s->gap_sum = 0;
    }
    atomic_flag_clear_explicit(&g_sendsite_lock, memory_order_release);
    for (int i = 0; i < n; i++) {
        const SendSite *s = &snap[i];
        char where[40];
        code_where(s->caller, where, sizeof(where));
        runtime_net_trace("Net   sender %-18s %u packets (%.0f/s), avg %u B, max %u B | %u rounds (%.1f/s), every %u-%u ms (avg %.0f ms)",
                          where, s->packets, s->packets / secs, s->bytes / s->packets, s->max_len, s->rounds,
                          s->rounds / secs, s->gap_min, s->gap_max, s->rounds ? (double)s->gap_sum / s->rounds : 0.0);
    }
}

static void report_clocks(double secs) {
    RuntimeClockCounts c;
    runtime_kernel_clock_take(&c);
    uint64_t network = 0, current = 0;
    uintptr_t callers[8];
    uint32_t counts[8];
    const int nc = runtime_rtc_clock_take(&network, &current, callers, counts, 8);
    char ids[64] = "", who[256] = "";
    size_t at = 0;
    for (int i = 0; i < 64; i++)
        if (c.clock_ids & (UINT64_C(1) << i)) at += (size_t)snprintf(ids + at, sizeof(ids) - at, "%s%d", at ? "," : "", i);
    at = 0;
    for (int i = 0; i < nc && at < sizeof(who) - 48; i++) {
        char where[40];
        code_where(callers[i], where, sizeof(where));
        at += (size_t)snprintf(who + at, sizeof(who) - at, "%s%s x%u", i ? ", " : " from ", where, counts[i]);
    }
    runtime_net_trace("Net   clock reads/s: network tick %.0f%s | RTC tick %.0f | TSC %.0f (frequency %.0f) | process time %.0f, counter %.0f | clock_gettime %.0f (ids %s) | gettimeofday %.0f | time() %.0f",
                      network / secs, who, current / secs, c.tsc_reads / secs, c.tsc_frequency / secs,
                      c.process_time / secs, c.process_counter / secs, c.clock_gettime / secs, ids[0] ? ids : "-",
                      c.gettimeofday / secs, c.time / secs);
    int kinds[12];
    uintptr_t where_from[12];
    uint32_t calls[12];
    const int nw = runtime_clock_callers_take(kinds, where_from, calls, 12);
    if (nw) {
        char list[640];
        size_t used = 0;
        for (int i = 0; i < nw && used < sizeof(list) - 64; i++) {
            char where[40];
            code_where(where_from[i], where, sizeof(where));
            used += (size_t)snprintf(list + used, sizeof(list) - used, "%s%s %s x%u", i ? ", " : "",
                                     kinds[i] ? "clock_gettime" : "gettimeofday", where, calls[i]);
        }
        runtime_net_trace("Net   clock callers: %s", list);
    }
    uint64_t given;
    double measured, over;
    if (runtime_tsc_check(&given, &measured, &over)) {
        const double ppm = (measured - (double)given) / (double)given * 1e6;
        runtime_net_trace("Net   CPU timer: the game was told %.3f MHz, measured over %.0f s %.3f MHz: the game's timer runs %+.0f ppm (%+.0f ms per 3 minutes)",
                          given / 1e6, over, measured / 1e6, ppm, ppm * 0.18);
    }
}

/* The game's wall clock against a time server (SNTP, UDP 123), at the start and every 10 minutes:
 * logged with this PC's own clock, and slewed toward the server's at no more than 1 ms a second
 * (runtime_wall_adjust_us), so a PC's drift (tens of ms an hour) never builds up. When run.py
 * found no time server, the first answer here corrects the game's clock at once (that is still at
 * the start screen). BB_NET_CLOCK_CHECK=0 turns the check off. */
static int64_t wall_us(void) {
    return runtime_wall_now_us();
}

static int64_t ntp_us(const uint8_t *p) {
    const uint32_t sec = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    const uint32_t frac = (uint32_t)p[4] << 24 | (uint32_t)p[5] << 16 | (uint32_t)p[6] << 8 | p[7];
    if (!sec) return 0;
    return ((int64_t)sec - 2208988800LL) * 1000000LL + (int64_t)(((uint64_t)frac * 1000000u) >> 32);
}

/* The best of three exchanges with host ("name" or "name:port", port 123 by default): 1 with
 * *offset_us (server minus this PC) and *rtt_us. */
static int sntp_query(const char *host, int64_t *offset_us, int64_t *rtt_us) {
    char name[128];
    const char *port = "123";
    snprintf(name, sizeof(name), "%s", host);
    char *colon = strchr(name, ':');
    if (colon) {
        *colon = '\0';
        port = colon + 1;
    }
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(name, port, &hints, &res) != 0 || !res) return 0;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        return 0;
    }
#ifdef _WIN32
    DWORD wait = 1500;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&wait, sizeof(wait));
#else
    struct timeval wait = {1, 500000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof(wait));
#endif
    int got = 0;
    for (int attempt = 0; attempt < 3; attempt++) {
        uint8_t request[48] = {0x23}, reply[64];
        const int64_t t1 = wall_us();
        if (sendto(s, (const char *)request, sizeof(request), 0, res->ai_addr, (int)res->ai_addrlen) != (int)sizeof(request)) break;
        const int n = (int)recv(s, (char *)reply, sizeof(reply), 0);
        const int64_t t4 = wall_us();
        if (n < 48 || (reply[0] & 7) != 4) continue;
        const int64_t t2 = ntp_us(reply + 32), t3 = ntp_us(reply + 40);
        if (!t2 || !t3) continue;
        const int64_t rtt = (t4 - t1) - (t3 - t2);
        if (!got || rtt < *rtt_us) {
            *rtt_us = rtt;
            *offset_us = ((t2 - t1) + (t3 - t4)) / 2;
        }
        got = 1;
    }
    closesocket(s);
    freeaddrinfo(res);
    return got;
}

static void *clock_check(void *arg) {
    (void)arg;
    /* BB_NET_CLOCK_SERVER=<name[:port]> asks that server instead. */
    const char *const servers[] = {getenv("BB_NET_CLOCK_SERVER") ? getenv("BB_NET_CLOCK_SERVER") : "time.windows.com",
                                   "pool.ntp.org", "time.google.com"};
    const int count = getenv("BB_NET_CLOCK_SERVER") ? 1 : 3;
    int64_t pending = 0;        /* microseconds still to slew */
    uint64_t next_check = 0;
    int first = 1;
    for (;;) {
        const uint64_t now = now_ms();
        if (now >= next_check) {
            int done = 0;
            for (int i = 0; i < count && !done; i++) {
                int64_t offset = 0, rtt = 0; /* the server minus the game's clock */
                if (!sntp_query(servers[i], &offset, &rtt)) continue;
                const int64_t game = -offset;                           /* the game's clock minus the server */
                const int64_t pc = game - runtime_wall_offset_us();     /* this PC's clock minus the server */
                runtime_net_trace("Clock: this PC's clock is %.0f ms %s %s (round trip %.0f ms); the game's clock is %.0f ms %s",
                                  (pc < 0 ? -pc : pc) / 1000.0, pc < 0 ? "behind" : "ahead of", servers[i], rtt / 1000.0,
                                  (game < 0 ? -game : game) / 1000.0, game < 0 ? "behind" : "ahead");
                if (runtime_wall_fixed()) {
                    if (first && !getenv("BB_CLOCK_OFFSET_US") && (offset > 100000 || offset < -100000)) {
                        runtime_wall_adjust_us(offset);
                        runtime_net_trace("Clock: the game's clock corrected at once by %+.0f ms (run.py found no time server)", offset / 1000.0);
                        pending = 0;
                    } else {
                        pending = (offset > 5000 || offset < -5000) ? offset : 0;
                        if (pending) runtime_net_trace("Clock: slewing the game's clock by %+.0f ms (1 ms a second at most)", pending / 1000.0);
                    }
                }
                done = 1;
            }
            if (!done) runtime_net_trace("Clock: no time server answered (UDP 123): the game's clock offset is unknown");
            first = 0;
            next_check = now + 600000;
        }
        if (pending) {
            const int64_t step = pending > 100 ? 100 : pending < -100 ? -100 : pending; /* 100 us per 100 ms */
            runtime_wall_adjust_us(step);
            pending -= step;
        }
#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif
    }
    return NULL;
}

static void clock_check_start(void) {
    const char *v = getenv("BB_NET_CLOCK_CHECK");
    if ((v && strcmp(v, "0") == 0) || !runtime_net_is_online()) return;
    pthread_t thread;
    if (pthread_create(&thread, NULL, clock_check, NULL) == 0) pthread_detach(thread);
}

/* The summary when the window is over (any thread; one of them prints it). */
static void netstat_maybe_report(void) {
    const uint32_t interval = netstat_interval();
    if (!interval) return;
    const uint64_t now = now_ms();
    uint64_t start = __atomic_load_n(&g_netstat_window, __ATOMIC_ACQUIRE);
    if (!start) {
        __atomic_compare_exchange_n(&g_netstat_window, &start, now, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
        return;
    }
    if (now < start || now - start < interval) return;
    if (!__atomic_compare_exchange_n(&g_netstat_window, &start, now, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;

    struct { uint32_t ip; uint16_t port; NetCounts c; } snap[NETSTAT_MAX_PEERS];
    int n = 0;
    netstat_take();
    for (int i = 0; i < NETSTAT_MAX_PEERS; i++) {
        NetStat *p = &g_netstat[i];
        if (!p->used) continue;
        const NetCounts *c = &p->c;
        if (c->in_direct + c->in_relay + c->in_server + c->out_pkts) {
            snap[n].ip = p->ip;
            snap[n].port = p->port;
            snap[n].c = p->c;
            n++;
        }
        memset(&p->c, 0, sizeof(p->c));
    }
    netstat_give();
    const uint32_t peeks = __atomic_exchange_n(&g_netstat_peeks, 0, __ATOMIC_RELAXED);
    const uint32_t read_gap = __atomic_exchange_n(&g_netstat_read_gap, 0, __ATOMIC_RELAXED);
    const uint32_t copies_dropped = __atomic_exchange_n(&g_mp_dropped, 0, __ATOMIC_RELAXED);
    const uint32_t stalls_33 = __atomic_exchange_n(&g_netstat_read_33, 0, __ATOMIC_RELAXED);
    const uint32_t stalls_50 = __atomic_exchange_n(&g_netstat_read_50, 0, __ATOMIC_RELAXED);
    if (!n) return;

    const double secs = (double)(now - start) / 1000.0;
    char clock[16];
    netstat_clock(clock, sizeof(clock));
    runtime_net_trace("Net %s summary (%.1f s): %d player address(es); longest wait between reads of the game socket %u ms (>=33 ms x%u, >=50 ms x%u); peeks %u; second copies dropped %u",
                      clock, secs, n, read_gap, stalls_33, stalls_50, peeks, copies_dropped);
    for (int i = 0; i < n; i++) {
        const NetCounts *c = &snap[i].c;
        char name[PING_NAME + 2], ping[16], addr[24];
        netstat_who(snap[i].ip, snap[i].port, now, name, sizeof(name), ping, sizeof(ping));
        netstat_addr(snap[i].ip, snap[i].port, addr, sizeof(addr));
        const uint32_t in = c->in_direct + c->in_relay + c->in_server;
        runtime_net_trace("Net   %-16s %-21s ping %-10s| in %u (%.0f/s, %.1f KB/s): direct %u, relay %u, server %u, twice %u"
                          " | out %u (%.0f/s, %.1f KB/s), tunnel copies relay %u, server %u"
                          " | longest silence %u ms, >=100 ms x%u, >=250 ms x%u",
                          name, addr, ping, in, in / secs, c->in_bytes / 1024.0 / secs,
                          c->in_direct, c->in_relay, c->in_server, c->dups,
                          c->out_pkts, c->out_pkts / secs, c->out_bytes / 1024.0 / secs,
                          c->copies_relay, c->copies_server, c->gap_max, c->gaps_100, c->gaps_250);
    }
    report_senders(secs);
    report_stacks();
    report_clocks(secs);
}

int32_t runtime_net_send(int s, const void *msg, size_t len, int flags) {
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;

    int win_flags = 0;
    if (flags & 0x1) win_flags |= MSG_OOB;
    if (flags & 0x4) win_flags |= MSG_DONTROUTE;

    char *upnp = vs->is_stream && upnp_external_port() != 3074 ? upnp_rewrite(msg, len) : NULL;
    int ret = send(vs->s, upnp ? upnp : (const char *)msg, (int)len, win_flags);
    free(upnp);
    if (ret < 0) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            g_net_errno = 35; /* EWOULDBLOCK */
            return -1;
        }
        g_net_errno = net_errno_from(err);
        runtime_net_trace("sceNetSend(fd=%d, len=%zu, flags=0x%x) -> err %d (wsa %d)", s, len, flags, g_net_errno, err);
        return -1;
    }
    runtime_net_pkt_trace("sceNetSend(fd=%d, len=%zu) -> %d bytes", s, len, ret);
    return ret;
}

int32_t runtime_net_sendto(int s, const void *msg, size_t len, int flags, const OrbisNetSockaddr *to, uint32_t tolen) {
    return runtime_net_sendto_from(s, msg, len, flags, to, tolen, NULL, NULL);
}

int32_t runtime_net_sendto_from(int s, const void *msg, size_t len, int flags, const OrbisNetSockaddr *to, uint32_t tolen,
                                const void *caller, const void *frame) {
    (void)tolen;
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;

    int win_flags = 0;
    if (flags & 0x1) win_flags |= MSG_OOB;
    if (flags & 0x4) win_flags |= MSG_DONTROUTE;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    if (to) {
        const OrbisNetSockaddrIn *in = (const OrbisNetSockaddrIn *)to;
        sin.sin_family = in->sin_family;
        sin.sin_port = in->sin_port;
        memcpy(&sin.sin_addr, &in->sin_addr, sizeof(sin.sin_addr));
        runtime_net_pkt_trace("sceNetSendto(fd=%d, len=%zu, to=%s:%u)", s, len, inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    } else {
        runtime_net_pkt_trace("sceNetSendto(fd=%d, len=%zu)", s, len);
    }

    int ret = sendto(vs->s, (const char *)msg, (int)len, win_flags,
                     to ? (struct sockaddr *)&sin : NULL, to ? sizeof(sin) : 0);
    if (ret < 0) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            g_net_errno = 35;
            return -1;
        }
        g_net_errno = net_errno_from(err);
        runtime_net_trace("sceNetSendto(fd=%d) failed: win err %d", s, err);
        return -1;
    }
    note_game_peer(vs, to ? &sin : NULL);
    if (to && vs->tunnel) {
        const int route = tunnel_copy(vs, msg, len, &sin);
        netstat_on_send(&sin, len, route);
        sendsite_on_send(caller, frame, &sin, len);
        ping_after_send(vs, &sin);
        netstat_maybe_report();
    }
    return ret;
}

int32_t runtime_net_recv(int s, void *buf, size_t len, int flags) {
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;

    int win_flags = 0;
    if (flags & 0x1) win_flags |= MSG_OOB;
    if (flags & 0x2) win_flags |= MSG_PEEK;
    if (flags & 0x40) win_flags |= MSG_WAITALL;

    int ret = recv(vs->s, (char *)buf, (int)len, win_flags);
    if (ret < 0) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            g_net_errno = 35;
            return -1;
        }
        g_net_errno = net_errno_from(err);
        runtime_net_trace("sceNetRecv(fd=%d, len=%zu, flags=0x%x) -> err %d (wsa %d)", s, len, flags, g_net_errno, err);
        return -1;
    }
    if (ret > 0) {
        runtime_net_pkt_trace("sceNetRecv(fd=%d, len=%zu) -> %d bytes (first=0x%02X)", s, len, ret, ((unsigned char *)buf)[0]);
    } else {
        runtime_net_pkt_trace("sceNetRecv(fd=%d) -> EOF (0 bytes)", s);
    }
    return ret;
}

int32_t runtime_net_recvfrom(int s, void *buf, size_t len, int flags, OrbisNetSockaddr *from, uint32_t *fromlen) {
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;

    int win_flags = 0;
    if (flags & 0x1) win_flags |= MSG_OOB;
    if (flags & 0x2) win_flags |= MSG_PEEK;
    if (flags & 0x40) win_flags |= MSG_WAITALL;

    struct sockaddr_in sin;
    NativeSockLen sin_len = sizeof(sin);
    struct sockaddr_in server;
    const int tunnel = vs->tunnel && tunnel_server(&server);
    if (tunnel) netstat_on_read_call();
    /* A datagram kept from a peek (g_peeked) comes first. */
    if (tunnel && g_peeked.fd == s) {
        int ret = g_peeked.len > (int)len ? (int)len : g_peeked.len;
        memcpy(buf, g_peeked.data, (size_t)ret);
        sin = g_peeked.from;
        if (!(win_flags & MSG_PEEK)) g_peeked.fd = 0;
        if (from) {
            OrbisNetSockaddrIn *out = (OrbisNetSockaddrIn *)from;
            out->sin_len = sizeof(OrbisNetSockaddrIn);
            out->sin_family = (uint8_t)sin.sin_family;
            out->sin_port = sin.sin_port;
            memcpy(&out->sin_addr, &sin.sin_addr, sizeof(out->sin_addr));
            memset(out->sin_zero, 0, sizeof(out->sin_zero));
        }
        if (fromlen) *fromlen = sizeof(OrbisNetSockaddrIn);
        return ret;
    }
    uint8_t wrapped[2048 + TUN_HEADER_LEN];
    char *into = tunnel ? (char *)wrapped : (char *)buf;
    const int cap = tunnel ? (int)sizeof(wrapped) : (int)len;
    int ret;
next_datagram: /* after a tunnel control packet, which is not the game's */
    sin_len = sizeof(sin);
    ret = recvfrom(vs->s, into, cap, tunnel ? (win_flags & ~MSG_PEEK) : win_flags,
                   (struct sockaddr *)&sin, &sin_len);
    if (ret < 0) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            g_net_errno = 35;
            return -1;
        }
        g_net_errno = net_errno_from(err);
        return -1;
    }
    if (tunnel) {
        tunnel_keepalive(vs, &server);
        const uint8_t *payload = wrapped;
        uint8_t tflags;
        uint32_t ip;
        uint16_t port;
        int relay = -1;
        int route_in = 0; /* 0 direct, TUN_VIA_RELAY or TUN_VIA_SERVER: for the summary */
        if (from_server(&sin, &server)) {
            /* The server's pass and relay list. */
            if (tun_on_offer(wrapped, (size_t)ret, now_ms())) goto next_datagram;
            /* The server's own NAT replies (0x15, 0x1F, 0x0B...) go to the game unchanged. */
            if (tun_unwrap(wrapped, (size_t)ret, &tflags, &ip, &port)) {
                port = tunnel_alias(ip, port, wrapped + TUN_HEADER_LEN, ret - TUN_HEADER_LEN);
                tun_on_tunnelled(ip, port, tflags, 0, now_ms());
                if (tflags & TUN_FLAG_PING) ping_on_capable(ip, port, now_ms());
                sin.sin_addr.s_addr = ip;
                sin.sin_port = htons(port);
                payload = wrapped + TUN_HEADER_LEN;
                ret -= TUN_HEADER_LEN;
                route_in = TUN_VIA_SERVER;
            }
        } else if ((relay = tun_relay_index(sin.sin_addr.s_addr, ntohs(sin.sin_port))) >= 0) {
            /* A relay: its registration replies, and peers' tunnelled packets. Nothing else
             * from it is the game's. */
            if (!tun_unwrap(wrapped, (size_t)ret, &tflags, &ip, &port)) {
                tun_on_register_reply(relay, wrapped, (size_t)ret, now_ms());
                goto next_datagram;
            }
            port = tunnel_alias(ip, port, wrapped + TUN_HEADER_LEN, ret - TUN_HEADER_LEN);
            tun_on_tunnelled(ip, port, tflags, 1, now_ms());
            if (tflags & TUN_FLAG_PING) ping_on_capable(ip, port, now_ms());
            sin.sin_addr.s_addr = ip;
            sin.sin_port = htons(port);
            payload = wrapped + TUN_HEADER_LEN;
            ret -= TUN_HEADER_LEN;
            route_in = TUN_VIA_RELAY;
        } else {
            /* BB_ONLINE_DIRECT=0 (tests): peers' direct packets are dropped, so the game's
             * traffic with them has to come through the tunnel. */
            static int direct_off = -1;
            if (direct_off < 0) {
                const char *v = getenv("BB_ONLINE_DIRECT");
                direct_off = v && strcmp(v, "0") == 0;
                if (direct_off) runtime_net_trace("Tunnel: direct packets from peers ignored (BB_ONLINE_DIRECT=0)");
            }
            if (direct_off && tun_candidate(sin.sin_addr.s_addr, server.sin_addr.s_addr)) goto next_datagram;
            tun_on_direct(sin.sin_addr.s_addr, ntohs(sin.sin_port), now_ms());
        }
        if (ping_take(vs, payload, ret, &sin)) goto next_datagram;
        if (sin.sin_addr.s_addr != server.sin_addr.s_addr) {
            netstat_on_recv(&sin, payload, ret, route_in);
            if (multipath_copy(&sin, payload, ret, route_in)) goto next_datagram; /* the game has it */
        }
        /* A peek: the datagram has left the OS socket, so it is kept for the next read. */
        if ((win_flags & MSG_PEEK) && ret <= (int)sizeof(g_peeked.data)) {
            g_peeked.fd = s;
            g_peeked.len = ret;
            g_peeked.from = sin;
            memcpy(g_peeked.data, payload, (size_t)ret);
            netstat_on_peek();
        }
        if ((size_t)ret > len) ret = (int)len; /* a datagram longer than the buffer is cut, as recvfrom does */
        memcpy(buf, payload, (size_t)ret);
    }

    if (from) {
        OrbisNetSockaddrIn *out = (OrbisNetSockaddrIn *)from;
        out->sin_len = sizeof(OrbisNetSockaddrIn);
        out->sin_family = (uint8_t)sin.sin_family;
        out->sin_port = sin.sin_port;
        memcpy(&out->sin_addr, &sin.sin_addr, sizeof(out->sin_addr));
        memset(out->sin_zero, 0, sizeof(out->sin_zero));
    }

    if (tunnel) note_game_peer(vs, &sin);
    if (fromlen) *fromlen = sizeof(OrbisNetSockaddrIn);

    runtime_net_pkt_trace("sceNetRecvfrom(fd=%d, len=%d, from=%s:%u)", s, ret, inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    if (tunnel) netstat_maybe_report();
    return ret;
}

int32_t runtime_net_setsockopt(int s, int level, int optname, const void *optval, uint32_t optlen) {
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;

    if (optname == ORBIS_NET_SO_NBIO) {
        unsigned long mode = optval ? *(const uint32_t *)optval : 0;
        vs->non_blocking = (mode != 0);
        int ret = ioctlsocket(vs->s, FIONBIO, &mode);
        runtime_net_trace("sceNetSetsockopt(fd=%d, SO_NBIO=%lu) -> %d", s, mode, ret);
        return ret == 0 ? ORBIS_OK : -1;
    }

    int win_level = level;
    int win_optname = optname;

    if (level == 0xffff) {
        win_level = SOL_SOCKET;
        switch (optname) {
            case 0x0004: win_optname = SO_REUSEADDR; break;
            case 0x0008: win_optname = SO_KEEPALIVE; break;
            case 0x0020: win_optname = SO_BROADCAST; break;
            case 0x0080: win_optname = SO_LINGER; break;
            case 0x0100: win_optname = SO_OOBINLINE; break;
            case 0x1001: win_optname = SO_SNDBUF; break;
            case 0x1002: win_optname = SO_RCVBUF; break;
            case 0x1005: win_optname = SO_SNDTIMEO; break;
            case 0x1006: win_optname = SO_RCVTIMEO; break;
            case 0x1007: win_optname = SO_ERROR; break;
            case 0x1008: win_optname = SO_TYPE; break;
            default:
                /* PS4 BSD options: 0x1105 (SO_PROTOCOL/PROTOTYPE), 0x0200 (SO_REUSEPORT),
                 * 0x0800 (SO_NOSIGPIPE). Winsock does not implement them: ignore and succeed. */
                runtime_net_trace("sceNetSetsockopt(fd=%d, level=0x%x, optname=0x%x, len=%u) ignored (PS4 BSD opt)",
                                  s, level, optname, optlen);
                return ORBIS_OK;
        }
    }

    int ret = setsockopt(vs->s, win_level, win_optname, (const char *)optval, (int)optlen);
    if (ret != 0) {
        int err = WSAGetLastError();
        runtime_net_trace("sceNetSetsockopt(fd=%d, level=0x%x, optname=0x%x, len=%u) -> win err %d (treated as OK)",
                          s, level, optname, optlen, err);
        return ORBIS_OK;
    }
    runtime_net_trace("sceNetSetsockopt(fd=%d, level=0x%x, optname=0x%x, len=%u) -> OK",
                      s, level, optname, optlen);
    return ORBIS_OK;
}

int32_t runtime_net_getsockopt(int s, int level, int optname, void *optval, uint32_t *optlen) {
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;

    if (optname == ORBIS_NET_SO_NBIO) {
        if (optval && optlen && *optlen >= sizeof(uint32_t)) {
            *(uint32_t *)optval = vs->non_blocking ? 1 : 0;
            *optlen = sizeof(uint32_t);
            return ORBIS_OK;
        }
        return ORBIS_NET_EINVAL;
    }

    int win_level = (level == 0xffff) ? SOL_SOCKET : level;
    int win_optname = optname;
    if (level == 0xffff) {
        switch (optname) {
            case 0x0004: win_optname = SO_REUSEADDR; break;
            case 0x0008: win_optname = SO_KEEPALIVE; break;
            case 0x1001: win_optname = SO_SNDBUF; break;
            case 0x1002: win_optname = SO_RCVBUF; break;
            case 0x1007: win_optname = SO_ERROR; break;
            case 0x1008: win_optname = SO_TYPE; break;
            default:
                if (optval && optlen && *optlen >= 4) {
                    *(uint32_t *)optval = 0;
                    *optlen = 4;
                }
                return ORBIS_OK;
        }
    }

    NativeSockLen len = optlen ? (NativeSockLen)*optlen : 0;
    int ret = getsockopt(vs->s, win_level, win_optname, (char *)optval, &len);
    if (optlen) *optlen = len;
    if (ret != 0) {
        if (optval && optlen && *optlen >= 4) {
            *(uint32_t *)optval = 0;
            *optlen = 4;
        }
        return ORBIS_OK;
    }
    return ORBIS_OK;
}

int32_t runtime_net_getsockname(int s, OrbisNetSockaddr *name, uint32_t *namelen) {
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;

    struct sockaddr_in sin;
    NativeSockLen sin_len = sizeof(sin);
    int ret = getsockname(vs->s, (struct sockaddr *)&sin, &sin_len);
    if (ret != 0) return -1;

    if (name) {
        OrbisNetSockaddrIn *out = (OrbisNetSockaddrIn *)name;
        out->sin_len = sizeof(OrbisNetSockaddrIn);
        out->sin_family = (uint8_t)sin.sin_family;
        out->sin_port = sin.sin_port;
        memcpy(&out->sin_addr, &sin.sin_addr, sizeof(out->sin_addr));
        memset(out->sin_zero, 0, sizeof(out->sin_zero));
    }
    if (namelen) *namelen = sizeof(OrbisNetSockaddrIn);
    return ORBIS_OK;
}

int32_t runtime_net_shutdown(int s, int how) {
    VSocket *vs = vsocket_get(s);
    if (!vs) return ORBIS_NET_EBADF;
    return shutdown(vs->s, how);
}

/* Epoll emulation */
#define MAX_EPOLLS 16
#define MAX_EPOLL_ENTRIES 64

typedef struct {
    int socket_fd;
    uint32_t events;
    uint64_t ident;
    OrbisNetEpollData data;
} EpollEntry;

typedef struct {
    int in_use;
    EpollEntry entries[MAX_EPOLL_ENTRIES];
    int entry_count;
} EpollContext;

static EpollContext g_epolls[MAX_EPOLLS];

int32_t runtime_net_epoll_create(const char *name, int flags) {
    (void)flags;
    for (int i = 0; i < MAX_EPOLLS; i++) {
        if (!g_epolls[i].in_use) {
            g_epolls[i].in_use = 1;
            g_epolls[i].entry_count = 0;
            runtime_net_pkt_trace("sceNetEpollCreate('%s') -> eid=%d", name ? name : "", i + 1);
            return i + 1;
        }
    }
    return -1;
}

int32_t runtime_net_epoll_destroy(int eid) {
    int idx = eid - 1;
    if (idx >= 0 && idx < MAX_EPOLLS) {
        g_epolls[idx].in_use = 0;
        runtime_net_pkt_trace("sceNetEpollDestroy(eid=%d)", eid);
    }
    return ORBIS_OK;
}

int32_t runtime_net_epoll_control(int eid, int op, int s, OrbisNetEpollEvent *event) {
    int idx = eid - 1;
    if (idx < 0 || idx >= MAX_EPOLLS || !g_epolls[idx].in_use) return ORBIS_NET_EBADF;
    EpollContext *ep = &g_epolls[idx];

    if (op == ORBIS_NET_EPOLL_CTL_ADD) {
        if (ep->entry_count >= MAX_EPOLL_ENTRIES) return -1;
        ep->entries[ep->entry_count].socket_fd = s;
        ep->entries[ep->entry_count].events = event ? event->events : 0;
        ep->entries[ep->entry_count].ident = event ? event->ident : 0;
        ep->entries[ep->entry_count].data = event ? event->data : (OrbisNetEpollData){0};
        ep->entry_count++;
        runtime_net_pkt_trace("sceNetEpollControl(ADD, eid=%d, fd=%d, ev=0x%x)", eid, s, event ? event->events : 0);
        return ORBIS_OK;
    } else if (op == ORBIS_NET_EPOLL_CTL_MOD) {
        for (int i = 0; i < ep->entry_count; i++) {
            if (ep->entries[i].socket_fd == s) {
                ep->entries[i].events = event ? event->events : 0;
                ep->entries[i].ident = event ? event->ident : 0;
                ep->entries[i].data = event ? event->data : (OrbisNetEpollData){0};
                return ORBIS_OK;
            }
        }
        return -1;
    } else if (op == ORBIS_NET_EPOLL_CTL_DEL) {
        for (int i = 0; i < ep->entry_count; i++) {
            if (ep->entries[i].socket_fd == s) {
                ep->entries[i] = ep->entries[ep->entry_count - 1];
                ep->entry_count--;
                return ORBIS_OK;
            }
        }
        return -1;
    }
    return ORBIS_NET_EINVAL;
}

int32_t runtime_net_epoll_wait(int eid, OrbisNetEpollEvent *events, int maxevents, int timeout_usec) {
    int idx = eid - 1;
    if (idx < 0 || idx >= MAX_EPOLLS || !g_epolls[idx].in_use) return ORBIS_NET_EBADF;
    EpollContext *ep = &g_epolls[idx];
    if (ep->entry_count == 0 || maxevents <= 0) return 0;

    fd_set read_fds, write_fds, except_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&except_fds);

    SOCKET max_sock = 0;
    for (int i = 0; i < ep->entry_count; i++) {
        VSocket *vs = vsocket_get(ep->entries[i].socket_fd);
        if (vs) {
            if (ep->entries[i].events & ORBIS_NET_EPOLLIN) FD_SET(vs->s, &read_fds);
            if (ep->entries[i].events & (ORBIS_NET_EPOLLOUT | 0x00000004)) FD_SET(vs->s, &write_fds);
            FD_SET(vs->s, &except_fds);
            if (vs->s > max_sock) max_sock = vs->s;
        }
    }

    /* A datagram kept from a peek is no longer in the OS socket: that socket is readable now. */
    const int peek_fd = g_peeked.fd;
    int peek_pending = 0;
    for (int i = 0; i < ep->entry_count; i++)
        if (peek_fd && ep->entries[i].socket_fd == peek_fd && (ep->entries[i].events & ORBIS_NET_EPOLLIN))
            peek_pending = 1;

    struct timeval tv;
    struct timeval *ptv = NULL;
    if (timeout_usec >= 0 || peek_pending) {
        const int t = peek_pending ? 0 : timeout_usec;
        tv.tv_sec = t / 1000000;
        tv.tv_usec = t % 1000000;
        ptv = &tv;
    }

    int ret = select((int)(max_sock + 1), &read_fds, &write_fds, &except_fds, ptv);
    if (ret < 0) {
        if (!peek_pending) return 0;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_ZERO(&except_fds);
    } else if (ret == 0 && !peek_pending) {
        return 0;
    }

    int out_count = 0;
    for (int i = 0; i < ep->entry_count && out_count < maxevents; i++) {
        VSocket *vs = vsocket_get(ep->entries[i].socket_fd);
        if (!vs) continue;

        uint32_t revents = 0;
        if (FD_ISSET(vs->s, &read_fds) ||
            (peek_pending && ep->entries[i].socket_fd == peek_fd && (ep->entries[i].events & ORBIS_NET_EPOLLIN)))
            revents |= ORBIS_NET_EPOLLIN;
        if (FD_ISSET(vs->s, &write_fds)) {
            revents |= ORBIS_NET_EPOLLOUT;
            if (ep->entries[i].events & 0x00000004) revents |= 0x00000004;
        }
        if (FD_ISSET(vs->s, &except_fds)) revents |= ORBIS_NET_EPOLLERR;

        if (revents) {
            events[out_count].events = revents;
            events[out_count].pad = 0;
            events[out_count].ident = ep->entries[i].ident ? ep->entries[i].ident : (uint64_t)ep->entries[i].socket_fd;
            events[out_count].data = ep->entries[i].data;
            out_count++;
        }
    }

    if (out_count > 0) {
        runtime_net_pkt_trace("sceNetEpollWait(eid=%d) -> %d event(s) (ev=0x%x)", eid, out_count, events[0].events);
    }

    return out_count;
}

int32_t runtime_net_epoll_abort(int eid, int flags) {
    (void)eid; (void)flags;
    return ORBIS_OK;
}

/* Resolver */
int32_t runtime_net_resolver_create(const char *name, int pool, int flags) {
    (void)name; (void)pool; (void)flags;
    static int next_rid = 1;
    return next_rid++;
}

int32_t runtime_net_resolver_destroy(int rid) {
    (void)rid;
    return ORBIS_OK;
}

int32_t runtime_net_resolver_start_ntoa(int rid, const char *hostname, struct in_addr *addr, int timeout_usec, int retry, int flags) {
    (void)rid; (void)timeout_usec; (void)retry; (void)flags;
    if (!hostname || !addr) return ORBIS_NET_EINVAL;

    runtime_net_init();

    uint16_t port_override = 0;
    int is_http = 0;
    const char *target = net_overrides_lookup(hostname, &port_override, &is_http);

    if (target) {
        runtime_net_trace("sceNetResolverStartNtoa('%s') -> '%s' (OVERRIDDEN)", hostname, target);
        addr->s_addr = inet_addr(target);
        if (addr->s_addr == INADDR_NONE) {
            struct hostent *he = gethostbyname(target);
            if (he && he->h_addr_list[0]) {
                memcpy(addr, he->h_addr_list[0], sizeof(struct in_addr));
            }
        }
        return ORBIS_OK;
    }

    if (!net_overrides_is_allowed(hostname)) {
        runtime_net_trace("sceNetResolverStartNtoa('%s') -> BLOCKED by whitelist", hostname);
        g_net_errno = 65; /* EHOSTUNREACH */
        return ORBIS_NET_EHOSTUNREACH;
    }

    struct hostent *he = gethostbyname(hostname);
    if (he && he->h_addr_list[0]) {
        memcpy(addr, he->h_addr_list[0], sizeof(struct in_addr));
        char buf[32];
        inet_ntop(AF_INET, addr, buf, sizeof(buf));
        runtime_net_trace("sceNetResolverStartNtoa('%s') -> %s (DNS)", hostname, buf);
        return ORBIS_OK;
    }

    runtime_net_trace("sceNetResolverStartNtoa('%s') -> host not found", hostname);
    return ORBIS_NET_EHOSTUNREACH;
}

int32_t runtime_net_resolver_start_aton(int rid, struct in_addr addr, char *hostname, size_t hostlen, int timeout_usec, int retry, int flags) {
    (void)rid; (void)timeout_usec; (void)retry; (void)flags;
    if (!hostname || hostlen == 0) return ORBIS_NET_EINVAL;
    const char *str = inet_ntop(AF_INET, &addr, hostname, (socklen_t)hostlen);
    return str ? ORBIS_OK : -1;
}

int32_t runtime_net_resolver_abort(int rid, int flags) {
    (void)rid; (void)flags;
    return ORBIS_OK;
}

/* NetCtl implementation */
static int g_netctl_initialized = 0;
typedef ABI void (*NetCtlCallback)(int event, void *arg);

static struct {
    NetCtlCallback cb;
    void *arg;
    int active;
    int notified;
} netctl_cbs[8];

int32_t runtime_netctl_init(void) {
    g_netctl_initialized = 1;
    runtime_net_trace("sceNetCtlInit (online=%d)", runtime_net_is_online());
    return ORBIS_OK;
}

int32_t runtime_netctl_term(void) {
    g_netctl_initialized = 0;
    runtime_net_trace("sceNetCtlTerm");
    return ORBIS_OK;
}

int32_t runtime_netctl_state(int32_t *state) {
    if (!state) return NET_CTL_INVALID_ADDR;
    if (!runtime_net_is_online()) {
        *state = 0; /* DISCONNECTED */
        runtime_net_trace("sceNetCtlGetState -> DISCONNECTED (0)");
        return ORBIS_OK;
    }
    *state = 3; /* IPOBTAINED */
    runtime_net_trace("sceNetCtlGetState -> IPOBTAINED (3)");
    return ORBIS_OK;
}

int32_t runtime_netctl_info(int code, void *info) {
    if (!info) return NET_CTL_INVALID_ADDR;
    if (!runtime_net_is_online()) return NET_CTL_NOT_CONNECTED;

    if (code != 4) {
        runtime_net_trace("sceNetCtlGetInfo(code=%d)", code);
    }
    switch (code) {
        case 1:  /* DEVICE: wired */
            *(uint32_t *)info = 0;
            break;
        case 2:  /* ETHER_ADDR */
            memset(info, 0xAA, 6);
            break;
        case 3:  /* MTU */
            *(uint32_t *)info = 1500;
            break;
        case 4:  /* LINK: connected */
            *(uint32_t *)info = 1;
            break;
        case 11: /* IP_CONFIG: DHCP */
            *(uint32_t *)info = 1;
            break;
        case 14: /* IP_ADDRESS */
            strncpy((char *)info, local_ipv4(), 16);
            break;
        case 15: /* NETMASK */
            strncpy((char *)info, "255.255.255.0", 16);
            break;
        case 16: /* DEFAULT_ROUTE */
            strncpy((char *)info, "127.0.0.1", 16);
            break;
        case 17: /* PRIMARY_DNS */
            strncpy((char *)info, "1.1.1.1", 16);
            break;
        case 18: /* SECONDARY_DNS */
            strncpy((char *)info, "8.8.8.8", 16);
            break;
        case 19: /* HTTP_PROXY_CONFIG: none */
            *(uint32_t *)info = 0;
            break;
        default:
            memset(info, 0, 16);
            break;
    }
    return ORBIS_OK;
}

int32_t runtime_netctl_nat(OrbisNetCtlNatInfo *info) {
    if (!info) return NET_CTL_INVALID_ADDR;
    if (!runtime_net_is_online()) {
        info->stun_status = 0;
        info->nat_type = 3; /* Strict offline */
        info->mapped_addr = 0;
        runtime_net_trace("sceNetCtlGetNatInfo -> Type 3 (offline)");
        return ORBIS_OK;
    }
    info->stun_status = 0; /* OK */
    info->nat_type = 2;    /* Type 2 - Open / Moderate */
    info->mapped_addr = inet_addr("127.0.0.1");
    runtime_net_trace("sceNetCtlGetNatInfo -> Type 2 (Open, mapped=127.0.0.1)");
    return ORBIS_OK;
}

int32_t runtime_netctl_register(void *cb, void *arg, int32_t *cid) {
    if (!cid) return NET_CTL_INVALID_ADDR;
    for (int i = 0; i < 8; i++) {
        if (!netctl_cbs[i].active) {
            netctl_cbs[i].cb = (NetCtlCallback)cb;
            netctl_cbs[i].arg = arg;
            netctl_cbs[i].active = 1;
            netctl_cbs[i].notified = 0;
            *cid = i + 1;
            runtime_net_trace("sceNetCtlRegisterCallback -> slot %d", i);
            return ORBIS_OK;
        }
    }
    *cid = 1;
    return ORBIS_OK;
}

int32_t runtime_netctl_unregister(int32_t cid) {
    int idx = cid - 1;
    if (idx >= 0 && idx < 8) {
        netctl_cbs[idx].active = 0;
        netctl_cbs[idx].notified = 0;
        runtime_net_trace("sceNetCtlUnregisterCallback -> slot %d", idx);
    }
    return ORBIS_OK;
}

int32_t runtime_netctl_check(void) {
    if (runtime_net_is_online()) {
        for (int i = 0; i < 8; i++) {
            if (netctl_cbs[i].active && !netctl_cbs[i].notified && netctl_cbs[i].cb) {
                netctl_cbs[i].notified = 1;
                runtime_net_trace("sceNetCtlCheckCallback -> notifying netctl cb slot %d: IPOBTAINED (3)", i);
                netctl_cbs[i].cb(3 /* IPOBTAINED */, netctl_cbs[i].arg);
            }
        }
    }
    return ORBIS_OK;
}
