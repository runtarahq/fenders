// The guest-chosen arguments the launcher passes to the host, and those it
// refuses. Compiled and run by scripts/verify_network_native.sh.
#define _GNU_SOURCE
#include <assert.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include "guest_args.inc"

int main(void) {
    // Clocks: the fixed ones, and nothing that names another process.
    for(uint64_t id=CLOCK_REALTIME;id<=CLOCK_BOOTTIME;id++)assert(clock_permitted(id));
    assert(!clock_permitted(CLOCK_REALTIME_ALARM));
    assert(!clock_permitted(CLOCK_BOOTTIME_ALARM));
    assert(!clock_permitted(CLOCK_TAI));
    // A process's CPU-time clock, as clock_getcpuclockid makes one for pid
    // 1: a negative id.
    assert(!clock_permitted((uint64_t)(int64_t)-14));
    assert(!clock_permitted(UINT64_MAX));

    // Socket options: what a runtime asks of its own socket.
    assert(socket_option_readable(SOL_SOCKET,SO_ERROR));
    assert(socket_option_readable(SOL_SOCKET,SO_RCVBUF));
    assert(socket_option_readable(SOL_SOCKET,SO_ACCEPTCONN));
    assert(socket_option_readable(IPPROTO_TCP,TCP_NODELAY));
    assert(socket_option_readable(IPPROTO_IP,IP_TTL));
    // Not who is at the other end of the shim's sockets, nor the rest.
    assert(!socket_option_readable(SOL_SOCKET,SO_PEERCRED));
    assert(!socket_option_readable(SOL_SOCKET,SO_PEERSEC));
    assert(!socket_option_readable(SOL_SOCKET,SO_PEERGROUPS));
    assert(!socket_option_readable(SOL_SOCKET,SO_BINDTODEVICE));
    assert(!socket_option_readable(SOL_SOCKET,SO_COOKIE));
    assert(!socket_option_readable(IPPROTO_TCP,TCP_INFO));
    assert(!socket_option_readable(IPPROTO_TCP,TCP_CONGESTION));
    assert(!socket_option_readable(IPPROTO_IPV6,0));
    assert(!socket_option_readable(UINT64_MAX,SO_ERROR));

    // Message flags.
    assert(message_flags_permitted(0));
    assert(message_flags_permitted(MSG_DONTWAIT|MSG_NOSIGNAL));
    assert(message_flags_permitted(MSG_PEEK|MSG_WAITALL|MSG_TRUNC));
    assert(!message_flags_permitted(MSG_OOB));
    assert(!message_flags_permitted(MSG_ERRQUEUE));
    assert(!message_flags_permitted(MSG_FASTOPEN));
    assert(!message_flags_permitted(MSG_ZEROCOPY));
    assert(!message_flags_permitted(MSG_DONTROUTE));
    assert(!message_flags_permitted(MSG_DONTWAIT|MSG_OOB));
    assert(!message_flags_permitted(1ull<<40));
    puts("PASS guest-chosen clock ids, socket options and message flags");
    return 0;
}
