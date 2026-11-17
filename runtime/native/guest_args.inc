// Arguments a guest chooses for calls that are passed on to the host.
//
// The guest picks the clock, the socket option and the message flags; the
// host call would take any of them. Only those the guest runtime has a use
// for are passed on: a dynamic clock id names another process's CPU time, a
// socket option such as SO_PEERCRED tells of the shim, and a flag such as
// MSG_OOB or MSG_ERRQUEUE reaches code no guest needs reached.

// CLOCK_REALTIME (0) to CLOCK_BOOTTIME (7): the fixed clocks, with this
// process's own CPU time. Not the alarm clocks, and not a dynamic id (the
// negative ones, which name a process, a thread or a descriptor).
static int clock_permitted(uint64_t id) {
    return id<=CLOCK_BOOTTIME;
}

// Options a guest may read. What it may set is a subset of these.
static int socket_option_readable(uint64_t level,uint64_t name) {
    if(level==SOL_SOCKET)
        return name==SO_ERROR || name==SO_TYPE || name==SO_DOMAIN || name==SO_PROTOCOL ||
            name==SO_ACCEPTCONN || name==SO_KEEPALIVE || name==SO_REUSEADDR ||
            name==SO_RCVBUF || name==SO_SNDBUF;
    if(level==IPPROTO_TCP)
        return name==TCP_NODELAY || name==TCP_KEEPIDLE || name==TCP_KEEPINTVL || name==TCP_KEEPCNT;
    if(level==IPPROTO_IP)return name==IP_TTL;
    return 0;
}

// Flags of send and recv a guest may give.
static int message_flags_permitted(uint64_t flags) {
    return !(flags&~(uint64_t)(MSG_DONTWAIT|MSG_PEEK|MSG_WAITALL|MSG_TRUNC|MSG_NOSIGNAL));
}

// A futex call a guest makes, as the host is asked it: wait and wake, plain
// or by bitset, and always private. Every guest thread shares this
// process's memory, and a shared key on a page still backed by the
// component's file would be one with every other VM that maps the same
// file: a guest that leaves the private flag off is given it. The operation
// the host is to be asked, or a negative error.
static long futex_operation(uint64_t requested) {
    unsigned op=requested&FUTEX_CMD_MASK;
    if(op!=FUTEX_WAIT && op!=FUTEX_WAKE && op!=FUTEX_WAIT_BITSET && op!=FUTEX_WAKE_BITSET)return -ENOSYS;
    if(requested&~(uint64_t)(FUTEX_CMD_MASK|FUTEX_PRIVATE_FLAG|FUTEX_CLOCK_REALTIME))return -EINVAL;
    return (long)(requested|FUTEX_PRIVATE_FLAG);
}
