// Host-only meter: cumulative outbound totals written to a pipe the launcher
// reads (FENDERS_METER_FD), never into guest memory or its descriptor table.
// Each line is `meter BYTES IN_FLIGHT MEASURED REFUSALS\n`: totals, not
// increments, so a reader that misses lines loses nothing but freshness. The
// line written as the VMM exits says `final` instead of `meter`.
// Lines are written at most every METER_PERIOD_NS while totals change, and
// once more as the VMM exits; a VMM killed outright loses at most one period.
// REFUSALS is a bitmask of egress budget refusal classes seen (1 over the
// ceiling, 2 expired authority, 4 unmeasurable). A launch with an egress
// budget adds one more number, WANTED: the total its waiting writes need the
// ceiling to reach, 0 when none waits.
#define METER_PERIOD_NS 50000000L
static uint64_t network_tx_inflight,network_refusals,network_tx_wanted,network_tx_waiting,network_budget_wait;
static int meter_fd=-1;
static _Atomic int meter_dirty;
static void network_refused(uint64_t reason) {network_refusals|=reason;}
static void network_publish_locked(void) {atomic_store(&meter_dirty,1);}
// Set under fd_lock as the VMM exits: no write is admitted after the totals
// its last line gives.
static int network_closed;
// `unsettled` is added to the writes in flight: a line that could not be made
// under fd_lock says so by never reading as complete.
static int meter_line(char *line,size_t capacity,const char *kind,uint64_t unsettled) {
    int length=snprintf(line,capacity,"%s %llu %llu %d %llu",kind,
        (unsigned long long)__atomic_load_n(&network_tx_bytes,__ATOMIC_RELAXED),
        (unsigned long long)(__atomic_load_n(&network_tx_inflight,__ATOMIC_RELAXED)+unsettled),
        __atomic_load_n(&network_tx_measured,__ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&network_refusals,__ATOMIC_RELAXED));
    if(network_budget_enabled)length+=snprintf(line+length,capacity-(size_t)length," %llu",
        (unsigned long long)__atomic_load_n(&network_tx_wanted,__ATOMIC_RELAXED));
    line[length++]='\n';return length;
}
static void meter_write_line(const char *kind,uint64_t unsettled) {
    char line[128];int length=meter_line(line,sizeof(line),kind,unsettled);
    // A full pipe drops this line: the next carries the same totals and more.
    if(write(meter_fd,line,(size_t)length)<0 && errno!=EAGAIN)meter_fd=-1;
}
static void meter_write(const char *kind) {meter_write_line(kind,0);}
static void *meter_thread(void *unused) {
    (void)unused;
    for(;;) {
        struct timespec tick={.tv_nsec=METER_PERIOD_NS};nanosleep(&tick,NULL);
        if(meter_fd>=0 && atomic_exchange(&meter_dirty,0))meter_write("meter");
    }
    return NULL;
}
// On exit (guest exit, fatal signal report, failure): the final totals. The
// guest's other threads run until the process ends, so admission is closed
// and the totals read under fd_lock: a line with nothing in flight is then
// everything this run sent. The exiting thread, or one that will never run
// again, may hold fd_lock; the lock is waited for briefly, and without it the
// line says a write is in flight, which a reader takes as incomplete.
static void meter_final(void) {
    struct timespec until;clock_gettime(CLOCK_REALTIME,&until);
    until.tv_nsec+=100000000;if(until.tv_nsec>=1000000000){until.tv_nsec-=1000000000;++until.tv_sec;}
    int held=!pthread_mutex_timedlock(&fd_lock,&until);
    if(held)network_closed=1;
    struct pollfd ready={.fd=meter_fd,.events=POLLOUT};
    if(meter_fd>=0 && poll(&ready,1,100)==1)meter_write_line("final",held?0:1);
    if(held){pthread_cond_broadcast(&network_changed);pthread_mutex_unlock(&fd_lock);}
}
static void network_meter_start(void) {
    const char *text=getenv("FENDERS_METER_FD");if(!text)return;
    char *end;errno=0;long fd=strtol(text,&end,10);struct stat info;
    if(errno || !*text || *end || fd<3 || fd>INT_MAX || fstat((int)fd,&info) || !S_ISFIFO(info.st_mode)) {
        fprintf(DIAGNOSTICS,"invalid inherited meter pipe\n");exit(2);
    }
    meter_fd=(int)fd;
    // A reader that went away ends the meter (EPIPE), never the VMM.
    signal(SIGPIPE,SIG_IGN);
    if(fcntl(meter_fd,F_SETFD,FD_CLOEXEC) || fcntl(meter_fd,F_SETFL,fcntl(meter_fd,F_GETFL)|O_NONBLOCK))fail("meter pipe");
    meter_write("meter");
    atexit(meter_final);
    pthread_t thread;int error=pthread_create(&thread,NULL,meter_thread,NULL);
    if(error){errno=error;fail("meter thread");}pthread_detach(thread);
}
// A write the budget cannot admit yet. Without FENDERS_EGRESS_WAIT_MS it is
// refused at once. With it, the write waits that long for a grant that
// admits it (the meter says how far the total must reach), and is refused
// only then. An unmeasurable total is never waited for.
static uint64_t network_budget_shortfall_locked(size_t size) {
    if(!network_tx_measured)return 4;
    if(network_budget_deadline<=network_now())return 2;
    if(network_tx_bytes>network_budget_ceiling ||
        network_tx_reserved>network_budget_ceiling-network_tx_bytes ||
        size>network_budget_ceiling-network_tx_bytes-network_tx_reserved)return 1;
    return 0;
}
static long network_begin_tx(struct descriptor *desc,size_t size) {
    if(size>(size_t)SSIZE_MAX)return -EINVAL;
    if(!desc->network)return 0;
    pthread_mutex_lock(&fd_lock);
    long error=0;
    if(desc->network->revoked || network_closed)error=-EBADF;
    else if(UINT64_MAX-network_tx_reserved<size)error=-EAGAIN;
    else if(network_budget_enabled) {
        uint64_t reason,until=0;
        while((reason=network_budget_shortfall_locked(size))) {
            uint64_t now=network_now();
            if(!until)until=now+network_budget_wait;
            if(reason==4 || now>=until || desc->network->revoked || network_closed)break;
            uint64_t wanted=UINT64_MAX-network_tx_bytes<network_tx_reserved ||
                UINT64_MAX-network_tx_bytes-network_tx_reserved<size?UINT64_MAX:network_tx_bytes+network_tx_reserved+size;
            if(wanted>network_tx_wanted) {
                __atomic_store_n(&network_tx_wanted,wanted,__ATOMIC_RELAXED);
                // Said at once: the grant is asked for while this write waits.
                if(meter_fd>=0)meter_write("meter");
            }
            ++network_tx_waiting;
            struct timespec tick;clock_gettime(CLOCK_REALTIME,&tick);
            uint64_t left=until-now;if(left>20000000)left=20000000;
            tick.tv_nsec+=(long)left;if(tick.tv_nsec>=1000000000){tick.tv_nsec-=1000000000;++tick.tv_sec;}
            pthread_cond_timedwait(&network_changed,&fd_lock,&tick);
            if(!--network_tx_waiting)__atomic_store_n(&network_tx_wanted,0,__ATOMIC_RELAXED);
        }
        if(desc->network->revoked || network_closed)error=-EBADF;
        else if(reason){network_refused(reason);error=-EDQUOT;}
    }
    if(error){pthread_mutex_unlock(&fd_lock);network_publish_locked();return error;}
    network_tx_reserved+=size;
    ++network_tx_inflight;network_publish_locked();
    pthread_mutex_unlock(&fd_lock);return 0;
}
