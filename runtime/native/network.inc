// Outbound access fixed at launch: TCP destinations in FENDERS_TCP_ALLOW and
// the DNS server. All connection state is protected by fd_lock. The guest
// never receives the management control socket.
static pthread_cond_t network_changed=PTHREAD_COND_INITIALIZER;
// Lifetime bytes accepted by host sockets created for guest outbound traffic.
// TLS records and DNS payloads count; ingress, file I/O, packet headers and
// retransmissions do not. Protected by fd_lock, including snapshot reads.
static uint64_t network_tx_bytes;
static int network_tx_measured=1;
// Optional admission ceiling, shared by every outbound descriptor and dup.
// The authority is cumulative for this execution; it is never reset by renewals.
static int network_budget_enabled,network_budget_authorized;
static uint64_t network_budget_revision,network_budget_deadline,network_budget_ceiling;
static uint64_t network_tx_reserved;
static uint64_t network_now(void);
#include "network_meter.inc"
static long network_account_tx(struct descriptor *desc,long count,size_t reserved) {
    if(desc->network) {
        pthread_mutex_lock(&fd_lock);
        if(count>0) {
            if(UINT64_MAX-network_tx_bytes<(uint64_t)count)network_tx_measured=0;
            else if(network_tx_measured)__atomic_store_n(&network_tx_bytes,network_tx_bytes+(uint64_t)count,__ATOMIC_RELAXED);
        }
        network_tx_reserved-=reserved;
        --network_tx_inflight;network_publish_locked();
        pthread_mutex_unlock(&fd_lock);
    }
    return count;
}
static void network_usage(uint64_t *bytes,int *measured) {
    pthread_mutex_lock(&fd_lock);
    *bytes=network_tx_bytes;*measured=network_tx_measured;
    pthread_mutex_unlock(&fd_lock);
}
static struct descriptor *network_io_descriptor(uint64_t guest) {
    struct descriptor *desc=lease_descriptor(guest);if(!desc)return NULL;
    pthread_mutex_lock(&fd_lock);
    int revoked=desc->network && desc->network->revoked;
    pthread_mutex_unlock(&fd_lock);
    return revoked?NULL:desc;
}
static long network_write(uint64_t guest,void *buffer,size_t size) {
    struct descriptor *desc=network_io_descriptor(guest);if(!desc)return -EBADF;
    long error=network_begin_tx(desc,size);if(error)return error;
    return network_account_tx(desc,result(write(desc->fd,buffer,size)),size);
}
static long network_writev(uint64_t guest,const struct iovec *vectors,int count) {
    struct descriptor *desc=network_io_descriptor(guest);if(!desc)return -EBADF;
    size_t size=0;if(count<0 || count>64)return -EINVAL;
    for(int i=0;i<count;i++) {
        if(vectors[i].iov_len>(size_t)SSIZE_MAX-size)return -EINVAL;
        size+=vectors[i].iov_len;
    }
    long error=network_begin_tx(desc,size);if(error)return error;
    return network_account_tx(desc,result(writev(desc->fd,vectors,count)),size);
}
static long network_send(uint64_t guest,void *buffer,size_t size,int flags) {
    struct descriptor *desc=network_io_descriptor(guest);if(!desc)return -EBADF;
    long error=network_begin_tx(desc,size);if(error)return error;
    return network_account_tx(desc,result(send(desc->fd,buffer,size,flags|MSG_NOSIGNAL)),size);
}

static uint64_t network_now(void) {
    // BOOTTIME is monotonic and includes host suspension. Suspending the host
    // must not extend network authority after the control plane expires it.
    struct timespec now;if(clock_gettime(CLOCK_BOOTTIME,&now))fail("network clock");
    return (uint64_t)now.tv_sec*1000000000ull+(uint64_t)now.tv_nsec;
}
static int network_number(const char *text,uint64_t *value) {
    if(!*text)return 0;
    for(const char *p=text;*p;p++)if(*p<'0' || *p>'9')return 0;
    char *end;errno=0;unsigned long long number=strtoull(text,&end,10);
    if(errno || *end)return 0;
    *value=number;return 1;
}
#include "network_budget.inc"
static int network_parse(char *text,struct sockaddr_in *entries,unsigned *count) {
    *count=0;if(!*text || !strcmp(text,"-"))return 1;
    // Reject empty entries; strtok alone would silently accept them.
    if(*text==',' || text[strlen(text)-1]==',' || strstr(text,",,"))return 0;
    char *save=NULL;
    for(char *entry=strtok_r(text,",",&save);entry;entry=strtok_r(NULL,",",&save)) {
        char *colon=strrchr(entry,':');uint64_t port;
        if(!colon || *count==32)return 0;
        *colon++=0;
        struct sockaddr_in address={.sin_family=AF_INET};
        if(!network_number(colon,&port) || !port || port>65535 || inet_pton(AF_INET,entry,&address.sin_addr)!=1)return 0;
        address.sin_port=htons((uint16_t)port);
        for(unsigned i=0;i<*count;i++)if(entries[i].sin_addr.s_addr==address.sin_addr.s_addr && entries[i].sin_port==address.sin_port)return 0;
        entries[(*count)++]=address;
    }
    return 1;
}
static int network_contains(const struct sockaddr_in *entries,unsigned count,const struct sockaddr_in *address) {
    if(address->sin_family!=AF_INET)return 0;
    for(unsigned i=0;i<count;i++)if(entries[i].sin_addr.s_addr==address->sin_addr.s_addr && entries[i].sin_port==address->sin_port)return 1;
    return 0;
}
static int destination_allowed_locked(int type,const struct sockaddr_in *address) {
    if(address->sin_family!=AF_INET)return 0;
    if(type==SOCK_DGRAM)return dns_server.sin_addr.s_addr!=INADDR_ANY && address->sin_addr.s_addr==dns_server.sin_addr.s_addr && address->sin_port==dns_server.sin_port;
    return type==SOCK_STREAM && network_contains(tcp_allow,tcp_allow_count,address);
}
static int guest_network_fd(int host,int type) {
    if(host<0)return -errno;
    struct network_connection *connection=calloc(1,sizeof(*connection));
    if(!connection){close(host);return -ENOMEM;}
    connection->refs=1;connection->type=type;
    return guest_fd_install(host,-1,connection);
}
static int guest_duplicate(uint64_t guest,int command) {
    struct descriptor *desc=lease_descriptor(guest);if(!desc)return -EBADF;
    int duplicate=fcntl(desc->fd,command,3);
    pthread_mutex_lock(&fd_lock);
    if(desc->network)++desc->network->refs;
    pthread_mutex_unlock(&fd_lock);
    return guest_fd_install(duplicate,desc->mount,desc->network);
}
static long network_connect(uint64_t guest,const struct sockaddr_in *address) {
    struct descriptor *desc=lease_descriptor(guest);if(!desc)return -EBADF;
    pthread_mutex_lock(&fd_lock);
    struct network_connection *connection=desc->network;
    if(!connection || connection->revoked || !destination_allowed_locked(connection->type,address)) {
        pthread_mutex_unlock(&fd_lock);return -EACCES;
    }
    // Never retarget a socket after it has an identity, including through dup.
    if(connection->assigned && (connection->peer.sin_addr.s_addr!=address->sin_addr.s_addr || connection->peer.sin_port!=address->sin_port)) {
        pthread_mutex_unlock(&fd_lock);return -EACCES;
    }
    connection->peer=*address;connection->assigned=1;
    pthread_mutex_unlock(&fd_lock);
    return result(connect(desc->fd,(const void *)address,sizeof(*address)));
}
static long network_sendto(uint64_t guest,void *buffer,size_t size,int flags,const struct sockaddr_in *address) {
    struct descriptor *desc=lease_descriptor(guest);if(!desc)return -EBADF;
    pthread_mutex_lock(&fd_lock);
    struct network_connection *connection=desc->network;
    // Stream I/O must use its connected peer. DNS is the only datagram path.
    int allowed=connection && !connection->revoked && connection->type==SOCK_DGRAM && destination_allowed_locked(connection->type,address);
    pthread_mutex_unlock(&fd_lock);
    if(!allowed)return -EACCES;
    long error=network_begin_tx(desc,size);if(error)return error;
    return network_account_tx(desc,result(sendto(desc->fd,buffer,size,flags|MSG_NOSIGNAL,(const void *)address,sizeof(*address))),size);
}
static void network_policy(void) {
    const char *budget=getenv("FENDERS_EGRESS_BUDGET");
    if(budget) {
        if(strcmp(budget,"1")){fprintf(DIAGNOSTICS,"invalid egress budget mode\n");exit(2);}
        network_budget_enabled=1;
        // How long a write short of allowance waits for a grant; none unless said.
        const char *wait=getenv("FENDERS_EGRESS_WAIT_MS");uint64_t milliseconds;
        if(wait) {
            if(!network_number(wait,&milliseconds) || milliseconds>30000){fprintf(DIAGNOSTICS,"invalid egress wait\n");exit(2);}
            network_budget_wait=milliseconds*1000000ull;
        }
    }
    const char *dns=getenv("FENDERS_DNS_SERVER");if(!dns)dns="0.0.0.0";
    dns_server.sin_family=AF_INET;dns_server.sin_port=htons(53);
    if(inet_pton(AF_INET,dns,&dns_server.sin_addr)!=1){fprintf(DIAGNOSTICS,"invalid DNS server\n");exit(2);}
    const char *policy=getenv("FENDERS_TCP_ALLOW");if(!policy)policy="-";
    char *copy=strdup(policy);if(!copy)fail("network allocation");
    if(!network_parse(copy,tcp_allow,&tcp_allow_count)){fprintf(DIAGNOSTICS,"invalid TCP policy\n");exit(2);}free(copy);
    // Leases and the start gate are gone: a launcher that still asks for
    // them gets a refusal rather than a run without them.
    if(getenv("FENDERS_NETWORK_DEADLINE_NS") || getenv("FENDERS_NETWORK_START_BLOCKED") ||
       getenv("FENDERS_EGRESS_FD") || getenv("FENDERS_EGRESS_PERIOD_FD") || getenv("FENDERS_OUTBOUND_REFUSAL_FD")) {
        fprintf(DIAGNOSTICS,"network leases, the start gate and meter files are no longer supported\n");exit(2);
    }
}
