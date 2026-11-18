// Descriptor lifetime and duplicate ownership shared by VMM and native tests.
struct network_connection {unsigned refs;int type,assigned,revoked;struct sockaddr_in peer;};
struct descriptor {int fd;unsigned refs;int mount;struct network_connection *network;struct descriptor *next;};
static struct descriptor *host_fds[64];
static struct descriptor *all_descriptors;
static _Thread_local struct descriptor *leases[128];
static _Thread_local unsigned lease_count;
static pthread_mutex_t fd_lock=PTHREAD_MUTEX_INITIALIZER;
static int guest_fd_install(int host,int mount,struct network_connection *network) {
    int error=host<0?errno:ENOMEM;
    struct descriptor *desc=host<0?NULL:malloc(sizeof(*desc));
    if(!desc){
        if(host>=0)close(host);
        pthread_mutex_lock(&fd_lock);if(network && !--network->refs)free(network);pthread_mutex_unlock(&fd_lock);
        return -error;
    }
    // Whatever the guest asked for, a host descriptor is closed on exec: the
    // launcher runs no other program, and none may inherit a guest's files
    // and sockets if it ever did.
    fcntl(host,F_SETFD,FD_CLOEXEC);
    *desc=(struct descriptor){.fd=host,.refs=1,.mount=mount,.network=network};
    pthread_mutex_lock(&fd_lock);
    for(unsigned i=3;i<64;i++) if(!host_fds[i]) {host_fds[i]=desc;desc->next=all_descriptors;all_descriptors=desc;pthread_mutex_unlock(&fd_lock);return i;}
    if(network && !--network->refs)free(network);
    pthread_mutex_unlock(&fd_lock);free(desc);close(host);return -EMFILE;
}
static int guest_fd_mount(int host,int mount) {return guest_fd_install(host,mount,NULL);}
static int guest_fd(int host) {return guest_fd_mount(host,-1);}
static void release_descriptor(struct descriptor *desc) {
    // Caller holds fd_lock. A descriptor cannot be reused beneath a concurrent syscall.
    if(!--desc->refs){
        struct descriptor **entry=&all_descriptors;
        while(*entry && *entry!=desc)entry=&(*entry)->next;
        if(*entry)*entry=desc->next;
        if(desc->network && !--desc->network->refs)free(desc->network);
        close(desc->fd);free(desc);
    }
}
static struct descriptor *lease_descriptor(uint64_t fd) {
    pthread_mutex_lock(&fd_lock);struct descriptor *desc=fd<64?host_fds[fd]:NULL;
    if(!desc || lease_count==128){pthread_mutex_unlock(&fd_lock);return NULL;}
    ++desc->refs;leases[lease_count++]=desc;pthread_mutex_unlock(&fd_lock);return desc;
}
static int host_fd(uint64_t fd) {
    struct descriptor *desc=lease_descriptor(fd);if(!desc)return -1;
    pthread_mutex_lock(&fd_lock);
    int host=desc->network && desc->network->revoked?-1:desc->fd;
    pthread_mutex_unlock(&fd_lock);return host;
}
