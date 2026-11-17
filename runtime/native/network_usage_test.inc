// Exercise the production outbound syscall wrappers against real host sockets.
// These tests do not claim guest execution, wire-byte billing or live TLS.
static void usage_is(uint64_t expected,int valid) {
    uint64_t bytes;int measured;network_usage(&bytes,&measured);
    assert(bytes==expected && measured==valid);
}
static void *traffic_writer(void *pointer) {
    int guest=*(int *)pointer;
    for(unsigned i=0;i<200;i++) {
        assert(network_send(guest,"x",1,0)==1);release_calls();
    }
    return NULL;
}
static void traffic_accounting(void) {
    struct sockaddr_in address;int server=listener(&address),peer;
    tcp_allow[0]=address;tcp_allow_count=1;
    int guest=connected(server,&address,&peer);
    usage_is(0,1);
    assert(network_write(guest,"abc",3)==3);release_calls();
    int duplicate=guest_duplicate(guest,F_DUPFD_CLOEXEC);assert(duplicate>=3);release_calls();
    guest_close(guest);
    struct iovec vector[]={{.iov_base="def",.iov_len=3},{.iov_base="gh",.iov_len=2}};
    assert(network_writev(duplicate,vector,2)==5);release_calls();
    assert(network_send(duplicate,"ij",2,0)==2);release_calls();
    char received[10];assert(recv(peer,received,sizeof(received),MSG_WAITALL)==10);
    assert(!memcmp(received,"abcdefghij",10));usage_is(10,1);
    pthread_t writers[4];
    for(unsigned i=0;i<4;i++)assert(!pthread_create(&writers[i],NULL,traffic_writer,&duplicate));
    for(unsigned i=0;i<4;i++)assert(!pthread_join(writers[i],NULL));
    char concurrent[800];assert(recv(peer,concurrent,sizeof(concurrent),MSG_WAITALL)==800);
    usage_is(810,1);

    // Count the actual accepted bytes, including partial nonblocking sends;
    // failed and zero-length operations must not change the counter.
    int fd=host_fd(duplicate),small=4096;assert(fd>=0);
    assert(!setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&small,sizeof(small)));release_calls();
    char *large=calloc(1,1024*1024);assert(large);
    uint64_t expected=810;int partial=0,blocked=0;
    for(unsigned i=0;i<1000;i++) {
        long count=network_send(duplicate,large,1024*1024,MSG_DONTWAIT);release_calls();
        if(count==-EAGAIN || count==-EWOULDBLOCK){blocked=1;break;}
        assert(count>0);if(count<1024*1024)partial=1;expected+=(uint64_t)count;
    }
    assert(partial && blocked);free(large);usage_is(expected,1);
    assert(network_send(duplicate,"",0,MSG_DONTWAIT)==0);release_calls();usage_is(expected,1);
    guest_close(duplicate);close(peer);close(server);
    assert(network_send(duplicate,"x",1,0)==-EBADF);release_calls();usage_is(expected,1);

    // The DNS datagram path counts bytes too, and refusal does not count.
    int udp=socket(AF_INET,SOCK_DGRAM,0);assert(udp>=0);
    address.sin_port=0;assert(!bind(udp,(void *)&address,sizeof(address)));
    socklen_t size=sizeof(address);assert(!getsockname(udp,(void *)&address,&size));dns_server=address;
    guest=guest_network_fd(socket(AF_INET,SOCK_DGRAM,0),SOCK_DGRAM);assert(guest>=3);
    assert(network_sendto(guest,"dns",3,0,&address)==3);release_calls();expected+=3;
    assert(recv(udp,received,sizeof(received),0)==3);usage_is(expected,1);
    struct sockaddr_in denied=address;denied.sin_addr.s_addr=htonl(INADDR_ANY);
    assert(network_sendto(guest,"bad",3,0,&denied)==-EACCES);release_calls();usage_is(expected,1);
    pthread_mutex_lock(&fd_lock);host_fds[guest]->network->revoked=1;pthread_mutex_unlock(&fd_lock);
    assert(network_write(guest,"bad",3)==-EBADF);release_calls();usage_is(expected,1);
    guest_close(guest);close(udp);

    // Accepted ingress sockets and file descriptors have no outbound marker.
    int pair[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    guest=guest_fd(pair[0]);assert(network_writev(guest,vector,2)==5);release_calls();
    assert(network_send(guest,"i",1,0)==1);release_calls();usage_is(expected,1);
    guest_close(guest);close(pair[1]);
    assert(!pipe(pair));guest=guest_fd(pair[1]);
    assert(network_write(guest,"file",4)==4);release_calls();usage_is(expected,1);
    guest_close(guest);close(pair[0]);

    // Overflow invalidates measurement instead of wrapping or reporting a
    // saturated value as an exact total. Invalidity is sticky.
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    guest=guest_network_fd(pair[0],SOCK_STREAM);
    network_tx_bytes=UINT64_MAX;
    assert(network_send(guest,"x",1,0)==1);release_calls();usage_is(UINT64_MAX,0);
    assert(network_send(guest,"x",1,0)==1);release_calls();usage_is(UINT64_MAX,0);
    guest_close(guest);close(pair[1]);assert(!all_descriptors);
    network_tx_bytes=0;network_tx_measured=1;tcp_allow_count=0;memset(&dns_server,0,sizeof(dns_server));
    puts("PASS outbound payload counters: dup, write/writev/send/sendto, concurrency, partial/error I/O, DNS, refused descriptors, ingress/files excluded, overflow invalidated");
}
