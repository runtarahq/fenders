static const char *budget_update(uint64_t revision,uint64_t deadline,uint64_t ceiling) {
    char command[128];snprintf(command,sizeof(command),"egress %llu %llu %llu\n",
        (unsigned long long)revision,(unsigned long long)deadline,(unsigned long long)ceiling);
    return network_budget_command(command);
}
static void *budget_writer(void *pointer) {
    int guest=*(int *)pointer;
    for(unsigned i=0;i<200;i++) {
        long count=network_send(guest,"x",1,0);release_calls();
        assert(count==1 || count==-EDQUOT);
    }
    return NULL;
}
static void budget_tests(void) {
    assert(!strcmp(budget_update(1,0,0),"egress-budget-disabled"));
    setenv("FENDERS_EGRESS_BUDGET","1",1);setenv("FENDERS_TCP_ALLOW","-",1);
    setenv("FENDERS_DNS_SERVER","0.0.0.0",1);network_policy();
    int pair[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    int guest=guest_network_fd(pair[0],SOCK_STREAM);assert(guest>=3);
    assert(network_send(guest,"x",1,0)==-EDQUOT);release_calls();
    assert(network_refusals==2);
    uint64_t deadline=network_now()+30000000000ull;
    assert(!budget_update(1,deadline,10));assert(!budget_update(1,deadline,10));
    assert(!strcmp(budget_update(1,deadline,11),"conflicting-egress-budget"));
    assert(!strcmp(budget_update(1,deadline-1,10),"conflicting-egress-deadline"));
    assert(!strcmp(budget_update(2,deadline,9),"unsafe-egress-ceiling-reduction"));
    assert(!strcmp(budget_update(2,UINT64_MAX,10),"invalid-egress-deadline"));
    const char *invalid[]={"egress 0 0 0\n","egress -1 0 0\n","egress 1 0 0", "egress 1 0 0 \n",
        "egress 1 0 18446744073709551616\n","egress 1\n","egress 1 0\n"};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);i++) {
        char command[128];strcpy(command,invalid[i]);assert(!strcmp(network_budget_command(command),"invalid-egress-budget"));
    }
    assert(network_write(guest,"abc",3)==3);release_calls();
    int duplicate=guest_duplicate(guest,F_DUPFD_CLOEXEC);assert(duplicate>=3);release_calls();guest_close(guest);
    struct iovec vectors[]={{.iov_base="de",.iov_len=2},{.iov_base="fg",.iov_len=2}};
    assert(network_writev(duplicate,vectors,2)==4);release_calls();
    assert(network_refusals==2);
    assert(network_send(duplicate,"xyz!",4,0)==-EDQUOT);release_calls();
    assert(network_refusals==3);
    assert(network_send(duplicate,"hij",3,0)==3);release_calls();
    assert(network_writev(duplicate,vectors,2)==-EDQUOT);release_calls();
    char received[64];assert(recv(pair[1],received,10,MSG_WAITALL)==10);
    assert(!memcmp(received,"abcdefghij",10));usage_is(10,1);
    assert(network_send(duplicate,"",0,0)==0);release_calls();

    // A reservation remains unavailable to other writes until its completion.
    assert(!budget_update(2,deadline,20));
    struct descriptor *desc=network_io_descriptor(duplicate);assert(desc);
    assert(!network_begin_tx(desc,10));assert(network_tx_reserved==10);
    assert(network_send(duplicate,"x",1,0)==-EDQUOT);
    assert(network_account_tx(desc,-EAGAIN,10)==-EAGAIN);release_calls();
    assert(network_tx_reserved==0 && network_tx_inflight==0);usage_is(10,1);

    // Revoke/expiry prevent new admissions, but cannot retract bytes already
    // handed to a host syscall. Their full reservations must remain held.
    desc=network_io_descriptor(duplicate);assert(desc);assert(!network_begin_tx(desc,10));
    assert(!budget_update(3,0,20));
    assert(!strcmp(budget_update(4,deadline,19),"unsafe-egress-ceiling-reduction"));
    assert(!strcmp(budget_update(2,deadline,20),"stale-egress-budget"));
    assert(!strcmp(budget_update(3,deadline,20),"conflicting-egress-deadline"));
    assert(network_send(duplicate,"x",1,0)==-EDQUOT);
    assert(network_account_tx(desc,result(send(desc->fd,"after",5,MSG_NOSIGNAL)),10)==5);release_calls();
    assert(network_tx_reserved==0);usage_is(15,1);
    assert(!strcmp(budget_update(4,deadline,14),"unsafe-egress-ceiling-reduction"));
    assert(!budget_update(4,0,15)); // discard all unused credit after frozen completion
    assert(!strcmp(budget_update(3,deadline,20),"stale-egress-budget"));
    assert(!budget_update(5,network_now()+1000000ull,20));usleep(3000);
    assert(network_send(duplicate,"x",1,0)==-EDQUOT);release_calls();usage_is(15,1);
    assert(!budget_update(6,deadline,46));
    pthread_t writers[4];
    for(unsigned i=0;i<4;i++)assert(!pthread_create(&writers[i],NULL,budget_writer,&duplicate));
    for(unsigned i=0;i<4;i++)assert(!pthread_join(writers[i],NULL));
    assert(network_tx_reserved==0 && network_tx_inflight==0);usage_is(46,1);
    assert(recv(pair[1],received,36,MSG_WAITALL)==36);
    assert(recv(pair[1],received,1,MSG_DONTWAIT)==-1 && errno==EAGAIN);
    guest_close(duplicate);close(pair[1]);

    // Partial sends return all unused reservation, not just on failure.
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));guest=guest_network_fd(pair[0],SOCK_STREAM);
    int small=4096;assert(!setsockopt(pair[0],SOL_SOCKET,SO_SNDBUF,&small,sizeof(small)));
    const size_t large_size=1024*1024;char *large=calloc(1,large_size);assert(large);
    assert(!budget_update(7,deadline,46+large_size));
    long count=network_send(guest,large,large_size,MSG_DONTWAIT);release_calls();
    assert(count>0 && (size_t)count<large_size);assert(network_tx_reserved==0);usage_is(46+count,1);
    uint64_t expected=network_tx_bytes;
    assert(network_send(guest,"x",1,MSG_DONTWAIT)==-EAGAIN);release_calls();usage_is(expected,1);
    close(pair[1]);assert(network_send(guest,"x",1,0)==-EPIPE);release_calls();
    assert(network_tx_reserved==0 && network_tx_inflight==0);usage_is(expected,1);
    free(large);guest_close(guest);

    // DNS datagrams require their entire payload allowance, never truncation.
    int udp=socket(AF_INET,SOCK_DGRAM,0);assert(udp>=0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
    assert(!bind(udp,(void *)&address,sizeof(address)));socklen_t length=sizeof(address);
    assert(!getsockname(udp,(void *)&address,&length));dns_server=address;
    guest=guest_network_fd(socket(AF_INET,SOCK_DGRAM,0),SOCK_DGRAM);
    // Advance usage within the existing ceiling without resetting authority.
    network_tx_bytes=network_budget_ceiling-3;
    assert(network_sendto(guest,"four",4,0,&address)==-EDQUOT);release_calls();
    assert(network_sendto(guest,"dns",3,0,&address)==3);release_calls();
    assert(recv(udp,received,sizeof(received),0)==3 && !memcmp(received,"dns",3));
    assert(network_sendto(guest,"x",1,0,&address)==-EDQUOT);release_calls();
    guest_close(guest);close(udp);

    // Files and accepted ingress have no outbound marker and remain usable.
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));guest=guest_fd(pair[0]);
    expected=network_tx_bytes;assert(network_writev(guest,vectors,2)==4);release_calls();
    usage_is(expected,1);guest_close(guest);close(pair[1]);
    assert(!pipe(pair));guest=guest_fd(pair[1]);assert(network_write(guest,"file",4)==4);release_calls();
    usage_is(expected,1);guest_close(guest);close(pair[0]);

    // A descriptor revoked after lookup is refused at the reservation boundary.
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));guest=guest_network_fd(pair[0],SOCK_STREAM);
    desc=network_io_descriptor(guest);assert(desc);desc->network->revoked=1;
    assert(network_begin_tx(desc,1)==-EBADF);release_calls();desc->network->revoked=0;
    struct iovec overflow[]={{.iov_base="x",.iov_len=SSIZE_MAX},{.iov_base="y",.iov_len=1}};
    assert(network_writev(guest,overflow,2)==-EINVAL);release_calls();
    assert(network_writev(guest,vectors,-1)==-EINVAL);release_calls();
    assert(!budget_update(8,deadline,UINT64_MAX));network_tx_bytes=UINT64_MAX-2;
    assert(network_send(guest,"xy",2,0)==2);release_calls();usage_is(UINT64_MAX,1);
    assert(network_send(guest,"x",1,0)==-EDQUOT);release_calls();
    network_tx_measured=0;assert(network_send(guest,"",0,0)==-EDQUOT);release_calls();
    assert(network_refusals==7);
    char status[384];network_budget_status(status,sizeof(status));
    assert(strstr(status,"\"egress_budget_ceiling\":18446744073709551615"));
    assert(strstr(status,"\"egress_budget_reserved\":0"));
    assert(strstr(status,"\"egress_budget_measured\":false"));
    guest_close(guest);close(pair[1]);assert(!all_descriptors);
    puts("PASS egress byte admission: concurrency, dup, all write paths, partial/error refunds, expiry/revoke/replay, u64 bounds and excluded descriptors");
}
static void *budget_granter(void *pointer) {
    usleep(100000);assert(!budget_update(2,*(uint64_t *)pointer,10));return NULL;
}
// With FENDERS_EGRESS_WAIT_MS a write short of allowance waits for a grant,
// says on the meter how far the ceiling must reach, and is refused only
// when none came in time.
static void budget_wait_tests(void) {
    int pipefd[2];assert(!pipe(pipefd));
    char text[16];snprintf(text,sizeof(text),"%d",pipefd[1]);setenv("FENDERS_METER_FD",text,1);
    setenv("FENDERS_EGRESS_BUDGET","1",1);setenv("FENDERS_EGRESS_WAIT_MS","400",1);
    setenv("FENDERS_TCP_ALLOW","-",1);setenv("FENDERS_DNS_SERVER","0.0.0.0",1);network_policy();
    network_meter_start();
    int pair[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    int guest=guest_network_fd(pair[0],SOCK_STREAM);assert(guest>=3);
    uint64_t deadline=network_now()+30000000000ull;
    assert(!budget_update(1,deadline,4));
    assert(network_send(guest,"abcd",4,0)==4);release_calls();
    pthread_t granter;assert(!pthread_create(&granter,NULL,budget_granter,&deadline));
    uint64_t began=network_now();
    assert(network_send(guest,"efghij",6,0)==6);release_calls();
    assert(network_now()-began>=90000000ull && !network_refusals);
    assert(!pthread_join(granter,NULL));
    assert(!network_tx_wanted && !network_tx_waiting);usage_is(10,1);
    char lines[4096];ssize_t total=0,n;fcntl(pipefd[0],F_SETFL,O_NONBLOCK);
    while((n=read(pipefd[0],lines+total,sizeof(lines)-1-(size_t)total))>0)total+=n;
    lines[total]=0;
    assert(!strncmp(lines,"meter 0 0 1 0 0\n",16));
    assert(strstr(lines,"meter 4 0 1 0 10\n"));
    began=network_now();
    assert(network_send(guest,"x",1,0)==-EDQUOT);release_calls();
    assert(network_now()-began>=400000000ull && network_refusals==1 && !network_tx_wanted);
    // Authority that lapsed is waited for as well, and refused as expired.
    assert(!budget_update(3,network_now()+1000000ull,20));usleep(3000);
    began=network_now();
    assert(network_send(guest,"x",1,0)==-EDQUOT);release_calls();
    assert(network_now()-began>=400000000ull && network_refusals==3);
    // An unmeasurable total is refused at once.
    assert(!budget_update(4,deadline,20));network_tx_measured=0;began=network_now();
    assert(network_send(guest,"x",1,0)==-EDQUOT);release_calls();
    assert(network_now()-began<200000000ull && network_refusals==7);
    guest_close(guest);close(pair[1]);close(pipefd[0]);
    puts("PASS egress byte admission waits for a grant when told to: admitted when it comes, said on the meter, refused when it does not");
}
