// Native socket enforcement tests. Uses the same descriptor/policy code as the
// VMM, without emulating or claiming KVM guest execution.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <signal.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
static void fail(const char *message){perror(message);exit(1);}
static long result(long value){return value<0?-errno:value;}
#include "diagnostics.inc"
#include "descriptors.inc"
static struct sockaddr_in tcp_allow[32],dns_server;
static unsigned tcp_allow_count;
#include "network.inc"
#include "control_command.inc"

static void *fragment_writer(void *pointer) {
    int fd=*(int *)pointer;
    const char *parts[]={"egress ","123 ","0 ","5","\n"};
    for(unsigned i=0;i<sizeof(parts)/sizeof(*parts);i++){assert(write(fd,parts[i],strlen(parts[i]))==(ssize_t)strlen(parts[i]));usleep(1000);}
    return NULL;
}
static void control_framing(void) {
    int pair[2];char buffer[64];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    pthread_t writer;assert(!pthread_create(&writer,NULL,fragment_writer,&pair[0]));
    assert(control_read_command(pair[1],buffer,sizeof(buffer)));
    assert(!strcmp(buffer,"egress 123 0 5\n"));assert(!pthread_join(writer,NULL));
    char invalid[]="status\0extra\n";assert(write(pair[0],invalid,sizeof(invalid)-1)==sizeof(invalid)-1);
    assert(!control_read_command(pair[1],buffer,sizeof(buffer)));
    memset(buffer,'a',sizeof(buffer));assert(write(pair[0],buffer,sizeof(buffer))==sizeof(buffer));
    assert(!control_read_command(pair[1],buffer,sizeof(buffer)));
    close(pair[0]);close(pair[1]);puts("PASS fragmented management commands, embedded NUL and size limits");
}

static void release_calls(void) {
    pthread_mutex_lock(&fd_lock);
    for(unsigned i=0;i<lease_count;i++)release_descriptor(leases[i]);
    lease_count=0;pthread_mutex_unlock(&fd_lock);
}
static void guest_close(int guest) {
    pthread_mutex_lock(&fd_lock);
    struct descriptor *desc=host_fds[guest];host_fds[guest]=NULL;
    if(desc)release_descriptor(desc);
    pthread_mutex_unlock(&fd_lock);
}
static int listener(struct sockaddr_in *address) {
    int fd=socket(AF_INET,SOCK_STREAM,0);assert(fd>=0);
    *address=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
    assert(!bind(fd,(void *)address,sizeof(*address)));
    socklen_t size=sizeof(*address);assert(!getsockname(fd,(void *)address,&size));
    assert(!listen(fd,8));return fd;
}
static int connected(int server,const struct sockaddr_in *address,int *peer) {
    int guest=guest_network_fd(socket(AF_INET,SOCK_STREAM,0),SOCK_STREAM);assert(guest>=3);
    assert(network_connect(guest,address)==0);release_calls();
    *peer=accept(server,NULL,NULL);assert(*peer>=0);return guest;
}
#include "network_usage_test.inc"
#include "network_budget_test.inc"
// The meter pipe carries cumulative totals; its last line is the run's total.
static void meter_pipe(void) {
    int pipefd[2];assert(!pipe(pipefd));
    char text[16];snprintf(text,sizeof(text),"%d",pipefd[1]);setenv("FENDERS_METER_FD",text,1);
    network_meter_start();
    int pair[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    int guest=guest_network_fd(pair[0],SOCK_STREAM);assert(guest>=3);
    for(unsigned i=0;i<1000;i++) {
        assert(network_send(guest,"xy",2,0)==2);release_calls();
        char drain[2];assert(recv(pair[1],drain,2,MSG_WAITALL)==2);
    }
    usleep(3*METER_PERIOD_NS/1000);
    meter_final();
    char lines[65536];ssize_t total=0,n;
    fcntl(pipefd[0],F_SETFL,O_NONBLOCK);
    while((n=read(pipefd[0],lines+total,sizeof(lines)-1-(size_t)total))>0)total+=n;
    lines[total]=0;assert(total>0 && lines[total-1]=='\n');lines[total-1]=0;
    char *last=strrchr(lines,'\n');last=last?last+1:lines;
    unsigned long long bytes,inflight,refusals;int measured;
    assert(sscanf(last,"final %llu %llu %d %llu",&bytes,&inflight,&measured,&refusals)==4);
    assert(bytes==2000 && inflight==0 && measured==1 && refusals==0);
    assert(!strncmp(lines,"meter 0 0 1 0",13));
    guest_close(guest);close(pair[1]);close(pipefd[0]);
    // The reader stays the run's: the meter descriptor is never inherited.
    assert(fcntl(pipefd[1],F_GETFD)&FD_CLOEXEC);
    puts("PASS meter pipe: initial and cumulative totals, final line on exit, close-on-exec");
}
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"--budget")){budget_tests();return 0;}
    if(argc==2 && !strcmp(argv[1],"--budget-wait")){budget_wait_tests();return 0;}
    if(argc==2 && !strcmp(argv[1],"--meter")){meter_pipe();return 0;}
    if(argc==2 && !strcmp(argv[1],"--leases")) {
        setenv("FENDERS_NETWORK_DEADLINE_NS","0",1);network_policy();
        return 1; // network_policy exits 2: leases are refused, not ignored
    }
    control_framing();
    traffic_accounting();
    struct sockaddr_in first,second,foreign;
    int a=listener(&first),b=listener(&second),c=listener(&foreign);
    char allow[128];
    snprintf(allow,sizeof(allow),"127.0.0.1:%u,127.0.0.1:%u",ntohs(first.sin_port),ntohs(second.sin_port));
    setenv("FENDERS_TCP_ALLOW",allow,1);setenv("FENDERS_DNS_SERVER","0.0.0.0",1);network_policy();
    int peer,guest=connected(a,&first,&peer);
    assert(write(host_fd(guest),"s",1)==1);release_calls();
    char byte;assert(read(peer,&byte,1)==1 && byte=='s');
    puts("PASS static launch policy connects to an allowed destination");
    int denied=guest_network_fd(socket(AF_INET,SOCK_STREAM,0),SOCK_STREAM);
    assert(network_connect(denied,&foreign)==-EACCES);release_calls();
    assert(network_connect(guest,&second)==-EACCES);release_calls();
    int datagram=guest_network_fd(socket(AF_INET,SOCK_DGRAM,0),SOCK_DGRAM);
    assert(network_sendto(datagram,"x",1,0,&foreign)==-EACCES);release_calls();
    puts("PASS denied destination and socket retargeting");
    // Dup before connect shares one destination identity.
    int unconnected=guest_network_fd(socket(AF_INET,SOCK_STREAM,0),SOCK_STREAM);
    int early_dup=guest_duplicate(unconnected,F_DUPFD);release_calls();
    assert(network_connect(early_dup,&second)==0);release_calls();int early_peer=accept(b,NULL,NULL);assert(early_peer>=0);
    assert(network_connect(unconnected,&first)==-EACCES);release_calls();
    puts("PASS dup-before-connect keeps one destination");
    int ingress_pair[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,ingress_pair));
    int ingress=guest_fd(ingress_pair[0]);assert(write(host_fd(ingress),"i",1)==1);release_calls();
    assert(read(ingress_pair[1],&byte,1)==1 && byte=='i');
    for(unsigned i=3;i<64;i++)if(host_fds[i])guest_close((int)i);
    assert(!all_descriptors);
    close(a);close(b);close(c);close(peer);close(early_peer);close(ingress_pair[1]);
    puts("PASS descriptor ownership cleanup");return 0;
}
