#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %s line %d errno %d\n",#x,__LINE__,errno); return 1; } } while (0)
static void *thread_main(void *value) { return value; }
static struct sockaddr_in loopback(int port) {
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK),.sin_port=htons((unsigned short)port)};
    return address;
}
int main(int argc,char **argv) {
    CHECK(argc==9);
    int compiler=!strcmp(argv[1],"compiler");
    int fd=open(argv[2],O_RDONLY);CHECK(fd>=0);char data[4];CHECK(read(fd,data,4)==4);close(fd);
    CHECK(open(argv[3],O_RDONLY)==-1 && errno==EACCES);
    CHECK(open(argv[2],O_WRONLY|O_TRUNC)==-1 && errno==EACCES);
    if(compiler) {
        fd=open(argv[4],O_WRONLY|O_TRUNC);CHECK(fd>=0);CHECK(write(fd,"compiled",8)==8);close(fd);
    } else CHECK(open(argv[4],O_WRONLY|O_TRUNC)==-1 && errno==EACCES);
    CHECK(open(argv[5],O_WRONLY|O_CREAT,0600)==-1 && errno==EACCES);
    puts("PASS own inputs readable; unrelated secrets, input writes and new files denied");
    CHECK(fork()==-1 && errno==EPERM);
    CHECK(kill(atoi(argv[6]),0)==-1 && errno==EPERM);
    CHECK(syscall(SYS_tgkill,atoi(argv[6]),atoi(argv[6]),0)==-1 && errno==EPERM);
    CHECK(syscall(SYS_unshare,0)==-1 && errno==EPERM);
    CHECK(ioctl(0,0x5412,0)==-1 && errno==EPERM); /* TIOCSTI denied. */
    /* A KVM call's number in another request's form (KVM_CHECK_EXTENSION's
       0x03 as a write of eight bytes) is not that call: matched on the
       number alone it was let through to the kernel. */
    CHECK(ioctl(0,0x4008ae03UL,0)==-1 && errno==EPERM);
    puts("PASS process creation, cross-process signals, namespaces and unrelated ioctl denied");
    cpu_set_t affinity;CHECK(sched_getaffinity(0,sizeof(affinity),&affinity)==0);
    if(compiler)CHECK(sched_setaffinity(0,sizeof(affinity),&affinity)==-1 && errno==EPERM);
    else CHECK(sched_setaffinity(0,sizeof(affinity),&affinity)==0);
    CHECK(sched_setaffinity(atoi(argv[6]),sizeof(affinity),&affinity)==-1 && errno==EPERM);
    puts("PASS affinity changes restricted to the VMM calling thread");
    pthread_t thread;void *returned=NULL;
    CHECK(pthread_create(&thread,NULL,thread_main,(void *)123)==0);
    CHECK(pthread_join(thread,&returned)==0 && returned==(void *)123);
    puts("PASS pthread creation and join remain usable");
    CHECK(socket(AF_UNIX,SOCK_STREAM,0)==-1 && errno==EPERM);
    CHECK(socket(AF_INET,SOCK_RAW,IPPROTO_TCP)==-1 && errno==EPERM);
    CHECK(socket(AF_INET,SOCK_DGRAM,0)==-1 && errno==EPERM);
    if(compiler) {
        CHECK(socket(AF_INET,SOCK_STREAM,0)==-1 && errno==EPERM);
        CHECK(memfd_create("compiler",MFD_CLOEXEC)==-1 && errno==EPERM);
        puts("PASS compiler cannot create sockets or memfds");
    } else {
        fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);CHECK(fd>=0);
        struct sockaddr_in address=loopback(atoi(argv[7]));
        CHECK(connect(fd,(struct sockaddr *)&address,sizeof(address))==0);close(fd);
        fd=socket(AF_INET,SOCK_STREAM,0);CHECK(fd>=0);address=loopback(atoi(argv[8]));
        CHECK(connect(fd,(struct sockaddr *)&address,sizeof(address))==-1 && errno==EACCES);close(fd);
        fd=socket(AF_INET,SOCK_STREAM,0);CHECK(fd>=0);address=loopback(0);
        CHECK(bind(fd,(struct sockaddr *)&address,sizeof(address))==-1 && errno==EACCES);close(fd);
        puts("PASS VMM TCP ceiling ports work; other ports and new TCP binds denied");
        fd=memfd_create("fenders-config",MFD_CLOEXEC);CHECK(fd>=0);
        CHECK(write(fd,"test",4)==4);
        char path[80];snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
        int second=open(path,O_RDONLY|O_CLOEXEC);CHECK(second>=0);
        CHECK(read(second,data,4)==4 && !memcmp(data,"test",4));close(second);close(fd);
        puts("PASS native resolver memfd reopening remains usable");
        // Socket calls the launcher does not make: none passes a descriptor
        // or takes a connection it was not handed.
        int ends[2]={0,1};
        fd=socket(AF_INET,SOCK_STREAM,0);CHECK(fd>=0);
        struct msghdr message={0};
        CHECK(sendmsg(fd,&message,0)==-1 && errno==EPERM);
        CHECK(recvmsg(fd,&message,0)==-1 && errno==EPERM);
        CHECK(listen(fd,1)==-1 && errno==EPERM);
        CHECK(syscall(SYS_accept,fd,NULL,NULL)==-1 && errno==EPERM);
        CHECK(syscall(SYS_socketpair,AF_UNIX,SOCK_STREAM,0,ends)==-1 && errno==EPERM);
        close(fd);
        puts("PASS VMM has no sendmsg, recvmsg, listen, accept or socketpair");
    }
    return 0;
}
