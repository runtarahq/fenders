#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static atomic_int done;
static void *waiter(void *unused) { (void)unused;while(!atomic_load(&done))usleep(1000);return NULL; }
static void *busy(void *unused) { (void)unused;while(!atomic_load(&done))atomic_signal_fence(memory_order_seq_cst);return NULL; }
int main(int argc,char **argv) {
    if(argc!=4 || getenv("FENDERS_TEST_SECRET"))return 10;
    if(socket(AF_INET,SOCK_STREAM,0)!=-1 || errno!=EPERM)return 11;
    if(fork()!=-1 || errno!=EPERM)return 12;
    int input=open(argv[1],O_RDONLY);char data[9];
    if(input<0 || read(input,data,sizeof(data))!=sizeof(data))return 13;
    close(input);
    if(data[8]=='M') {
        volatile char *memory=malloc(128*1024*1024);
        if(!memory)return 14;
        for(size_t i=0;i<128*1024*1024;i+=4096)memory[i]=1;
        return 15; /* The 64 MiB test cgroup must kill this process first. */
    }
    pthread_t threads[64];int count=0,error=0;
    if(data[8]=='P') {
        for(;count<64;count++) { error=pthread_create(&threads[count],NULL,waiter,NULL);if(error)break; }
        if(error!=EAGAIN || count<1 || count>31)return 16;
    } else if(data[8]=='C') {
        for(;count<2;count++)if(pthread_create(&threads[count],NULL,busy,NULL))return 17;
        struct timespec duration={.tv_sec=2};nanosleep(&duration,NULL);
    } else return 18;
    atomic_store(&done,1);
    for(int i=0;i<count;i++)if(pthread_join(threads[i],NULL))return 19;
    int out=open(argv[2],O_WRONLY|O_TRUNC);
    if(out<0 || write(out,"bounded",7)!=7)return 20;
    close(out);return 0;
}
