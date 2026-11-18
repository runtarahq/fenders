// What the launcher's running filter (running_filter.inc) refuses and what
// it leaves: run without the shim's confinement, which it does not need.
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/kvm.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
static void fail(const char *msg) {fprintf(stderr,"%s: %s\n",msg,strerror(errno));exit(1);}
#include "running_filter.inc"
static void *leaves(void *unused) {(void)unused;pthread_exit((void *)7);}
static void *other_thread(void *ready) {
    // A thread that was already running when the filter went on.
    while(!__atomic_load_n((int *)ready,__ATOMIC_ACQUIRE))usleep(1000);
    void *page=mmap(NULL,4096,PROT_READ|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    return (void *)(intptr_t)(page==MAP_FAILED && errno==EPERM);
}
int main(void) {
    int ready=0;pthread_t earlier;assert(!pthread_create(&earlier,NULL,other_thread,&ready));
    running_filter();
    __atomic_store_n(&ready,1,__ATOMIC_RELEASE);
    void *refused;assert(!pthread_join(earlier,&refused) && refused==(void *)1);
    // No other program, no further filter.
    char *const args[]={"/bin/true",NULL};
    assert(execve(args[0],args,NULL)==-1 && errno==EPERM);
    assert(syscall(SYS_execveat,AT_FDCWD,args[0],args,NULL,0)==-1 && errno==EPERM);
    struct sock_filter allow={BPF_RET|BPF_K,0,0,SECCOMP_RET_ALLOW};struct sock_fprog program={.len=1,.filter=&allow};
    assert(syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program)==-1 && errno==EPERM);
    // No executable memory, made or turned into.
    assert(mmap(NULL,4096,PROT_READ|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0)==MAP_FAILED && errno==EPERM);
    void *page=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(page!=MAP_FAILED);
    assert(mprotect(page,4096,PROT_READ|PROT_EXEC)==-1 && errno==EPERM);
    assert(!mprotect(page,4096,PROT_READ));
    // The calls that make or shape a VM are refused before KVM sees them;
    // the ones that run it reach it (and fail on what is not a VM).
    int null=open("/dev/null",O_RDWR);assert(null>=0);
    unsigned long refused_calls[]={KVM_CREATE_VM,KVM_CREATE_VCPU,KVM_SET_USER_MEMORY_REGION,KVM_SET_TSS_ADDR,
        KVM_SET_CPUID2,KVM_SET_MSRS,KVM_X86_SET_MSR_FILTER,KVM_ENABLE_CAP,KVM_SET_DEVICE_ATTR};
    for(unsigned i=0;i<sizeof(refused_calls)/sizeof(*refused_calls);i++)
        assert(ioctl(null,refused_calls[i],0)==-1 && errno==EPERM);
    unsigned long kept[]={KVM_RUN,KVM_GET_REGS,KVM_SET_REGS,KVM_GET_SREGS,KVM_SET_SREGS,KVM_GET_FPU,KVM_SET_FPU,KVM_GET_XCRS,KVM_SET_XCRS};
    for(unsigned i=0;i<sizeof(kept)/sizeof(*kept);i++)
        assert(ioctl(null,kept[i],0)==-1 && errno!=EPERM);
    // Threads still start and leave: the unwinder was loaded beforehand.
    pthread_t thread;void *left;
    assert(!pthread_create(&thread,NULL,leaves,NULL) && !pthread_join(thread,&left) && left==(void *)7);
    puts("PASS running filter: no exec, no executable memory, no VM or vCPU setup, for every thread; threads still start and leave");
    return 0;
}
