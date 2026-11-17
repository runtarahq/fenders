// A vCPU set up as the launcher sets one up (vcpu_features.inc) is refused
// KVM's paravirtual hypercalls: a real KVM guest asks for each and reports
// what it was told. Needs /dev/kvm.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
static void fail(const char *msg) {fprintf(stderr,"%s: %s\n",msg,strerror(errno));exit(1);}
#define CHECK(x) do {if((x)<0) fail(#x);} while(0)
#include "cpuid.inc"
#include "vcpu_features.inc"
// What the guest was told for hypercall `number`: a 16-bit guest that loads
// the number, makes the call, and writes the answer to port 0x80.
static uint32_t ask(int kvm,uint32_t number,int as_launcher) {
    int vm=ioctl(kvm,KVM_CREATE_VM,0);CHECK(vm);
    uint8_t *mem=mmap(NULL,0x10000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(mem==MAP_FAILED)fail("mmap");
    struct kvm_userspace_memory_region region={.memory_size=0x10000,.userspace_addr=(uintptr_t)mem};
    CHECK(ioctl(vm,KVM_SET_USER_MEMORY_REGION,&region));
    int cpu=ioctl(vm,KVM_CREATE_VCPU,0);CHECK(cpu);
    if(as_launcher)vcpu_features(kvm,cpu);
    else {
        // As KVM offers it, for contrast: every feature, nothing enforced.
        struct kvm_cpuid2 *cpuid=calloc(1,sizeof(*cpuid)+256*sizeof(struct kvm_cpuid_entry2));cpuid->nent=256;
        CHECK(ioctl(kvm,KVM_GET_SUPPORTED_CPUID,cpuid));CHECK(ioctl(cpu,KVM_SET_CPUID2,cpuid));free(cpuid);
    }
    // mov eax,number; vmcall; out 0x80,eax; hlt. KVM rewrites the call to
    // the host processor's own instruction where that differs.
    uint8_t code[]={0x66,0xb8,0,0,0,0, 0x0f,0x01,0xc1, 0x66,0xe7,0x80, 0xf4};
    memcpy(code+2,&number,4);memcpy(mem+0x1000,code,sizeof(code));
    struct kvm_sregs sregs;CHECK(ioctl(cpu,KVM_GET_SREGS,&sregs));sregs.cs.base=0;sregs.cs.selector=0;CHECK(ioctl(cpu,KVM_SET_SREGS,&sregs));
    struct kvm_regs regs={.rip=0x1000,.rflags=2};CHECK(ioctl(cpu,KVM_SET_REGS,&regs));
    int size=ioctl(kvm,KVM_GET_VCPU_MMAP_SIZE,0);CHECK(size);
    struct kvm_run *run=mmap(NULL,(size_t)size,PROT_READ|PROT_WRITE,MAP_SHARED,cpu,0);if(run==MAP_FAILED)fail("mmap vcpu");
    uint32_t answer=0;int answered=0;
    for(int steps=0;steps<8;steps++) {
        CHECK(ioctl(cpu,KVM_RUN,0));
        if(run->exit_reason==KVM_EXIT_IO && run->io.port==0x80){memcpy(&answer,(uint8_t *)run+run->io.data_offset,4);answered=1;continue;}
        if(run->exit_reason==KVM_EXIT_HLT)break;
        fprintf(stderr,"hypercall %u: unexpected exit %u\n",number,run->exit_reason);exit(1);
    }
    if(!answered){fprintf(stderr,"hypercall %u: no answer\n",number);exit(1);}
    munmap(run,(size_t)size);close(cpu);close(vm);munmap(mem,0x10000);
    return answer;
}
int main(void) {
    int kvm=open("/dev/kvm",O_RDWR|O_CLOEXEC);CHECK(kvm);
    const struct {uint32_t number;const char *name;} calls[]={
        {KVM_HC_KICK_CPU,"kick a vCPU"},{KVM_HC_SEND_IPI,"send IPIs"},{KVM_HC_SCHED_YIELD,"yield to a vCPU"}};
    int failed=0;
    for(unsigned i=0;i<sizeof(calls)/sizeof(*calls);i++) {
        int32_t offered=(int32_t)ask(kvm,calls[i].number,0),held=(int32_t)ask(kvm,calls[i].number,1);
        printf("hypercall %u (%s): %d as KVM offers a vCPU, %d as the launcher sets one up\n",calls[i].number,calls[i].name,offered,held);
        if(held!=-KVM_ENOSYS)failed=1;
    }
    if(failed){puts("FAIL a paravirtual hypercall was served");return 1;}
    puts("PASS a guest is refused KVM's paravirtual hypercalls as unknown");
    return 0;
}
