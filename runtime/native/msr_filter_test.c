// A VM under the launcher's MSR filter (msr_filter.inc) faults on every read
// and write of a model-specific register, where a VM as KVM offers it
// performs them: a real KVM guest tries each and reports what happened.
// Needs /dev/kvm.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
static void fail(const char *msg) {fprintf(stderr,"%s: %s\n",msg,strerror(errno));exit(1);}
#define CHECK(x) do {if((x)<0) fail(#x);} while(0)
#include "msr_filter.inc"
// What a guest that touches a model-specific register is told: 1 when the
// access went through, 2 when it faulted. A 16-bit guest whose
// general-protection handler writes 2 to port 0x80, and whose access is
// followed by a write of 1.
static uint32_t msr_access(int kvm,uint32_t msr,int write,int as_launcher) {
    int vm=ioctl(kvm,KVM_CREATE_VM,0);CHECK(vm);
    if(as_launcher)vm_msr_filter(vm);
    uint8_t *mem=mmap(NULL,0x10000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(mem==MAP_FAILED)fail("mmap");
    struct kvm_userspace_memory_region region={.memory_size=0x10000,.userspace_addr=(uintptr_t)mem};
    CHECK(ioctl(vm,KVM_SET_USER_MEMORY_REGION,&region));
    int cpu=ioctl(vm,KVM_CREATE_VCPU,0);CHECK(cpu);
    // The CPUID a guest is given is beside the point here: every access is
    // the filter's to refuse.
    {
        struct kvm_cpuid2 *cpuid=calloc(1,sizeof(*cpuid)+256*sizeof(struct kvm_cpuid_entry2));cpuid->nent=256;
        CHECK(ioctl(kvm,KVM_GET_SUPPORTED_CPUID,cpuid));CHECK(ioctl(cpu,KVM_SET_CPUID2,cpuid));free(cpuid);
    }
    // Vector 13 of the real-mode table: 0000:2000.
    mem[13*4]=0x00;mem[13*4+1]=0x20;mem[13*4+2]=0;mem[13*4+3]=0;
    // mov ecx,msr; xor eax,eax; xor edx,edx; rdmsr|wrmsr; mov eax,1; out 0x80,eax; hlt
    uint8_t code[]={0x66,0xb9,0,0,0,0, 0x66,0x31,0xc0, 0x66,0x31,0xd2, 0x0f,(uint8_t)(write?0x30:0x32),
        0x66,0xb8,1,0,0,0, 0x66,0xe7,0x80, 0xf4};
    memcpy(code+2,&msr,4);memcpy(mem+0x1000,code,sizeof(code));
    // The handler: mov eax,2; out 0x80,eax; hlt
    uint8_t handler[]={0x66,0xb8,2,0,0,0, 0x66,0xe7,0x80, 0xf4};
    memcpy(mem+0x2000,handler,sizeof(handler));
    struct kvm_sregs sregs;CHECK(ioctl(cpu,KVM_GET_SREGS,&sregs));sregs.cs.base=0;sregs.cs.selector=0;CHECK(ioctl(cpu,KVM_SET_SREGS,&sregs));
    struct kvm_regs regs={.rip=0x1000,.rsp=0x8000,.rflags=2};CHECK(ioctl(cpu,KVM_SET_REGS,&regs));
    int size=ioctl(kvm,KVM_GET_VCPU_MMAP_SIZE,0);CHECK(size);
    struct kvm_run *run=mmap(NULL,(size_t)size,PROT_READ|PROT_WRITE,MAP_SHARED,cpu,0);if(run==MAP_FAILED)fail("mmap vcpu");
    uint32_t answer=0;
    for(int steps=0;steps<8 && !answer;steps++) {
        CHECK(ioctl(cpu,KVM_RUN,0));
        if(run->exit_reason==KVM_EXIT_IO && run->io.port==0x80)memcpy(&answer,(uint8_t *)run+run->io.data_offset,4);
        else if(run->exit_reason==KVM_EXIT_HLT)break;
        else {fprintf(stderr,"msr %x: unexpected exit %u\n",msr,run->exit_reason);exit(1);}
    }
    munmap(run,(size_t)size);close(cpu);close(vm);munmap(mem,0x10000);
    return answer;
}
static int msrs(int kvm) {
    // The time-stamp counter, the system-call target the launcher itself
    // sets, the extended-feature register, and KVM's paravirtual clock.
    const struct {uint32_t msr;const char *name;} registers[]={
        {0x10,"time-stamp counter"},{0xc0000082,"system-call target"},{0xc0000080,"extended features"},{0x4b564d01,"KVM system time"}};
    int failed=0;
    for(unsigned i=0;i<sizeof(registers)/sizeof(*registers);i++) {
        for(int write=0;write<2;write++) {
            uint32_t offered=msr_access(kvm,registers[i].msr,write,0),held=msr_access(kvm,registers[i].msr,write,1);
            printf("%s %#x (%s): %s as KVM offers a VM, %s as the launcher sets one up\n",write?"write":"read ",registers[i].msr,registers[i].name,
                offered==1?"done":"faults",held==1?"done":"faults");
            if(held!=2)failed=1;
        }
    }
    // The contrast is real: unfiltered, the time-stamp counter is read.
    if(msr_access(kvm,0x10,0,0)!=1)failed=1;
    if(failed)puts("FAIL a guest's access to a model-specific register went through");
    else puts("PASS a guest's every read and write of a model-specific register faults");
    return failed;
}
int main(void) {
    int kvm=open("/dev/kvm",O_RDWR|O_CLOEXEC);CHECK(kvm);
    return msrs(kvm);
}
