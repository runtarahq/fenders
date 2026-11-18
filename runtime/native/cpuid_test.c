// What the launcher leaves out of a guest's CPUID. Compiled and run by
// scripts/verify_network_native.sh on x86-64.
#include <assert.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include "cpuid.inc"

int main(void) {
    struct {unsigned function,index;} leaves[]={{0,0},{1,0},{7,0},{7,1},{0xa,0},{0xd,0},{0x12,0},{0x14,0},
        {0x1c,0},{0x40000000,0},{0x40000001,0},{0x80000001,0},{0x8000000a,0}};
    unsigned count=sizeof(leaves)/sizeof(*leaves);
    struct kvm_cpuid2 *cpuid=calloc(1,sizeof(*cpuid)+count*sizeof(struct kvm_cpuid_entry2));
    assert(cpuid);
    cpuid->nent=count;
    // A host that offers everything.
    for(unsigned i=0;i<count;i++) {
        struct kvm_cpuid_entry2 *e=&cpuid->entries[i];
        e->function=leaves[i].function;e->index=leaves[i].index;
        e->eax=e->ebx=e->ecx=e->edx=~0u;
    }
    restrict_cpuid(cpuid);
    for(unsigned i=0;i<count;i++) {
        struct kvm_cpuid_entry2 *e=&cpuid->entries[i];
        unsigned all=e->eax&e->ebx&e->ecx&e->edx,any=e->eax|e->ebx|e->ecx|e->edx;
        switch(e->function) {
        case 1: assert(!(e->ecx&(1u<<5)) && e->ecx==~(1u<<5) && e->edx==~0u);break;
        case 7:
            if(e->index==0)assert(!(e->ebx&(1u<<2)) && !(e->ecx&(1u<<30)) && e->edx==~0u);
            else assert(all==~0u);
            break;
        case 0xa: case 0x12: case 0x14: case 0x1c: case 0x40000001: case 0x8000000a: assert(!any);break;
        case 0x80000001: assert(!(e->ecx&(1u<<2)) && e->edx==~0u);break;
        // The processor's own leaves, its extended state and the
        // hypervisor's signature are passed on whole.
        default: assert(all==~0u);break;
        }
    }
    free(cpuid);
    puts("PASS guest CPUID names no virtualization, paravirtual interface or performance monitoring");
    return 0;
}
