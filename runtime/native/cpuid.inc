// What a guest's CPUID says.
//
// KVM offers every feature it can virtualize. A guest here is one Wasmtime
// with no kernel under it, and it runs in ring 0: whatever CPUID names, it
// may use, and each feature is host kernel code it can then drive. It is
// told of the processor's instructions and nothing of virtualization itself,
// of the hypervisor's paravirtual interfaces or of performance monitoring.
static void restrict_cpuid(struct kvm_cpuid2 *cpuid) {
    for(unsigned i=0;i<cpuid->nent;i++) {
        struct kvm_cpuid_entry2 *e=&cpuid->entries[i];
        switch(e->function) {
        // VMX: no nested virtualization.
        case 1: e->ecx&=~(1u<<5);break;
        // SGX and its launch control.
        case 7: if(e->index==0){e->ebx&=~(1u<<2);e->ecx&=~(1u<<30);}break;
        // Performance monitoring, processor trace, last-branch records.
        case 0xa: case 0x14: case 0x1c: e->eax=e->ebx=e->ecx=e->edx=0;break;
        // SGX enumeration.
        case 0x12: e->eax=e->ebx=e->ecx=e->edx=0;break;
        // KVM's paravirtual features: clocks, async page faults, steal
        // time, PV IPIs and the rest. The signature leaf stays.
        case 0x40000001: e->eax=e->ebx=e->ecx=e->edx=0;break;
        // SVM, and its feature leaf.
        case 0x80000001: e->ecx&=~(1u<<2);break;
        case 0x8000000a: e->eax=e->ebx=e->ecx=e->edx=0;break;
        default: break;
        }
    }
}
