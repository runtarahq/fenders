// The guest reads and writes no model-specific register: the launcher sets
// the three its system calls need, and those are not the guest's accesses.
// Any it attempts is refused (it faults), rather than being whatever this
// host's KVM would emulate. KVM takes no filter that is empty: one range,
// whose bitmap allows nothing, beside the default.
static void vm_msr_filter(int vm) {
    static uint8_t none_allowed=0;
    struct kvm_msr_filter msrs={.flags=KVM_MSR_FILTER_DEFAULT_DENY,
        .ranges={{.flags=KVM_MSR_FILTER_READ|KVM_MSR_FILTER_WRITE,.nmsrs=1,.base=0,.bitmap=&none_allowed}}};
    CHECK(ioctl(vm,KVM_X86_SET_MSR_FILTER,&msrs));
}
