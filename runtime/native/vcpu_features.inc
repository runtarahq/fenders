// What a vCPU is given before it runs: the restricted CPUID (cpuid.inc), and
// KVM told to hold the guest to it. CPUID only says what is there. KVM serves
// its paravirtual hypercalls (kick, IPI, yield) to a ring-0 guest whether the
// feature leaf names them or not, unless it is told to enforce the leaf; the
// leaf is empty here, so enforced, each is refused as unknown.
static void vcpu_features(int kvm,int cpu) {
    struct kvm_enable_cap enforce={.cap=KVM_CAP_ENFORCE_PV_FEATURE_CPUID,.args={1}};
    if(ioctl(kvm,KVM_CHECK_EXTENSION,KVM_CAP_ENFORCE_PV_FEATURE_CPUID)<=0 || ioctl(cpu,KVM_ENABLE_CAP,&enforce))
        fail("KVM cannot hold a guest to its paravirtual feature leaf");
    struct kvm_cpuid2 *cpuid=calloc(1,sizeof(*cpuid)+256*sizeof(struct kvm_cpuid_entry2));
    if(!cpuid)fail("calloc");
    cpuid->nent=256;
    CHECK(ioctl(kvm,KVM_GET_SUPPORTED_CPUID,cpuid));restrict_cpuid(cpuid);CHECK(ioctl(cpu,KVM_SET_CPUID2,cpuid));free(cpuid);
}
