    int kvm = open("/dev/kvm", O_RDWR|O_CLOEXEC); CHECK(kvm);
    if (ioctl(kvm, KVM_GET_API_VERSION, 0) != KVM_API_VERSION) fail("KVM version");
    if (ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_IMMEDIATE_EXIT) <= 0) {
        fprintf(DIAGNOSTICS,"KVM immediate-exit support is required\n");exit(2);
    }
    int vm = ioctl(kvm, KVM_CREATE_VM, 0); CHECK(vm);
    CHECK(ioctl(vm, KVM_SET_TSS_ADDR, 0xfffbd000));
    struct kvm_userspace_memory_region region = {.slot=0,.guest_phys_addr=0,.memory_size=ram,.userspace_addr=(uintptr_t)mem};
    CHECK(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region));
    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0); CHECK(cpu);
    struct kvm_cpuid2 *cpuid = calloc(1, sizeof(*cpuid)+256*sizeof(struct kvm_cpuid_entry2));
    if (!cpuid) fail("calloc");
    cpuid->nent = 256;
    CHECK(ioctl(kvm,KVM_GET_SUPPORTED_CPUID,cpuid)); CHECK(ioctl(cpu,KVM_SET_CPUID2,cpuid)); free(cpuid);
    struct kvm_sregs s; CHECK(ioctl(cpu,KVM_GET_SREGS,&s));
    s.cs=(struct kvm_segment){.base=0,.limit=~0u,.selector=8,.type=11,.present=1,.s=1,.l=1,.g=1};
    s.ds=s.es=s.fs=s.gs=s.ss=(struct kvm_segment){.base=0,.limit=~0u,.selector=16,.type=3,.present=1,.s=1,.db=1,.g=1};
    s.cr3=0x1000; s.cr4=(1<<5)|(1<<9)|(1<<10)|(1<<18);
    s.cr0=(1ul<<31)|(1<<16)|(1<<5)|(1<<4)|(1<<1)|1;
    s.efer=1|(1<<8)|(1<<10)|(1<<11);
    CHECK(ioctl(cpu,KVM_SET_SREGS,&s));
    struct kvm_xcrs xcr={.nr_xcrs=1,.xcrs={{.xcr=0,.value=7}}}; CHECK(ioctl(cpu,KVM_SET_XCRS,&xcr));
    struct kvm_fpu fpu={.fcw=0x37f,.mxcsr=0x1f80}; CHECK(ioctl(cpu,KVM_SET_FPU,&fpu));
    struct kvm_regs regs={.rip=entry,.rsp=initial_sp,.rflags=2}; CHECK(ioctl(cpu,KVM_SET_REGS,&regs));
    int run_size=ioctl(kvm,KVM_GET_VCPU_MMAP_SIZE,0); CHECK(run_size);
    struct kvm_run *run=mmap(NULL,run_size,PROT_READ|PROT_WRITE,MAP_SHARED,cpu,0);
    if (run==MAP_FAILED) fail("mmap vcpu");
