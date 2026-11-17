// Minimal shared-address-space threads for the upstream blocking resolver pool.
static void set_syscall_msrs(int cpu) {
    struct {struct kvm_msrs header;struct kvm_msr_entry entries[3];} m={.header.nmsrs=3,.entries={{.index=0xc0000081,.data=8ull<<32},{.index=0xc0000082,.data=0x80000},{.index=0xc0000084,.data=0}}};
    if(ioctl(cpu,KVM_SET_MSRS,&m)!=3)fail("KVM_SET_MSRS");
}
static void setup_cpuid(int cpu) {
    struct kvm_cpuid2 *cpuid=calloc(1,sizeof(*cpuid)+256*sizeof(struct kvm_cpuid_entry2));
    if(!cpuid)fail("calloc");
    cpuid->nent=256;
    CHECK(ioctl(kvm_handle,KVM_GET_SUPPORTED_CPUID,cpuid));restrict_cpuid(cpuid);CHECK(ioctl(cpu,KVM_SET_CPUID2,cpuid));free(cpuid);
}
static void *run_virtual_thread(void *arg) {
    struct virtual_thread *thread=arg;current_thread=thread;
    pthread_mutex_lock(&lifecycle_lock);
    thread->host_thread=pthread_self();thread->active=1;
    pthread_mutex_unlock(&lifecycle_lock);
    for(;;) {
        lifecycle_barrier();
        int rc=ioctl(thread->cpu,KVM_RUN,0);if(rc<0 && errno==EINTR)continue;CHECK(rc);
        struct kvm_regs regs;CHECK(ioctl(thread->cpu,KVM_GET_REGS,&regs));
        struct kvm_run *run=thread->run;
        if(run->exit_reason==KVM_EXIT_IO && run->io.direction==KVM_EXIT_IO_OUT && run->io.port==0x510 && run->io.size==4 && run->io.count==1) {
            regs.rax=syscall_guest(thread->cpu,&regs);CHECK(ioctl(thread->cpu,KVM_SET_REGS,&regs));continue;
        }
        fprintf(DIAGNOSTICS,"unexpected KVM exit %u tid=%u rip=%llx\n",run->exit_reason,thread->tid,(unsigned long long)regs.rip);exit(1);
    }
}
static long clone_virtual_thread(int parent,struct kvm_regs *regs,uint64_t flags,uint64_t stack,uint64_t ptid,uint64_t ctid,uint64_t tls) {
    unsigned long required=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS;
    if((flags&required)!=required || (flags&~(required|CLONE_PARENT_SETTID|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID|CLONE_DETACHED)))return -ENOTSUP;
    if(stack<8)return -EINVAL;
    ptr(stack-8,8);ptr(tls,1);
    if(flags&CLONE_PARENT_SETTID)ptr(ptid,4);
    if(flags&(CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID))ptr(ctid,4);
    pthread_mutex_lock(&clone_lock);
    unsigned index=thread_count;if(index>=8){pthread_mutex_unlock(&clone_lock);return -EAGAIN;}
    struct virtual_thread *thread=&virtual_threads[index];thread->tid=index+1;
    thread->cpu=ioctl(vm_handle,KVM_CREATE_VCPU,index);
    // The clock page holds for vCPU 0's TSC: every vCPU keeps its offset.
    if(thread->cpu>=0 && vdso_loaded) {
        struct kvm_device_attr attr={.group=KVM_VCPU_TSC_CTRL,.attr=KVM_VCPU_TSC_OFFSET,.addr=(uint64_t)(uintptr_t)&tsc_offset};
        if(!tsc_offset_known || ioctl(thread->cpu,KVM_SET_DEVICE_ATTR,&attr))
            __atomic_store_n(&((struct fenders_clock *)(mem+FENDERS_CLOCK_PAGE))->valid,0u,__ATOMIC_RELEASE);
    }
    if(thread->cpu<0){pthread_mutex_unlock(&clone_lock);return -errno;}
    setup_cpuid(thread->cpu);
    struct kvm_sregs s;CHECK(ioctl(parent,KVM_GET_SREGS,&s));s.fs.base=tls;CHECK(ioctl(thread->cpu,KVM_SET_SREGS,&s));
    struct kvm_xcrs xcr;CHECK(ioctl(parent,KVM_GET_XCRS,&xcr));CHECK(ioctl(thread->cpu,KVM_SET_XCRS,&xcr));
    struct kvm_fpu fpu;CHECK(ioctl(parent,KVM_GET_FPU,&fpu));CHECK(ioctl(thread->cpu,KVM_SET_FPU,&fpu));
    set_syscall_msrs(thread->cpu);
    // The parent has a pending KVM I/O completion. A fresh vCPU does not:
    // resume after the OUT instruction in the fixed syscall entry stub.
    struct kvm_regs child=*regs;child.rax=0;child.rsp=stack-8;child.rip=0x80006;
    *(uint64_t *)ptr(stack-8,8)=*(uint64_t *)ptr(regs->rsp,8);
    CHECK(ioctl(thread->cpu,KVM_SET_REGS,&child));
    thread->run=mmap(NULL,vcpu_map_size,PROT_READ|PROT_WRITE,MAP_SHARED,thread->cpu,0);if(thread->run==MAP_FAILED)fail("mmap child vcpu");
    thread->clear_tid=(flags&CLONE_CHILD_CLEARTID)?ctid:0;
    if(flags&CLONE_PARENT_SETTID)*(uint32_t *)ptr(ptid,4)=thread->tid;
    if(flags&CLONE_CHILD_SETTID)*(uint32_t *)ptr(ctid,4)=thread->tid;
    ++thread_count;
    pthread_t worker;int e=pthread_create(&worker,NULL,run_virtual_thread,thread);
    if(e){fprintf(DIAGNOSTICS,"pthread_create: %s\n",strerror(e));exit(1);}pthread_detach(worker);
    pthread_mutex_unlock(&clone_lock);return thread->tid;
}
static void exit_virtual_thread(void) {
    if(current_thread->clear_tid) {
        uint32_t *tid=ptr(current_thread->clear_tid,4);__atomic_store_n(tid,0,__ATOMIC_RELEASE);
        syscall(SYS_futex,tid,FUTEX_WAKE,INT_MAX,NULL,NULL,0);
        syscall(SYS_futex,tid,FUTEX_WAKE|FUTEX_PRIVATE_FLAG,INT_MAX,NULL,NULL,0);
    }
    pthread_mutex_lock(&lifecycle_lock);current_thread->active=0;
    pthread_cond_broadcast(&lifecycle_changed);pthread_mutex_unlock(&lifecycle_lock);
    close(current_thread->cpu);munmap(current_thread->run,vcpu_map_size);pthread_exit(NULL);
}
