// What the launcher gives up before the guest first runs.
//
// Its confinement (the `vmm` profile its shim applies) has to allow what
// setting a VM up takes: making the VM and its vCPUs, their CPUID, the MSR
// filter, guest memory, and the executable mappings the loader makes for the
// launcher itself. None of that is needed once the guest runs, and all of it
// is what a launcher that had been taken over would want: a second VM
// without the filter, a vCPU told of nested virtualization, code of its own
// to run. Every vCPU the guest may use is made beforehand (threads.inc), and
// then a second filter, which the first allows to be added and nothing can
// take away, refuses:
//  - execve and execveat, and any further filter;
//  - mmap and mprotect asking for PROT_EXEC;
//  - the KVM calls that make or shape a VM or vCPU.
// It is installed for every thread of the process.
static void *unwinder_loaded(void *unused) {(void)unused;pthread_exit(NULL);}
static void running_filter(void) {
    // pthread_exit loads the unwinder's library the first time it is called,
    // which maps it executable: called once now, in a thread made for it.
    pthread_t thread;int error=pthread_create(&thread,NULL,unwinder_loaded,NULL);
    if(error){errno=error;fail("unwinder thread");}pthread_join(thread,NULL);
#define REFUSE BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
#define KVM_REFUSED(request) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(request),0,1),REFUSE
    struct sock_filter code[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_execve,0,1),REFUSE,
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_execveat,0,1),REFUSE,
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_seccomp,0,1),REFUSE,
        // mmap and mprotect: the protection is the third argument of both.
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mmap,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_mprotect,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,PROT_EXEC,0,1),REFUSE,
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_ioctl,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        KVM_REFUSED(KVM_CREATE_VM),KVM_REFUSED(KVM_CREATE_VCPU),KVM_REFUSED(KVM_SET_USER_MEMORY_REGION),
        KVM_REFUSED(KVM_SET_TSS_ADDR),KVM_REFUSED(KVM_SET_CPUID2),KVM_REFUSED(KVM_SET_MSRS),
        KVM_REFUSED(KVM_X86_SET_MSR_FILTER),KVM_REFUSED(KVM_ENABLE_CAP),KVM_REFUSED(KVM_SET_DEVICE_ATTR),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef KVM_REFUSED
#undef REFUSE
    struct sock_fprog program={.len=sizeof(code)/sizeof(*code),.filter=code};
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_TSYNC,&program))
        fail("the launcher's running filter");
}
