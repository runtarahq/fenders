// Kernel-free native ABI platform for upstream Wasmtime/Tokio. Linux host only.
#define _GNU_SOURCE
#include <linux/kvm.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/random.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sched.h>
#include <limits.h>
#include <x86intrin.h>
#include "vdso_clock.h"
#include <stdatomic.h>
#include <sys/resource.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <sys/un.h>

// Guest RAM is chosen per launch; one page directory maps at most 1 GiB in 2 MiB entries.
#define MAX_RAM (1024u*1024*1024)
#define STACK_RESERVE (2u*1024*1024)
#define NX (1ull<<63)
#define PAGE 4096u
static uint8_t *mem;
static uint64_t ram=32u*1024*1024,page_tables;
static uint8_t used[MAX_RAM/PAGE];
// Guest pages backed by a copy-on-write mapping of the component file.
static uint8_t file_backed[MAX_RAM/PAGE];
static dev_t component_dev;static ino_t component_ino;static int component_known;
static uint64_t image_end,elf_phdr,elf_phnum;
static _Atomic unsigned long syscall_count;
static const char *component_path;
static int component_fd=-1;
static int vm_handle,kvm_handle,vcpu_map_size;
static pthread_mutex_t allocator_lock=PTHREAD_MUTEX_INITIALIZER,clone_lock=PTHREAD_MUTEX_INITIALIZER;
struct virtual_thread {int cpu;struct kvm_run *run;unsigned tid;uint64_t clear_tid;pthread_t host_thread;int active,parked;};
static struct virtual_thread virtual_threads[8];
static _Atomic unsigned thread_count=1;
static _Thread_local struct virtual_thread *current_thread;
static long clone_virtual_thread(int,struct kvm_regs *,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
static void exit_virtual_thread(void);
static void *run_virtual_thread(void *);
// One thread ends the process. A guest's threads, the control thread and any
// failed check may all decide to at once; `exit` run by two of them at a time
// flushes streams and runs the meter's last line under each other. The first
// goes on to exit; the rest wait to be ended with it.
static _Atomic int exiting;
__attribute__((noreturn)) static void exit_once(int code) {
    if(atomic_exchange(&exiting,1))for(;;)pause();
    (exit)(code);
}
#define exit(code) exit_once(code)
#include "diagnostics.inc"
static void fail(const char *msg) {fprintf(DIAGNOSTICS,"%s: %s\n",msg,strerror(errno));exit(1);}
#define CHECK(x) do {if((x)<0) fail(#x);} while(0)
static void network_usage(uint64_t *,int *);
static const char *network_budget_command(char *);
static void network_budget_status(char *,size_t);
#include "descriptors.inc"
static struct sockaddr_in tcp_allow[32],dns_server;
static unsigned tcp_allow_count;
#include "lifecycle.inc"
static void timeout_handler(int s) {(void)s;_exit(124);}
// The guest's vDSO (vdso.c), built beside this file, and its clock page: the
// guest reads the clocks the TSC can answer without a VM exit. Every vCPU
// keeps vCPU 0's TSC offset (threads.inc), or the page is marked invalid and
// every read takes the syscall.
__asm__(".pushsection .rodata\n.balign 16\n.globl vdso_image\n.hidden vdso_image\nvdso_image:\n.incbin \"vdso.so\"\n.globl vdso_image_end\n.hidden vdso_image_end\nvdso_image_end:\n.popsection");
extern const unsigned char vdso_image[],vdso_image_end[];
static void permissions(uint64_t,size_t,uint64_t);
static int vdso_loaded,tsc_offset_known;static uint64_t tsc_offset;
// An invariant TSC (CPUID 0x80000007 EDX bit 8) ticks at one rate in every
// power state, so the clock page holds for the whole run. Read from CPUID:
// the confined VMM cannot read /proc.
static int invariant_tsc(void) {
    unsigned a,b,c,d;
    return __get_cpuid(0x80000007,&a,&b,&c,&d) && (d&(1u<<8));
}
// Copies the vDSO's loadable segments to their addresses at FENDERS_VDSO_BASE.
static int load_vdso(void) {
    size_t size=(size_t)(vdso_image_end-vdso_image);
    const Elf64_Ehdr *e=(const void *)vdso_image;
    if(size<sizeof(*e) || memcmp(e->e_ident,ELFMAG,SELFMAG) || e->e_phoff>size || e->e_phnum>(size-e->e_phoff)/sizeof(Elf64_Phdr))return 0;
    for(unsigned i=0;i<e->e_phnum;i++) {
        const Elf64_Phdr *p=(const void *)(vdso_image+e->e_phoff+i*sizeof(Elf64_Phdr));
        if(p->p_type!=PT_LOAD)continue;
        if(p->p_offset>size || p->p_filesz>size-p->p_offset || p->p_filesz>p->p_memsz || p->p_vaddr+p->p_memsz>FENDERS_VDSO_PAGES*PAGE)return 0;
        memcpy(mem+FENDERS_VDSO_BASE+p->p_vaddr,vdso_image+p->p_offset,p->p_filesz);
    }
    permissions(FENDERS_VDSO_BASE,FENDERS_VDSO_PAGES*PAGE,1);
    permissions(FENDERS_CLOCK_PAGE,PAGE,1|NX);
    return 1;
}
// Fills the clock page from vCPU `cpu`'s TSC: its frequency and offset, and
// the host clocks read with the host TSC around them.
static void calibrate_clock(int cpu) {
    struct fenders_clock *page=(void *)(mem+FENDERS_CLOCK_PAGE);
    page->valid=0;
    long khz=ioctl(cpu,KVM_GET_TSC_KHZ,0);if(khz<=0)return;
    struct kvm_device_attr attr={.group=KVM_VCPU_TSC_CTRL,.attr=KVM_VCPU_TSC_OFFSET,.addr=(uint64_t)(uintptr_t)&tsc_offset};
    if(ioctl(cpu,KVM_GET_DEVICE_ATTR,&attr))return;
    tsc_offset_known=1;
    const clockid_t clocks[]={CLOCK_REALTIME,CLOCK_MONOTONIC,CLOCK_MONOTONIC_RAW,CLOCK_BOOTTIME};
    struct timespec now[4];
    uint64_t before=__rdtsc();
    for(unsigned i=0;i<4;i++)if(clock_gettime(clocks[i],&now[i]))return;
    uint64_t after=__rdtsc();
    page->tsc_ref=before+(after-before)/2+tsc_offset;
    page->shift=32;page->mult=((uint64_t)1000000<<32)/(uint64_t)khz;
    uint32_t valid=0;
    for(unsigned i=0;i<4;i++) {
        if((unsigned)clocks[i]>=FENDERS_CLOCKS)continue;
        page->base_ns[clocks[i]]=(int64_t)now[i].tv_sec*1000000000+now[i].tv_nsec;valid|=1u<<clocks[i];
    }
    __atomic_store_n(&page->valid,valid,__ATOMIC_RELEASE);
}
static void *ptr(uint64_t address,size_t size) {
    if(address>ram || size>ram-address) {fprintf(DIAGNOSTICS,"invalid guest pointer\n");exit(1);}
    return mem+address;
}
static void reserve_pages(uint64_t address,size_t size) {
    ptr(address,size);
    for(uint64_t p=address/PAGE;p<(address+size+PAGE-1)/PAGE;p++) used[p]=1;
}
// Gives pages above the image back zeroed: the host drops them, and the
// next touch faults in a zero page. Every free guest page is zero, so
// allocation writes nothing. Guest memory above the image is anonymous.
static void zero_pages(uint64_t address,size_t size) {
    ptr(address,size);
    if(!size)return;
    int mapped=0;
    for(uint64_t p=address/PAGE;p<(address+size+PAGE-1)/PAGE;p++)if(file_backed[p]){mapped=1;file_backed[p]=0;}
    // A dropped file page would read back the file: replace such a range
    // with fresh anonymous memory.
    if(mapped){if(mmap(mem+address,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==MAP_FAILED)fail("mmap anonymous");}
    else if(madvise(mem+address,size,MADV_DONTNEED))fail("madvise");
}
// A guest mmap of the component: its file pages are mapped copy-on-write at
// the guest's address instead of read into it, so they come from the page
// cache the VMs of that artifact share and only written pages are copied.
// Bytes past the end of the file stay zero. 0 when the mapping is not that.
static int map_component(uint64_t address,size_t size,int fd,uint64_t offset) {
    struct stat st;
    if(!component_known || offset%PAGE || fstat(fd,&st) || st.st_dev!=component_dev || st.st_ino!=component_ino)return 0;
    if(offset>=(uint64_t)st.st_size)return 1;
    uint64_t length=(uint64_t)st.st_size-offset;if(length>size)length=size;
    length=(length+PAGE-1)&~(uint64_t)(PAGE-1);
    if(mmap(mem+address,length,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED,fd,(off_t)offset)==MAP_FAILED)return 0;
    for(uint64_t p=address/PAGE;p<(address+length)/PAGE;p++)file_backed[p]=1;
    return 1;
}
#include "elf.inc"
// No page below this one is free (above the image): first-fit allocation
// starts here instead of rescanning the used pages below it every time.
static unsigned first_free;
static void freed(uint64_t page) {if(page<first_free)first_free=(unsigned)page;}
static uint64_t allocate_unlocked(size_t size,int prot) {
    if(!size || size>ram) return 0;
    unsigned pages=(size+PAGE-1)/PAGE,start=(image_end+PAGE-1)/PAGE;
    if(first_free<start)first_free=start;
    while(first_free<page_tables/PAGE && used[first_free])first_free++;
    for(unsigned i=first_free;i+pages<=page_tables/PAGE;i++) {
        unsigned j=0;while(j<pages && !used[i+j]) j++;
        if(j!=pages) {i+=j;continue;}
        uint64_t addr=(uint64_t)i*PAGE;
        // Free pages are zero (see release_pages), so a new mapping is not
        // written here: pages the guest never touches are never faulted in.
        reserve_pages(addr,(size_t)pages*PAGE);
        permissions(addr,(size_t)pages*PAGE,((prot&PROT_READ)?1:0)|((prot&PROT_WRITE)?2:0)|((prot&PROT_EXEC)?0:NX));
        return addr;
    }
    return 0;
}
static uint64_t allocate(size_t size,int prot) {
    pthread_mutex_lock(&allocator_lock);uint64_t address=allocate_unlocked(size,prot);pthread_mutex_unlock(&allocator_lock);return address;
}
// mremap over the anonymous area: shrink in place, grow in place when the
// following pages are free, else move (MREMAP_MAYMOVE) by copying. Growing in
// place keeps a growing allocation from holding its old and new copies at once.
static long remap_unlocked(uint64_t old,uint64_t old_size,uint64_t new_size,uint64_t flags) {
    // Sizes over the guest's memory are refused before they are rounded up
    // to pages, where one near 2^64 would wrap to none.
    if(old%PAGE || !old_size || !new_size || old_size>ram || new_size>ram || (flags&~(uint64_t)MREMAP_MAYMOVE))return -EINVAL;
    uint64_t first=old/PAGE,old_pages=(old_size+PAGE-1)/PAGE,new_pages=(new_size+PAGE-1)/PAGE,limit=page_tables/PAGE;
    if(old<image_end || first>=limit || old_pages>limit-first || new_pages>ram/PAGE)return -EINVAL;
    for(uint64_t p=first;p<first+old_pages;p++)if(!used[p])return -EFAULT;
    uint64_t *pte=(void *)(mem+page_tables),flags_of=pte[first]&(3|NX);
    if(new_pages<=old_pages) {
        zero_pages((first+new_pages)*PAGE,(old_pages-new_pages)*PAGE);
        for(uint64_t p=first+new_pages;p<first+old_pages;p++){used[p]=0;freed(p);}
        permissions((first+new_pages)*PAGE,(old_pages-new_pages)*PAGE,NX);return (long)old;
    }
    uint64_t extra=new_pages-old_pages,end=first+old_pages,free_after=0;
    while(free_after<extra && end+free_after<limit && !used[end+free_after])free_after++;
    if(free_after==extra) {
        reserve_pages(end*PAGE,extra*PAGE);
        permissions(end*PAGE,extra*PAGE,flags_of);return (long)old;
    }
    if(!(flags&MREMAP_MAYMOVE))return -ENOMEM;
    uint64_t moved=allocate_unlocked(new_pages*PAGE,PROT_READ);if(!moved)return -ENOMEM;
    permissions(moved,new_pages*PAGE,flags_of);
    memcpy(mem+moved,mem+old,old_pages*PAGE);
    zero_pages(old,old_pages*PAGE);
    for(uint64_t p=first;p<end;p++){used[p]=0;freed(p);}
    permissions(old,old_pages*PAGE,NX);return (long)moved;
}
static long remap(uint64_t old,uint64_t old_size,uint64_t new_size,uint64_t flags) {
    pthread_mutex_lock(&allocator_lock);long address=remap_unlocked(old,old_size,new_size,flags);pthread_mutex_unlock(&allocator_lock);return address;
}
static long result(long r) {return r<0?-errno:r;}
// A warm launch (FENDERS_HOLD_FD, a pipe from its shim) boots its guest and
// lets it load its component, then holds it: the guest opens /fenders/go,
// which returns only when the shim closes the pipe for the one run it is
// claimed for, with what the shim wrote (at most 4 KiB, none yet). Without
// the pipe /fenders/go does not exist, and a guest runs at once.
static int hold_fd=-1;
static void hold_start(void) {
    const char *text=getenv("FENDERS_HOLD_FD");if(!text)return;
    char *end;errno=0;long fd=strtol(text,&end,10);struct stat info;
    if(errno || !*text || *end || fd<3 || fd>INT_MAX || fstat((int)fd,&info) || !S_ISFIFO(info.st_mode)) {
        fprintf(DIAGNOSTICS,"invalid inherited hold pipe\n");exit(2);
    }
    hold_fd=(int)fd;
}
// One opener takes the pipe: two guest threads opening it at once would
// otherwise both read it and both close its descriptor, the second closing
// whatever another thread had been given that number since.
static pthread_mutex_t hold_lock=PTHREAD_MUTEX_INITIALIZER;
static int held_go(void) {
    pthread_mutex_lock(&hold_lock);int held=hold_fd;hold_fd=-1;pthread_mutex_unlock(&hold_lock);
    if(held<0)return -ENOENT;
    char data[4096];size_t len=0;
    for(;;) {
        ssize_t n=read(held,data+len,sizeof(data)-len);
        if(n<0 && errno==EINTR)continue;
        if(n<0){int error=errno;close(held);return -error;}
        if(n==0)break;
        len+=(size_t)n;if(len==sizeof(data)){close(held);return -E2BIG;}
    }
    close(held);
    int fd=memfd_create("fenders-go",MFD_CLOEXEC);if(fd<0)return -errno;
    if(len && write(fd,data,len)!=(ssize_t)len){close(fd);return -EIO;}
    char path[64];snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    int read_only=open(path,O_RDONLY|O_CLOEXEC);close(fd);return guest_fd(read_only);
}
static int virtual_config_file(const char *name) {
    const char *data;char resolver[128],ip[INET_ADDRSTRLEN];
    if(!strcmp(name,"/etc/hosts"))data="127.0.0.1 localhost\n";
    else if(!strcmp(name,"/etc/resolv.conf")) {
        if(!inet_ntop(AF_INET,&dns_server.sin_addr,ip,sizeof(ip)))return -EIO;
        snprintf(resolver,sizeof(resolver),"nameserver %s\noptions attempts:1 timeout:1\n",ip);data=resolver;
    }
    else return -ENOENT;
    int fd=memfd_create("fenders-config",MFD_CLOEXEC);if(fd<0)return -errno;
    size_t len=strlen(data);if(write(fd,data,len)!=(ssize_t)len){close(fd);return -EIO;}
    char path[64];snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    int read_only=open(path,O_RDONLY|O_CLOEXEC);close(fd);return guest_fd(read_only);
}
#include "filesystem.inc"
#include "network.inc"
#include "guest_args.inc"
static long syscall_guest_inner(int cpu,struct kvm_regs *r) {
    uint64_t n=r->rax,a=r->rdi,b=r->rsi,c=*(uint64_t *)ptr(r->rsp,8),d=r->r10;
    ++syscall_count;
    if(getenv("FENDERS_TRACE")) fprintf(DIAGNOSTICS,"syscall %llu (%llx,%llx,%llx,%llx)\n",(unsigned long long)n,(unsigned long long)a,(unsigned long long)b,(unsigned long long)c,(unsigned long long)d);
    switch(n) {
    // Native runtime lifecycle hook. Not exported as an application capability.
    case 500: if(a>1)return -EINVAL;atomic_store(&application_idle,(int)a);return 0;
    case 0: if(a==0)return 0;return result(read(host_fd(a),ptr(b,c),c));
    case 1: if(a==1 || a==2) return result(write(a,ptr(b,c),c));return network_write(a,ptr(b,c),c);
    case 2: case 257: {
        uint64_t address=n==2?a:b,flags=n==2?b:c;
        char name[PATH_MAX];int error=guest_path(address,name);if(error)return error;
        if(!strcmp(name,"/fenders/listener")) {
            if(ingress_fd<0 || flags&O_ACCMODE)return -EACCES;
            return guest_fd(dup(ingress_fd));
        }
        if(!strcmp(name,"/fenders/go")) {
            if((flags&O_ACCMODE)!=O_RDONLY || (flags&(O_CREAT|O_TRUNC)))return -EACCES;
            return held_go();
        }
        if(!strcmp(name,"/fenders/host-origin")) {
            if(host_origin_fd<0 || flags&O_ACCMODE)return -EACCES;
            return guest_fd(dup(host_origin_fd));
        }
        if(!strcmp(name,"/component.cwasm") || !strcmp(name,"/etc/hosts") || !strcmp(name,"/etc/resolv.conf")) {
            if((flags&O_ACCMODE)!=O_RDONLY || (flags&(O_CREAT|O_TRUNC)))return -EACCES;
            if(strcmp(name,"/component.cwasm"))return virtual_config_file(name);
            if(!component_path)return -ENOENT;
            // An inherited component is shared: each open reads it from the start.
            if(component_fd>=0){if(lseek(component_fd,0,SEEK_SET))return -errno;return guest_fd(dup(component_fd));}
            return guest_fd(open(component_path,O_RDONLY|O_CLOEXEC));
        }
        return fs_open(n==2?(uint64_t)AT_FDCWD:a,name,flags,n==2?c:d,0);
    }
    case 3: {
        if(a>=64)return -EBADF;
        pthread_mutex_lock(&fd_lock);struct descriptor *desc=host_fds[a];int found=desc!=NULL;host_fds[a]=NULL;
        if(desc)release_descriptor(desc);
        pthread_mutex_unlock(&fd_lock);return found?0:-EBADF;
    }
    case 5: {
        struct stat st={0};st.st_mode=S_IFCHR|0600;st.st_blksize=4096;
        if(a>2 && fstat(host_fd(a),&st)) return -errno;
        memcpy(ptr(b,sizeof(st)),&st,sizeof(st));return 0;
    }
    case 7: {
        if(b>64)return -EINVAL;
        struct pollfd *guest=ptr(a,b*sizeof(struct pollfd)),fds[64];
        memcpy(fds,guest,b*sizeof(*fds));
        // From the copy alone: the guest's own array can change under
        // another of its threads between a check and a use.
        for(unsigned i=0;i<b;i++){int wanted=fds[i].fd;fds[i].fd=wanted>=0 && wanted<=2?wanted:host_fd((uint64_t)wanted);}
        int rc=poll(fds,b,(int)c);
        if(rc<0)return -errno;
        for(unsigned i=0;i<b;i++)guest[i].revents=fds[i].revents;
        return rc;
    }
    case 8: return result(lseek(host_fd(a),(off_t)b,c));
    case 9: {
        if((d&MAP_FIXED) || a)return -ENOTSUP;
        if((c&(PROT_WRITE|PROT_EXEC))==(PROT_WRITE|PROT_EXEC))return -EACCES;
        if(!(d&MAP_ANONYMOUS) && host_fd(r->r8)<0)return -EBADF;
        uint64_t address=allocate(b,c);if(!address)return -ENOMEM;
        if(!(d&MAP_ANONYMOUS)) {
            int fd=host_fd(r->r8);
            pthread_mutex_lock(&allocator_lock);int mapped=map_component(address,b,fd,r->r9);pthread_mutex_unlock(&allocator_lock);
            if(!mapped) {
                ssize_t size=pread(fd,ptr(address,b),b,r->r9);
                if(size<0)return -errno;
            }
        }
        return address;
    }
    case 17: return result(pread(host_fd(a),ptr(b,c),c,d));
    case 18: return result(pwrite(host_fd(a),ptr(b,c),c,d));
    case 19: case 295: case 296: {
        if(c>64)return -EINVAL;
        struct iovec v[64];memcpy(v,ptr(b,c*sizeof(*v)),c*sizeof(*v));
        for(unsigned i=0;i<c;i++)v[i].iov_base=ptr((uint64_t)v[i].iov_base,v[i].iov_len);
        int fd=host_fd(a);off_t offset=(d&0xffffffffull)|(r->r8<<32);
        if(n==19)return result(readv(fd,v,c));
        return result(n==295?preadv(fd,v,c,offset):pwritev(fd,v,c,offset));
    }
    case 74: return result(fsync(host_fd(a)));
    case 75: return result(fdatasync(host_fd(a)));
    case 77: {int fd=fs_writable_fd(a);if(fd<0)return fd;return result(ftruncate(fd,b));}
    case 217: {struct descriptor *desc=lease_descriptor(a);if(!desc || desc->mount<0)return -EBADF;return result(syscall(SYS_getdents64,desc->fd,ptr(b,c),c));}
    case 221: return result(syscall(SYS_fadvise64,host_fd(a),b,c,d));
    case 258: case 262: case 263: case 264: case 265: case 266: case 267: case 280: case 316: case 332: case 437:
        return fs_syscall(n,a,b,c,d,r->r8,r->r9);
    case 10:
        if(a%PAGE || b>ram || a>ram-b)return -EINVAL;
        if((c&(PROT_WRITE|PROT_EXEC))==(PROT_WRITE|PROT_EXEC))return -EACCES;
        permissions(a,b,((c&PROT_READ)?1:0)|((c&PROT_WRITE)?2:0)|((c&PROT_EXEC)?0:NX));return 0;
    case 11:
        if(a%PAGE || a<image_end || a>=page_tables || b>page_tables-a)return -EINVAL;
        pthread_mutex_lock(&allocator_lock);
        zero_pages(a,(a+b+PAGE-1)/PAGE*PAGE-a);
        for(uint64_t p=a/PAGE;p<(a+b+PAGE-1)/PAGE;p++){used[p]=0;freed(p);}
        permissions(a,b,NX);pthread_mutex_unlock(&allocator_lock);return 0;
    case 25: return remap(a,b,c,d);
    case 12: return (image_end+PAGE-1)&~(uint64_t)(PAGE-1); // No growable brk; libc uses mmap.
    case 13: if(d!=8)return -EINVAL;if(c)memset(ptr(c,32),0,32);return 0;
    case 14: if(d!=8)return -EINVAL;if(c)memset(ptr(c,8),0,8);return 0;
    case 16: {
        if(b!=FIONBIO)return -ENOTTY;
        int fd=host_fd(a),type;socklen_t size=sizeof(type);
        if(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&size))return -ENOTTY;
        int enabled=*(int *)ptr(c,sizeof(int));
        return result(ioctl(fd,FIONBIO,&enabled));
    }
    case 20: {
        if(a==0)return -EBADF;
        if(c>64)return -EINVAL;
        struct iovec v[64];memcpy(v,ptr(b,c*sizeof(*v)),c*sizeof(*v));
        for(unsigned i=0;i<c;i++)v[i].iov_base=ptr((uint64_t)v[i].iov_base,v[i].iov_len);
        if(a<=2)return result(writev((int)a,v,c));
        return network_writev(a,v,c);
    }
    case 21: return -ENOENT;
    case 24: return 0;
    case 28:
        if(c!=MADV_DONTNEED)return 0;
        // Whole pages above the image are dropped (zero on next touch);
        // anything else is zeroed in place, as before.
        if(a%PAGE==0 && b%PAGE==0 && a>=((image_end+PAGE-1)&~(uint64_t)(PAGE-1)) && a<page_tables && b<=page_tables-a) {
            pthread_mutex_lock(&allocator_lock);zero_pages(a,b);pthread_mutex_unlock(&allocator_lock);
        }
        else memset(ptr(a,b),0,b);
        return 0;
    case 39: return 1;
    case 186: return current_thread->tid;
    case 218: if(a)ptr(a,4);current_thread->clear_tid=a;return current_thread->tid;
    case 56: return clone_virtual_thread(cpu,r,a,b,c,d,r->r8);
    case 41:
        if(a!=AF_INET || (b&~(SOCK_CLOEXEC|SOCK_NONBLOCK|0xf)))return -EAFNOSUPPORT;
        if(!(((b&0xf)==SOCK_STREAM && (!c || c==IPPROTO_TCP)) || ((b&0xf)==SOCK_DGRAM && (!c || c==IPPROTO_UDP))))return -EAFNOSUPPORT;
        return guest_network_fd(socket(a,b,c),b&0xf);
    case 42: {
        if(c!=sizeof(struct sockaddr_in))return -EINVAL;
        struct sockaddr_in addr;memcpy(&addr,ptr(b,c),c);
        return network_connect(a,&addr);
    }
    case 44: {
        if(!message_flags_permitted(d))return -EINVAL;
        if(!r->r8 && !r->r9)return network_send(a,ptr(b,c),c,d);
        if(r->r9!=sizeof(struct sockaddr_in))return -EINVAL;
        struct sockaddr_in addr;memcpy(&addr,ptr(r->r8,sizeof(addr)),sizeof(addr));
        return network_sendto(a,ptr(b,c),c,d,&addr);
    }
    case 45: {
        if(!message_flags_permitted(d))return -EINVAL;
        if(!r->r8 && !r->r9)return result(recv(host_fd(a),ptr(b,c),c,d));
        if(!r->r8 || !r->r9)return -EINVAL;
        socklen_t size=*(uint32_t *)ptr(r->r9,4);if(size>128)return -EINVAL;
        long rc=recvfrom(host_fd(a),ptr(b,c),c,d,ptr(r->r8,size),&size);*(uint32_t *)ptr(r->r9,4)=size;return result(rc);
    }
    case 49: {
        if(c!=sizeof(struct sockaddr_in))return -EINVAL;
        struct sockaddr_in addr;memcpy(&addr,ptr(b,c),c);int type;socklen_t size=sizeof(type);
        if(getsockopt(host_fd(a),SOL_SOCKET,SO_TYPE,&type,&size))return -errno;
        if(type!=SOCK_DGRAM || addr.sin_family!=AF_INET || addr.sin_addr.s_addr!=INADDR_ANY || addr.sin_port)return -EACCES;
        return result(bind(host_fd(a),(void *)&addr,sizeof(addr)));
    }
    case 48: return result(shutdown(host_fd(a),b));
    case 288: {
        int fd=host_fd(a);struct stat expected,actual;
        if(ingress_fd<0 || fstat(ingress_fd,&expected) || fstat(fd,&actual) || expected.st_ino!=actual.st_ino || expected.st_dev!=actual.st_dev)return -EACCES;
        if(d&~(SOCK_NONBLOCK|SOCK_CLOEXEC))return -EINVAL;
        if(!b && !c)return guest_fd(accept4(fd,NULL,NULL,d));
        if(!b || !c)return -EINVAL;
        socklen_t size=*(uint32_t *)ptr(c,4);if(size>128)return -EINVAL;
        int accepted=accept4(fd,ptr(b,size),&size,d);*(uint32_t *)ptr(c,4)=size;return guest_fd(accepted);
    }
    case 51: case 52: {
        socklen_t size=*(uint32_t *)ptr(c,4);if(size>128)return -EINVAL;
        int rc=n==51?getsockname(host_fd(a),ptr(b,size),&size):getpeername(host_fd(a),ptr(b,size),&size);
        *(uint32_t *)ptr(c,4)=size;return result(rc);
    }
    case 54: {
        int permitted=(b==SOL_SOCKET && (c==SO_KEEPALIVE || c==SO_REUSEADDR || c==SO_RCVBUF || c==SO_SNDBUF)) ||
            (b==IPPROTO_TCP && (c==TCP_NODELAY || c==TCP_KEEPIDLE || c==TCP_KEEPINTVL || c==TCP_KEEPCNT));
        if(!permitted || r->r8!=sizeof(int))return -ENOPROTOOPT;
        return result(setsockopt(host_fd(a),b,c,ptr(d,sizeof(int)),sizeof(int)));
    }
    case 55: {
        if(!socket_option_readable(b,c))return -ENOPROTOOPT;
        socklen_t size=*(uint32_t *)ptr(r->r8,4);if(size>256)return -EINVAL;
        int rc=getsockopt(host_fd(a),b,c,ptr(d,size),&size);*(uint32_t *)ptr(r->r8,4)=size;return result(rc);
    }
    case 60: exit_virtual_thread();return 0;
    case 231: {
        struct rusage usage;CHECK(getrusage(RUSAGE_SELF,&usage));
        fprintf(DIAGNOSTICS,"FENDERS_VMM_METRICS {\"peak_rss_kib\":%ld,\"guest_ram_mib\":%lu,\"virtual_threads\":%u,\"syscalls\":%lu}\n",usage.ru_maxrss,(unsigned long)(ram/(1024*1024)),thread_count,syscall_count);
        fprintf(DIAGNOSTICS,"guest exit %llu; syscalls=%lu\n",(unsigned long long)a,syscall_count);exit(a?1:0);
    }
    case 63: {
        struct utsname name={0};strcpy(name.sysname,"Fenders");strcpy(name.release,"0.1");strcpy(name.machine,"x86_64");memcpy(ptr(a,sizeof(name)),&name,sizeof(name));return 0;
    }
    case 72: {
        int fd=a<=2?(int)a:host_fd(a);
        if(b==F_DUPFD || b==F_DUPFD_CLOEXEC)return guest_duplicate(a,b);
        if(b==F_GETFD || b==F_GETFL)return result(fcntl(fd,b));
        if(b==F_SETFD && !(c&~FD_CLOEXEC))return result(fcntl(fd,b,c));
        // Standard output and error are the launcher's own too: a guest
        // does not change how they block or append.
        if(b==F_SETFL && a<=2)return 0;
        if(b==F_SETFL && !(c&~(O_NONBLOCK|O_APPEND|O_ACCMODE|O_DIRECTORY|O_NOFOLLOW|O_SYNC|O_DSYNC|0x8000)))return result(fcntl(fd,b,c));
        return -EINVAL;
    }
    case 131: if(b){uint8_t *out=ptr(b,24);memset(out,0,24);*(uint32_t *)(out+8)=2;}return 0;
    case 158: {
        if(a!=0x1002)return -ENOTSUP;
        ptr(b,1);struct kvm_sregs s;CHECK(ioctl(cpu,KVM_GET_SREGS,&s));s.fs.base=b;CHECK(ioctl(cpu,KVM_SET_SREGS,&s));return 0;
    }
    case 200: fprintf(DIAGNOSTICS,"guest fatal signal %llu\n",(unsigned long long)b);exit(1);
    case 204: if(b<8)return -EINVAL;memset(ptr(c,b),0,b);*(uint64_t *)ptr(c,8)=1;return 8;
    case 202: {
        // Always private (guest_args.inc).
        long asked=futex_operation(b);if(asked<0)return asked;
        unsigned op=b&FUTEX_CMD_MASK;
        struct timespec *timeout=(op==FUTEX_WAIT || op==FUTEX_WAIT_BITSET) && d?ptr(d,sizeof(struct timespec)):NULL;
        return result(syscall(SYS_futex,ptr(a,4),asked,c,timeout,NULL,r->r9));
    }
    case 157: if(a==15){ptr(b,16);return 0;}return -ENOSYS;
    case 228: if(!clock_permitted(a))return -EINVAL;return result(clock_gettime(a,ptr(b,sizeof(struct timespec))));
    case 281: case 232: if(b>ram || !c || c>1024)return -EINVAL;return result(epoll_wait(host_fd(a),ptr(b,c*sizeof(struct epoll_event)),c,(int)d));
    case 233: return result(epoll_ctl(host_fd(a),b,host_fd(c),d?ptr(d,sizeof(struct epoll_event)):NULL));
    case 273: return 0;
    case 290: return guest_fd(eventfd(a,b));
    case 291: return guest_fd(epoll_create1(a));
    case 318: if(b>4096)return -EINVAL;return result(getrandom(ptr(a,b),b,c));
    case 334: return -ENOSYS;
    default: fprintf(DIAGNOSTICS,"unsupported syscall %llu\n",(unsigned long long)n);return -ENOSYS;
    }
}
static long syscall_guest(int cpu,struct kvm_regs *r) {
    long rc=syscall_guest_inner(cpu,r);
    pthread_mutex_lock(&fd_lock);
    for(unsigned i=0;i<lease_count;i++)release_descriptor(leases[i]);
    lease_count=0;pthread_mutex_unlock(&fd_lock);return rc;
}
#include "cpuid.inc"
#include "msr_filter.inc"
#include "threads.inc"
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"--capabilities")) {
        puts("{\"network_clock\":\"boottime\",\"network_egress_accounting\":\"socket-payload-v1\",\"network_meter\":\"pipe-cumulative-v1\",\"network_egress_budget\":\"socket-payload-ceiling-v2\",\"inherited_files\":true}");return 0;
    }
    diagnostics_start();
    if(argc<2 || argc>4){fprintf(DIAGNOSTICS,"usage: launch runtime.elf [component.cwasm [env-file]] (each a path or fd:N)\n");return 2;}
    // execve left the VMM dumpable: no core dumps or /proc/<pid>/mem access to guest memory.
    CHECK(prctl(PR_SET_DUMPABLE,0,0,0,0));
    if(argc>=3){
        component_path=argv[2];component_fd=inherited_file(component_path);
        struct stat st;
        if(component_fd>=0?!fstat(component_fd,&st):!stat(component_path,&st)){component_dev=st.st_dev;component_ino=st.st_ino;component_known=1;}
    }
    network_meter_start();
    hold_start();
    network_policy();
    filesystem_policy();
    signal(SIGALRM,timeout_handler);
    const char *lifetime=getenv("FENDERS_LIFETIME_SECONDS");
    // A deadline that cannot be set is not one the launcher goes on without:
    // where its confinement refuses the timer, a lifetime must be 0 and kept
    // by whoever started it, as its shim does.
    unsigned long seconds=20;
    if(lifetime){char *end;seconds=strtoul(lifetime,&end,10);if(!*lifetime || *end || seconds>86400)return 2;}
    struct itimerval deadline={.it_value={.tv_sec=(time_t)seconds}};
    if(seconds && setitimer(ITIMER_REAL,&deadline,NULL)){fprintf(DIAGNOSTICS,"lifetime of %lu s cannot be set: %s\n",seconds,strerror(errno));return 2;}
    // All virtual CPUs share one host CPU allowance; resolver threads do not add CPU capacity.
    cpu_set_t allowed,pinned;CPU_ZERO(&allowed);CPU_ZERO(&pinned);CHECK(sched_getaffinity(0,sizeof(allowed),&allowed));
    for(unsigned i=0;i<CPU_SETSIZE;i++)if(CPU_ISSET(i,&allowed)){CPU_SET(i,&pinned);break;}
    CHECK(sched_setaffinity(0,sizeof(pinned),&pinned));
    const char *guest_memory=getenv("FENDERS_GUEST_MEMORY_MIB");
    if(guest_memory){char *end;unsigned long mib=strtoul(guest_memory,&end,10);if(!*guest_memory || *end || mib<32 || mib>MAX_RAM/(1024*1024) || mib%2)return 2;ram=(uint64_t)mib*1024*1024;}
    mem=mmap(NULL,ram,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(mem==MAP_FAILED)fail("mmap");
    // Page tables sit just below the stack so their size can follow the RAM size.
    uint64_t table_bytes=ram/(2*1024*1024)*PAGE;page_tables=ram-STACK_RESERVE-table_bytes;
    *(uint64_t *)(mem+0x1000)=0x2003;*(uint64_t *)(mem+0x2000)=0x3003;
    for(unsigned i=0;i<ram/(2*1024*1024);i++)((uint64_t *)(mem+0x3000))[i]=(page_tables+i*PAGE)|3;
    permissions(0,ram,3|NX);reserve_pages(0,0x100000);reserve_pages(page_tables,table_bytes);reserve_pages(ram-STACK_RESERVE,STACK_RESERVE);
    uint64_t entry=load_guest(argv[1]);
    // SYSCALL enters this stub at CPL0; return at CPL0 without SYSRET.
    const uint8_t stub[]={0x52,0x66,0xba,0x10,0x05,0xef,0x5a,0x50,0x0f,0x20,0xd8,0x0f,0x22,0xd8,0x58,0xff,0xe1};
    memcpy(mem+0x80000,stub,sizeof(stub));permissions(0x80000,PAGE,1);
    strcpy((char *)mem+ram-8192,"fenders-http-runtime");
    strcpy((char *)mem+ram-8128,"/component.cwasm");
    CHECK(getrandom(mem+ram-512,16,0));
    uint64_t initial_sp=ram-16384,*stack=(void *)(mem+initial_sp);unsigned si=0;
    stack[si++]=component_path?2:1;stack[si++]=ram-8192;if(component_path)stack[si++]=ram-8128;stack[si++]=0;
    if(argc==4) {
        size_t env_size;uint8_t *env=read_file(argv[3],&env_size);
        if(!env_size || env_size>4096 || env[env_size-1]){fprintf(DIAGNOSTICS,"invalid environment\n");return 2;}
        memcpy(mem+ram-8000,env,env_size);free(env);
        for(size_t pos=0;pos<env_size;) {
            if(si>=200){fprintf(DIAGNOSTICS,"too many environment entries\n");return 2;}
            stack[si++]=ram-8000+pos;pos+=strlen((char *)mem+ram-8000+pos)+1;
        }
    }
    stack[si++]=0;
    vdso_loaded=invariant_tsc() && load_vdso();
    uint64_t aux[]={AT_SYSINFO_EHDR,vdso_loaded?FENDERS_VDSO_BASE:0,AT_PHDR,elf_phdr,AT_PHENT,sizeof(Elf64_Phdr),AT_PHNUM,elf_phnum,AT_PAGESZ,PAGE,AT_ENTRY,entry,AT_RANDOM,ram-512,AT_UID,0,AT_EUID,0,AT_GID,0,AT_EGID,0,AT_SECURE,0,AT_NULL,0};
    memcpy(stack+si,aux,sizeof(aux));
#include "kvm.inc"
    vm_handle=vm;kvm_handle=kvm;vcpu_map_size=run_size;
    if(vdso_loaded)calibrate_clock(cpu);
    set_syscall_msrs(cpu);
    virtual_threads[0]=(struct virtual_thread){.cpu=cpu,.run=run,.tid=1};
    lifecycle_start();
    if(network_budget_enabled && control_fd<0){fprintf(DIAGNOSTICS,"egress budget requires control socket\n");return 2;}
    run_virtual_thread(&virtual_threads[0]);return 0;
}
