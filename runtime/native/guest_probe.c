// A guest for testing the launcher from inside the VM: a freestanding
// program the launcher boots in place of the Wasmtime runtime, which makes
// the system calls a hostile or merely unusual guest would and reports what
// it was told. `scripts/verify_launcher_guest_live.sh` runs each scenario on
// KVM and checks how the launcher ended.
//
// The scenario is the guest's environment variable PROBE. A check that fails
// ends the guest with its number (`guest exit N` in the launcher's messages).
typedef unsigned long u64;
typedef long i64;
static i64 call(u64 n,u64 a,u64 b,u64 c,u64 d,u64 e,u64 f) {
    register u64 r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;i64 result;
    __asm__ volatile("syscall":"=a"(result):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return result;
}
#define CALL(n,...) call6(n,##__VA_ARGS__,0,0,0,0,0,0)
#define call6(n,a,b,c,d,e,f,...) call(n,(u64)(a),(u64)(b),(u64)(c),(u64)(d),(u64)(e),(u64)(f))
enum {WRITE=1,OPEN=2,CLOSE=3,FSTAT=5,MMAP=9,PREAD=17,SOCKET=41,CLONE=56,EXIT=60,FADVISE=221,EXIT_GROUP=231};
__attribute__((noreturn)) static void leave(u64 code) {for(;;)CALL(EXIT_GROUP,code);}
#define CHECK(number,condition) do {if(!(condition))leave(number);} while(0)
static int same(const char *a,const char *b) {while(*a && *a==*b){a++;b++;}return *a==*b;}

// What a guest learns of a host file, and what it may do to it.
static void files(void) {
    i64 fd=CALL(OPEN,"/component.cwasm",0);CHECK(10,fd>=3);
    u64 st[18];for(unsigned i=0;i<18;i++)st[i]=~0ul;
    CHECK(11,CALL(FSTAT,fd,st)==0);
    // Its kind and size, and nothing that names it on the host.
    CHECK(12,st[0]==0 && st[1]==0);                      // device, inode
    CHECK(13,(unsigned)(st[3]>>32)==0 && (unsigned)st[4]==0); // owner, group
    CHECK(14,((unsigned)st[3]&0170000)==0100000 && (i64)st[6]>0); // a regular file, its size
    CHECK(15,st[9]==0 && st[11]==0 && st[13]==0);        // times
    // Advice that would drop the shared page cache is answered and not done.
    CHECK(16,CALL(FADVISE,fd,0,0,4)==0);
    CHECK(17,CALL(FADVISE,fd,0,0,2)==0);
    CHECK(18,CALL(FADVISE,99,0,0,4)==-9);
    // A file mapping holds the file's bytes; one of no file is refused and
    // leaves nothing behind: the same address is given again.
    char head[16];CHECK(19,CALL(PREAD,fd,head,16,0)==16);
    i64 mapped=CALL(MMAP,0,4096,1,2,fd,0);CHECK(20,mapped>0);
    for(unsigned i=0;i<16;i++)CHECK(21,((char *)mapped)[i]==head[i]);
    CHECK(22,CALL(MMAP,0,4096,1,2,77,0)==-9);
    i64 plain=CALL(MMAP,0,8192,3,0x22,-1,0);CHECK(23,plain>0);
    ((char *)plain)[8191]=1;
    // A call the launcher does not have is refused each time it is made.
    CHECK(24,CALL(9999)==-38 && CALL(9999)==-38);
    leave(0);
}
// A thread made just before its parent exits is not taken for nobody: the
// run goes on until the thread ends it, with the thread's code.
static char stack[65536],tls[64];
static volatile u64 spun;
__attribute__((noreturn)) static void child(void) {
    for(u64 i=0;i<200000000ul;i++)spun=i;
    leave(7);
}
static void thread(void) {
    u64 flags=0x100|0x200|0x400|0x800|0x10000|0x40000|0x80000,top=(u64)(stack+sizeof(stack))&~15ul;
    register u64 r10 __asm__("r10")=0,r8 __asm__("r8")=(u64)tls;register void (*entry)(void) __asm__("r12")=child;i64 result;
    __asm__ volatile("syscall\n test %%rax,%%rax\n jnz 1f\n xor %%ebp,%%ebp\n and $-16,%%rsp\n call *%%r12\n1:"
        :"=a"(result):"a"((u64)CLONE),"D"(flags),"S"(top),"d"(0ul),"r"(r10),"r"(r8),"r"(entry):"rcx","r11","memory");
    CHECK(30,result>1);
    for(;;)CALL(EXIT,0);
}
// The last thread's exit is the guest's.
static void last_thread(void) {for(;;)CALL(EXIT,0);}
// A pointer outside the guest ends it, and is told apart from a failure.
static void pointer(void) {CALL(WRITE,1,~0ul-4096,1);leave(40);}
// Sockets are made at a bounded rate.
static void sockets(void) {
    unsigned made=0,refused=0;
    for(unsigned i=0;i<1500;i++) {
        i64 fd=CALL(SOCKET,2,1,0);
        if(fd>=3){made++;CHECK(50,CALL(CLOSE,fd)==0);}
        else {CHECK(51,fd==-11);refused++;}
    }
    CHECK(52,refused>0 && made>=1000 && made<=1100);
    leave(0);
}
// A model-specific register is not the guest's to read: the access faults,
// and with no handler of its own for the fault this guest is ended.
static void msr(void) {
    unsigned low,high;
    __asm__ volatile("rdmsr":"=a"(low),"=d"(high):"c"(0x10u));
    leave(60+(low|high?1:0));
}
// Runs until it is ended from outside: for looking at the launcher meanwhile.
static void spin(void) {for(;;)spun++;}
__attribute__((noreturn,used)) static void start(u64 *sp) {
    u64 argc=sp[0];char **env=(char **)(sp+argc+2);
    for(;*env;env++) {
        const char *entry=*env;
        if(entry[0]!='P' || entry[1]!='R' || entry[2]!='O' || entry[3]!='B' || entry[4]!='E' || entry[5]!='=')continue;
        entry+=6;
        if(same(entry,"files"))files();
        if(same(entry,"thread"))thread();
        if(same(entry,"last-thread"))last_thread();
        if(same(entry,"pointer"))pointer();
        if(same(entry,"sockets"))sockets();
        if(same(entry,"msr"))msr();
        if(same(entry,"spin"))spin();
    }
    leave(99);
}
__asm__(".globl _start\n_start:\n mov %rsp,%rdi\n and $-16,%rsp\n call start\n");
