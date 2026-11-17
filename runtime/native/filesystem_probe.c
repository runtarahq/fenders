// Deliberately bypass Wasmtime: verify that the VMM itself confines native calls.
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/openat2.h>
static long invoke(long n,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
    long value;__asm__ volatile("syscall":"=a"(value):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return value;
}
#define S(n,a,b,c,d,e,f) invoke(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
static void require(int ok) {
    if(!ok){const char text[]="FENDERS_NATIVE_FS_FAILURE\n";S(1,2,text,sizeof(text)-1,0,0,0);S(231,1,0,0,0,0,0);for(;;){}}
}
static int denied(long result) {return result==-EACCES || result==-EPERM || result==-EROFS || result==-EXDEV || result==-ENOENT;}
long test_main(void) {
    long app=S(2,"/app",O_RDONLY|O_DIRECTORY,0,0,0,0);require(app>=3);
    long data=S(2,"/data",O_RDONLY|O_DIRECTORY,0,0,0,0);require(data>=3);
    long tmp=S(2,"/tmp",O_RDONLY|O_DIRECTORY,0,0,0,0);require(tmp>=3);
    struct open_how how={.flags=O_RDONLY,.mode=0,.resolve=0};
    require(denied(S(437,data,"escape-relative",&how,sizeof(how),0,0)));
    require(denied(S(437,data,"escape-absolute",&how,sizeof(how),0,0)));
    require(denied(S(257,data,"../outside/secret.txt",O_RDONLY,0,0,0)));
    require(denied(S(257,app,"/data/created.txt",O_RDONLY,0,0,0)));
    require(denied(S(257,data,"blocked-fifo",O_RDONLY,0,0,0)));
    require(denied(S(2,"/etc/passwd",O_RDONLY,0,0,0,0)));
    require(denied(S(2,"/proc/self/fd/0",O_RDONLY,0,0,0,0)));
    require(denied(S(257,app,"asset.txt",O_WRONLY|O_TRUNC,0,0,0)));
    require(denied(S(257,app,"native-created",O_WRONLY|O_CREAT,0600,0,0)));
    require(denied(S(258,app,"native-dir",0700,0,0,0)));
    require(denied(S(263,app,"asset.txt",0,0,0,0)));
    long alias=S(72,app,F_DUPFD_CLOEXEC,3,0,0,0);require(alias>=3);
    require(denied(S(280,alias,0,0,0,0,0)));
    require(denied(S(257,alias,"asset.txt",O_WRONLY,0,0,0)));
    S(3,alias,0,0,0,0,0);
    long file=S(257,data,"native.txt",O_CREAT|O_EXCL|O_RDWR,0600,0,0);require(file>=3);
    const char bytes[]="native confined write\n";
    require(S(1,file,bytes,sizeof(bytes)-1,0,0,0)==sizeof(bytes)-1);S(3,file,0,0,0,0,0);
    require(denied(S(264,data,"native.txt",tmp,"cross-mount",0,0)));
    require(denied(S(265,data,"native.txt",tmp,"cross-mount",0,0)));
    require(denied(S(264,data,"native.txt",data,"../outside/moved",0,0)));
    require(denied(S(265,data,"escape-relative",data,"stolen",AT_SYMLINK_FOLLOW,0)));
    require(denied(S(258,data,"../outside/native-dir",0700,0,0,0)));
    require(S(266,"../outside",data,"escape-directory",0,0,0)==0);
    require(S(264,data,"escape-directory/",data,"moved-directory",0,0)==-ENOTDIR);
    require(S(263,data,"escape-directory/",AT_REMOVEDIR,0,0,0)==-ENOTDIR);
    // The host concurrently switches race/ between an allowed and forbidden directory.
    unsigned allowed_count=0,denied_count=0;
    for(unsigned i=0;i<2000;i++) {
        long fd=S(257,data,"race/attempt.txt",O_WRONLY|O_CREAT|O_TRUNC,0600,0,0);
        if(fd>=0){++allowed_count;require(S(1,fd,bytes,sizeof(bytes)-1,0,0,0)==sizeof(bytes)-1);S(3,fd,0,0,0,0,0);}
        else {++denied_count;require(denied(fd) || fd==-EAGAIN);}
    }
    require(allowed_count && denied_count);
    const char marker[]="FENDERS_NATIVE_FS_VERIFIED\n";S(1,1,marker,sizeof(marker)-1,0,0,0);return 0;
}
__asm__(".global _start\n_start:\n andq $-16,%rsp\n call test_main\n mov %rax,%rdi\n mov $231,%rax\n syscall\n ud2\n");
