// Filesystem ABI for upstream cap-std. Host roots are operator-supplied capabilities.
// Never pass a guest pathname to an ambient host filesystem operation.
struct fs_mount {const char *name,*env;int fd;int writable;};
static struct fs_mount fs_mounts[]={
    {"/app","FENDERS_FS_APP",-1,0},
    {"/tmp","FENDERS_FS_TMP",-1,1},
    {"/data","FENDERS_FS_DATA",-1,1},
};
static void filesystem_policy(void) {
    for(unsigned i=0;i<3;i++) {
        const char *path=getenv(fs_mounts[i].env);if(!path || !*path)continue;
        fs_mounts[i].fd=open(path,O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        CHECK(fs_mounts[i].fd);
    }
}
static int guest_path(uint64_t address,char out[PATH_MAX]) {
    if(address>=ram)return -EFAULT;
    size_t available=ram-address;if(available>PATH_MAX)available=PATH_MAX;
    // Copy first: a second guest thread must not change a validated pathname.
    memcpy(out,ptr(address,available),available);
    if(!memchr(out,0,available))return -ENAMETOOLONG;
    return 0;
}
static int fs_base(uint64_t guest_dir,const char **path,int *mount) {
    if((*path)[0]=='/') {
        // Only ambient native preopen setup can name a mount. A path passed
        // relative to a capability must never switch to another mount.
        if(guest_dir!=(uint64_t)(int64_t)AT_FDCWD)return -EXDEV;
        for(unsigned i=0;i<3;i++) {
            size_t n=strlen(fs_mounts[i].name);
            if(!strncmp(*path,fs_mounts[i].name,n) && (!(*path)[n] || (*path)[n]=='/')) {
                if(fs_mounts[i].fd<0)return -ENOENT;
                *path+=n;while(**path=='/')++*path;if(!**path)*path=".";
                *mount=i;return fs_mounts[i].fd;
            }
        }
        return -ENOENT;
    }
    struct descriptor *desc=lease_descriptor(guest_dir);
    if(!desc || desc->mount<0)return -EBADF;
    *mount=desc->mount;return desc->fd;
}
static int fs_writable_fd(uint64_t guest) {
    struct descriptor *desc=lease_descriptor(guest);
    if(!desc || desc->mount<0)return -EBADF;
    if(!fs_mounts[desc->mount].writable)return -EROFS;
    return desc->fd;
}
static int beneath(int base,const char *path,uint64_t flags,uint64_t mode,uint64_t extra) {
    struct open_how how={.flags=flags|O_CLOEXEC,.mode=mode,
        .resolve=RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV|extra};
    return syscall(SYS_openat2,base,path,&how,sizeof(how));
}
static int fs_open_raw(uint64_t guest_dir,const char *path,uint64_t flags,uint64_t mode,uint64_t resolve,int *mount) {
    if(getenv("FENDERS_TRACE"))fprintf(DIAGNOSTICS,"fs_open dir=%llu path=%s flags=%llx mode=%llo resolve=%llx\n",(unsigned long long)guest_dir,path,(unsigned long long)flags,(unsigned long long)mode,(unsigned long long)resolve);
    if((resolve&RESOLVE_BENEATH) && path[0]=='/')return -EXDEV;
    int base=fs_base(guest_dir,&path,mount);if(base<0)return base;
    uint64_t allowed=O_ACCMODE|O_APPEND|O_CLOEXEC|O_CREAT|O_DIRECTORY|O_DSYNC|O_EXCL|O_NOFOLLOW|O_NONBLOCK|O_PATH|O_SYNC|O_TRUNC|0x8000;
    if(flags&~allowed || resolve&~(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV|RESOLVE_CACHED))return -EINVAL;
    if((flags&(O_CREAT|O_TRUNC)) || (flags&O_ACCMODE)!=O_RDONLY) {
        if(!fs_mounts[*mount].writable)return -EROFS;
    }
    if(!(flags&O_CREAT))mode=0;else mode&=0777;
    // Inspect existing objects without opening devices or blocking on FIFOs.
    // Reopening our own pinned descriptor cannot be redirected by a path race.
    int pinned=beneath(base,path,O_PATH|(flags&(O_NOFOLLOW|O_DIRECTORY)),0,resolve);
    int fd;
    if(pinned>=0) {
        struct stat st;
        if(fstat(pinned,&st)){int error=-errno;close(pinned);return error;}
        if((flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)){close(pinned);return -EEXIST;}
        if(flags&O_PATH)return pinned;
        if(!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)){close(pinned);return S_ISLNK(st.st_mode)?-ELOOP:-EACCES;}
        char proc[64];snprintf(proc,sizeof(proc),"/proc/self/fd/%d",pinned);
        fd=open(proc,(flags&~(O_CREAT|O_EXCL|O_NOFOLLOW))|O_CLOEXEC|O_NONBLOCK);
        int saved=errno;close(pinned);errno=saved;
    } else {
        if(errno!=ENOENT || !(flags&O_CREAT))return -errno;
        fd=beneath(base,path,flags|O_NONBLOCK,mode,resolve);
    }
    if(getenv("FENDERS_TRACE"))fprintf(DIAGNOSTICS,"fs_open host=%d result=%d errno=%d\n",base,fd,fd<0?errno:0);
    if(fd<0)return -errno;
    struct stat st;if(fstat(fd,&st)){int error=-errno;close(fd);return error;}
    // O_PATH may inspect symlink metadata. Data access is for regular files/directories.
    if(!(flags&O_PATH) && !S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)){close(fd);return -EACCES;}
    if(!(flags&(O_PATH|O_NONBLOCK))) {
        int status=fcntl(fd,F_GETFL);
        if(status<0 || fcntl(fd,F_SETFL,status&~O_NONBLOCK)){int error=-errno;close(fd);return error;}
    }
    return fd;
}
static long fs_open(uint64_t dir,const char *path,uint64_t flags,uint64_t mode,uint64_t resolve) {
    int mount=-1,fd=fs_open_raw(dir,path,flags,mode,resolve,&mount);
    return fd<0?fd:guest_fd_mount(fd,mount);
}
static void close_local(int *fd) {if(*fd>=0)close(*fd);}
#define LOCAL_FD(name) int name __attribute__((cleanup(close_local)))=-1
static int fs_parent(uint64_t dir,char path[PATH_MAX],int *mount,char **leaf,int creating_directory) {
    const char *relative=path;int base=fs_base(dir,&relative,mount);if(base<0)return base;
    if(relative!=path)memmove(path,relative,strlen(relative)+1);
    size_t len=strlen(path);int trailing=len && path[len-1]=='/';
    while(len && path[len-1]=='/')path[--len]=0;
    if(!len)return -ENOENT;
    char *slash=strrchr(path,'/');const char *parent=".";
    if(slash){*slash=0;*leaf=slash+1;parent=path;}else *leaf=path;
    if(!strcmp(*leaf,".") || !strcmp(*leaf,".."))return -EACCES;
    int fd=beneath(base,parent,O_PATH|O_DIRECTORY,0,0);if(fd<0)return -errno;
    // Pass a single final component to namespace syscalls. A trailing slash
    // must not turn their normally-unfollowed final symlink into a path walk.
    if(trailing && creating_directory!=2) {
        struct stat st;int rc=fstatat(fd,*leaf,&st,AT_SYMLINK_NOFOLLOW);
        if(rc<0 && !(errno==ENOENT && creating_directory)){int error=-errno;close(fd);return error;}
        if(!rc && !S_ISDIR(st.st_mode)){close(fd);return -ENOTDIR;}
    }
    return fd;
}
static long fs_syscall(uint64_t n,uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f) {
    (void)f;char path[PATH_MAX],other[PATH_MAX];int mount=-1,mount2=-1,error;char *leaf=NULL,*leaf2=NULL;
    LOCAL_FD(fd);LOCAL_FD(parent);LOCAL_FD(parent2);
    if(n==437) {
        if(d!=sizeof(struct open_how))return -EINVAL;
        struct open_how how;memcpy(&how,ptr(c,sizeof(how)),sizeof(how));
        if((error=guest_path(b,path)))return error;
        return fs_open(a,path,how.flags,how.mode,how.resolve);
    }
    if(n==280 && !b) { // libc futimens
        int writable=fs_writable_fd(a);if(writable<0)return writable;
        struct timespec times[2];if(c)memcpy(times,ptr(c,sizeof(times)),sizeof(times));
        return result(futimens(writable,c?times:NULL));
    }
    if((error=guest_path(n==266?a:b,path)))return error;
    if(n==262 || n==332) {
        unsigned flags=n==262?d:c;
        if(flags&~(AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH|AT_NO_AUTOMOUNT|AT_STATX_SYNC_TYPE))return -EINVAL;
        int target;
        if(!*path && (flags&AT_EMPTY_PATH))target=host_fd(a);
        else {fd=fs_open_raw(a,path,O_PATH|((flags&AT_SYMLINK_NOFOLLOW)?O_NOFOLLOW:0),0,0,&mount);if(fd<0)return fd;target=fd;}
        if(n==262){struct stat st;int rc=fstat(target,&st);if(rc<0)return -errno;memcpy(ptr(c,sizeof(st)),&st,sizeof(st));return 0;}
        struct statx st;int rc=statx(target,"",AT_EMPTY_PATH,d,&st);if(rc<0)return -errno;memcpy(ptr(e,sizeof(st)),&st,sizeof(st));return 0;
    }
    if(n==267) {
        parent=fs_parent(a,path,&mount,&leaf,0);if(parent<0)return parent;
        return result(readlinkat(parent,leaf,ptr(c,d),d));
    }
    if(n==280) {
        if(d&~(AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH))return -EINVAL;
        if(!*path && (d&AT_EMPTY_PATH)) { // futimens as Wasmtime 50 (rustix) issues it
            int writable=fs_writable_fd(a);if(writable<0)return writable;
            struct timespec times[2];if(c)memcpy(times,ptr(c,sizeof(times)),sizeof(times));
            return result(futimens(writable,c?times:NULL));
        }
        fd=fs_open_raw(a,path,O_PATH|((d&AT_SYMLINK_NOFOLLOW)?O_NOFOLLOW:0),0,0,&mount);if(fd<0)return fd;
        if(!fs_mounts[mount].writable)return -EROFS;
        struct timespec times[2];if(c)memcpy(times,ptr(c,sizeof(times)),sizeof(times));
        return result(utimensat(fd,"",c?times:NULL,AT_EMPTY_PATH|((d&AT_SYMLINK_NOFOLLOW)?AT_SYMLINK_NOFOLLOW:0)));
    }
    if(n==266) { // symlinkat: path is the stored target, other is the new link name.
        if((error=guest_path(c,other)))return error;
        parent=fs_parent(b,other,&mount,&leaf,0);if(parent<0)return parent;
        if(!fs_mounts[mount].writable)return -EROFS;
        return result(symlinkat(path,parent,leaf));
    }
    parent=fs_parent(a,path,&mount,&leaf,n==258?2:0);if(parent<0)return parent;
    if(!fs_mounts[mount].writable)return -EROFS;
    if(n==258)return result(mkdirat(parent,leaf,c&0777));
    if(n==263){if(c&~AT_REMOVEDIR)return -EINVAL;return result(unlinkat(parent,leaf,c));}
    if(n==264 || n==316 || n==265) {
        if((error=guest_path(d,other)))return error;
        struct stat source;int creating_directory=n!=265 && !fstatat(parent,leaf,&source,AT_SYMLINK_NOFOLLOW) && S_ISDIR(source.st_mode);
        parent2=fs_parent(c,other,&mount2,&leaf2,creating_directory);if(parent2<0)return parent2;
        if(!fs_mounts[mount2].writable)return -EROFS;
        if(mount!=mount2)return -EXDEV;
        if(n!=265) {if(n==316 && e)return -EINVAL;return result(renameat(parent,leaf,parent2,leaf2));}
        if(e&~AT_SYMLINK_FOLLOW)return -EINVAL;
        if(!(e&AT_SYMLINK_FOLLOW))return result(linkat(parent,leaf,parent2,leaf2,0));
        fd=beneath(parent,leaf,O_PATH,0,0);if(fd<0)return -errno;
        // Follow only the pinned, already-confined source inode, never a guest path.
        char pinned[64];snprintf(pinned,sizeof(pinned),"/proc/self/fd/%d",fd);
        return result(linkat(AT_FDCWD,pinned,parent2,leaf2,AT_SYMLINK_FOLLOW));
    }
    return -ENOSYS;
}
#undef LOCAL_FD
