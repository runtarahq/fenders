// The launcher's own messages (refusals, `guest exit`, metrics, unsupported
// system calls) go to standard error, which is also the guest's descriptor 2.
// A supervisor that keeps the guest's output names a pipe of its own for them
// in FENDERS_DIAGNOSTICS_FD; without it nothing changes. The pipe is written
// without blocking: a reader that falls behind or goes away loses messages,
// and never stalls or ends the VMM.
static FILE *diagnostics;
#define DIAGNOSTICS (diagnostics?diagnostics:stderr)
__attribute__((unused)) static void diagnostics_start(void) {
    const char *text=getenv("FENDERS_DIAGNOSTICS_FD");if(!text)return;
    char *end;errno=0;long fd=strtol(text,&end,10);struct stat info;
    if(errno || !*text || *end || fd<3 || fd>INT_MAX || fstat((int)fd,&info) || !S_ISFIFO(info.st_mode)) {
        fprintf(stderr,"invalid inherited diagnostics pipe\n");exit(2);
    }
    signal(SIGPIPE,SIG_IGN);
    FILE *stream=NULL;
    if(fcntl((int)fd,F_SETFD,FD_CLOEXEC) || fcntl((int)fd,F_SETFL,fcntl((int)fd,F_GETFL)|O_NONBLOCK) || !(stream=fdopen((int)fd,"w"))) {
        perror("diagnostics pipe");exit(1);
    }
    setvbuf(stream,NULL,_IOLBF,0);
    diagnostics=stream;
}
