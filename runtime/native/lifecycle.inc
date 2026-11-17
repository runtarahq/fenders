// Retained, cooperative pause. Control descriptors are supplied by the node
// worker, never discovered through guest paths or tenant-provided environment.
static int ingress_fd=-1,control_fd=-1,host_origin_fd=-1;
static _Atomic int application_idle;
static int pause_requested;
static pthread_mutex_t lifecycle_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t lifecycle_changed=PTHREAD_COND_INITIALIZER;
#include "control_command.inc"

static void lifecycle_kick(int signal_number) {
    (void)signal_number;
    if(current_thread)current_thread->run->immediate_exit=1;
}
static void lifecycle_barrier(void) {
    pthread_mutex_lock(&lifecycle_lock);
    if(pause_requested) {
        // Complete a pending OUT without executing another guest instruction.
        current_thread->run->immediate_exit=1;
        int rc=ioctl(current_thread->cpu,KVM_RUN,0);
        if(rc<0 && errno!=EINTR)fail("complete paused KVM operation");
        current_thread->parked=1;
        pthread_cond_broadcast(&lifecycle_changed);
        while(pause_requested)pthread_cond_wait(&lifecycle_changed,&lifecycle_lock);
        current_thread->parked=0;
    }
    current_thread->run->immediate_exit=0;
    pthread_mutex_unlock(&lifecycle_lock);
}
static int lifecycle_all_parked(void) {
    unsigned active=0;
    for(unsigned i=0;i<thread_count;i++)if(virtual_threads[i].active) {
        ++active;if(!virtual_threads[i].parked)return 0;
    }
    return active!=0;
}
static void *lifecycle_control(void *unused) {
    (void)unused;
    // A listening control socket takes one connection a command. A connected
    // one (the other end of a pair its shim keeps: no name anything else
    // could connect to) carries every command, a line each, until it closes.
    // A line that is no command is answered as such and the next is read:
    // two commands that arrive together are two commands, not an error that
    // ends the thread and with it every later grant.
    int listening=0;socklen_t option=sizeof(listening);
    if(getsockopt(control_fd,SOL_SOCKET,SO_ACCEPTCONN,&listening,&option))fail("control socket");
    struct timeval timeout={.tv_sec=2};
    if(!listening)setsockopt(control_fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    static struct control_input connected;
    for(;;) {
        int client=control_fd;
        if(listening) {
            client=accept4(control_fd,NULL,NULL,SOCK_CLOEXEC);
            if(client<0){if(errno==EINTR)continue;fail("control accept");}
            setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
            setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
        }
        char command[1024];
        int read=listening?control_read_command(client,command,sizeof(command)):control_next_command(client,&connected,command,sizeof(command));
        if(!listening && !read)return NULL;
        int complete=read==1;
        const char *error=NULL;
        pthread_mutex_lock(&lifecycle_lock);
        if(!complete)error="invalid-command";
        else if(!strncmp(command,"egress ",7))error=network_budget_command(command);
        else if(!strcmp(command,"pause\n")) {
            if(!pause_requested && !atomic_load(&application_idle))error="application-busy";
            else {
                pause_requested=1;
                struct timespec until;clock_gettime(CLOCK_REALTIME,&until);until.tv_sec+=2;
                while(!lifecycle_all_parked()) {
                    for(unsigned i=0;i<thread_count;i++)if(virtual_threads[i].active && !virtual_threads[i].parked)
                        pthread_kill(virtual_threads[i].host_thread,SIGUSR1);
                    struct timespec tick;clock_gettime(CLOCK_REALTIME,&tick);tick.tv_nsec+=20000000;
                    if(tick.tv_nsec>=1000000000){tick.tv_nsec-=1000000000;++tick.tv_sec;}
                    pthread_cond_timedwait(&lifecycle_changed,&lifecycle_lock,&tick);
                    clock_gettime(CLOCK_REALTIME,&tick);
                    if(tick.tv_sec>until.tv_sec || (tick.tv_sec==until.tv_sec && tick.tv_nsec>=until.tv_nsec)) {
                        error="quiescence-timeout";pause_requested=0;
                        pthread_cond_broadcast(&lifecycle_changed);break;
                    }
                }
            }
        } else if(!strcmp(command,"resume\n")) {
            pause_requested=0;pthread_cond_broadcast(&lifecycle_changed);
        } else if(strcmp(command,"status\n"))error="invalid-command";
        uint64_t tx_bytes;int tx_measured;network_usage(&tx_bytes,&tx_measured);
        char budget[384];network_budget_status(budget,sizeof(budget));
        char response[1024];
        int count=snprintf(response,sizeof(response),"{\"paused\":%s,\"idle\":%s,\"network_egress_accounting\":\"socket-payload-v1\",\"network_tx_bytes\":%llu,\"network_tx_measured\":%s,%s,\"error\":%s%s%s}\n",
            pause_requested && lifecycle_all_parked()?"true":"false",atomic_load(&application_idle)?"true":"false",
            (unsigned long long)tx_bytes,tx_measured?"true":"false",budget,
            error?"\"":"",error?error:"null",error?"\"":"");
        pthread_mutex_unlock(&lifecycle_lock);
        send(client,response,count,MSG_NOSIGNAL);
        if(listening)close(client);
    }
    return NULL;
}
static int inherited_socket(const char *name,int type) {
    const char *value=getenv(name);if(!value)return -1;
    char *end;long fd=strtol(value,&end,10);int actual; socklen_t size=sizeof(actual);
    if(!*value || *end || fd<3 || fd>INT_MAX || getsockopt(fd,SOL_SOCKET,SO_TYPE,&actual,&size) || actual!=type) {
        fprintf(DIAGNOSTICS,"invalid inherited socket: %s\n",name);exit(2);
    }
    return (int)fd;
}
static void lifecycle_start(void) {
    ingress_fd=inherited_socket("FENDERS_INGRESS_FD",SOCK_STREAM);
    // One stream to the node for the host-bound origin; the guest multiplexes over it.
    host_origin_fd=inherited_socket("FENDERS_HOST_ORIGIN_FD",SOCK_STREAM);
    control_fd=inherited_socket("FENDERS_CONTROL_FD",SOCK_STREAM);
    struct sigaction action={0};action.sa_handler=lifecycle_kick;sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1,&action,NULL));
    if(control_fd>=0){pthread_t thread;int error=pthread_create(&thread,NULL,lifecycle_control,NULL);if(error){errno=error;fail("control thread");}pthread_detach(thread);}
}
