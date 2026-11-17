// A stream can split or coalesce writes: a command is one bounded, NUL-free
// line, and what arrives after it in the same read is the next command, kept
// for the next call. The caller applies SO_RCVTIMEO before reading an
// operator-owned socket.
struct control_input {
    char data[2048];
    size_t used;
};
// The next command from `client`, as a line with its newline, in `command`.
// 1: a command. 0: the stream ended, or failed. -1: a line that is no command
// (too long for `capacity`, or with a NUL in it), which is passed by.
static int control_next_command(int client,struct control_input *input,char *command,size_t capacity) {
    memset(command,0,capacity);
    int oversized=0;
    for(;;) {
        char *newline=memchr(input->data,'\n',input->used);
        if(newline) {
            size_t length=(size_t)(newline-input->data)+1;
            int valid=!oversized && length<capacity && !memchr(input->data,0,length);
            if(valid)memcpy(command,input->data,length);
            memmove(input->data,input->data+length,input->used-length);
            input->used-=length;
            return valid?1:-1;
        }
        // No newline in a full buffer: the line is longer than any command.
        // Its bytes are dropped as they come, up to its newline.
        if(input->used==sizeof(input->data)){input->used=0;oversized=1;}
        ssize_t count=recv(client,input->data+input->used,sizeof(input->data)-input->used,0);
        if(count<0 && errno==EINTR)continue;
        if(count<=0)return 0;
        input->used+=(size_t)count;
    }
}
// One command from a connection that carries only one: a bounded, NUL-free
// line and nothing after it.
static int control_read_command(int client,char *command,size_t capacity) {
    size_t used=0;
    memset(command,0,capacity);
    while(used<capacity-1) {
        ssize_t count=recv(client,command+used,capacity-1-used,0);
        if(count<=0)return 0;
        used+=(size_t)count;
        char *newline=memchr(command,'\n',used);
        if(newline)return newline==command+used-1 && !memchr(command,0,used);
    }
    return 0;
}
