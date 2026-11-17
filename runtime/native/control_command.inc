// A stream can split or coalesce writes. Accept one bounded, NUL-free line.
// The caller applies SO_RCVTIMEO before reading an operator-owned socket.
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
