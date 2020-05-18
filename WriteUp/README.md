# 每周习题记录

#### 【Pre】

待整理。

#### 【2020-04-04->2020-04-11】

| 题目                                                         | 补偿                                                  |
| ------------------------------------------------------------ | ----------------------------------------------------- |
| [applestore](./pwnable.tw-applestore.md)                     | Overflow                                              |
| [silver_bullet](./pwnable.tw-silver_bullet.md)               | strncat()类函数冗余的`'\0'`                           |
| [hacknote](./pwnable.tw-hacknote.md)                         | Linux ;分割连续命令｜Fastbin                          |
| [calc](./Pwnable.tw-calc.md)                                 | scanf("%d")中`+`算是合法输入导致输入空内容            |
| [Dubblesort](./pwnable.tw-dubblesort/pwnable.tw-dubblesort.md) | CANARY绕过｜`_GLOBAL_OFFSET_TABLE_`地址即`'.got.plt'` |

#### 【2020-04-12->2020-04-18】

| 题目                                                 | 补偿                                                       |
| ---------------------------------------------------- | ---------------------------------------------------------- |
| [easy_stack](./eonew-easy_stack/eonew-easy_stack.md) | `read()`函数与`\x00`｜`__libc_start_main`                  |
| [no_leak](./eonew-no_leak/eonew-no_leak.md)          | `syscall`｜`ld.so` 地址部分写｜栈迁移｜`[ret2del_resolve]` |
| [Re-alloc](./pwnable.tw-Re-alloc.md)                 | `realloc()`函数与UAF                                       |
| [Tcache_Tear](./pwnable.tw-Tcache-tear.md)           | `House of spirit`                                          |

#### 【2020-04-19->2020-04-24】

| 题目                                                         | 补偿                                                   |
| ------------------------------------------------------------ | ------------------------------------------------------ |
| [simpleHeap](./[V&N]simpleHeap.md)                           | `Fastbin dup`｜`__malloc_hook`和`__realloc_hook`的配合 |
| [Alive note && Death Note](./pwnable.tw-Alive_note&&Death_Note.md) | Shellcode 编写                                         |
| [seethefile](./pwnable.tw-seethefile.md)                     | `/proc/self/map`｜`IO_FILE`                            |
| [HFCTF-MarksMan](./HCTF/MarksMan/HCTF-MarksMan.md)           | 改写`libc.so.6`的GOT                                   |
| 铁三2019-littlenot                                           | `Fastbin attack`                                       |
| eonew-shellcode                                              | Ex大佬的`shellcode`题目（太难，待研究）                |
| 【···】                                                      | 【···】                                                |

#### 【2020-04-25->2020-05-02】

| 题目                                                   | 补偿                     |
| ------------------------------------------------------ | ------------------------ |
| [HFCTF-SecureBox](./HCTF/SecureBox/HFCTF-SecureBox.md) | `malloc(0)`|
| DE1CTF-weapon                                          | `IO_FILE`中的`_IO_file_jumps`->`vtable` |
| DE1CTF-a+b                                             |                          |
| 36D杯                                                  | 待比赛结束补充。         |

DE1CTF2020题目实在不会，之后会补充相关知识复现。已知的有C++pwn和MIPS pwn

#### 【2020-05-02->2020-05-10】

| 题目                                                         | 补偿          |
| ------------------------------------------------------------ | ------------- |
| [HCTF2018-the_end](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/io_file/fake-vtable-exploit-zh/#2018-hctf-the_end) | 伪造 `vtable` |

还有SharkyCTF、网鼎杯

#### 【2020-05-11->2020-05-18】

| 题目                                         | 补偿    |
| -------------------------------------------- | ------- |
| [wdb2020-boom1](./网鼎杯2020/boom1/boom1.md) | c解释器 |
| [wdb2020-boom2](./网鼎杯2020/boom2/boom2.md) | Vm pwn  |
| sharkeyCTF-CaptainHook                       | FMT     |

