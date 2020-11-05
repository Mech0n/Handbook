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

#### 【2020-05-19->2020-05-23】

| 题目                                                         | 补偿                 |
| ------------------------------------------------------------ | -------------------- |
| [Memory_Monster_I](./DASCTF/Memory_Monster_I/Memory_Monster_I_II_III.md) | 劫持`stack_chk_fail` |
| [Secret2](./DASCTF/secret2/Secret2.md)                       | `ulimit -a`          |

参加了安恒五月赛、写了一下HackpackCTF的题目。

#### 【2020-05-24->2020-05-31】

| 题目                               | 补偿                   |
| ---------------------------------- | ---------------------- |
| [kidding](./pwnable.tw-kidding.md) | 反弹shell              |
| happyending                        | GLIBC-2.29 off_by_null |

#### 【2020-06-01->2020-06-06】

| 题目                                                  | 补偿                       |
| ----------------------------------------------------- | -------------------------- |
| [fakev](./M0lencon-fakev/m0lencon-fakev&&fclose().md) | `IO_FILE` | `GLIBC2.27`    |
| blacky_echo                                           | FMT覆盖大地址              |
| knife                                                 | `socket`\|重定向文件描述符 |

复现了m0lecon2020的pwn（这两周准备考试，摸鱼了。

#### 【2020-08】

| 题目                                                         | 补偿                             |
| ------------------------------------------------------------ | -------------------------------- |
| [Geekpwn-babypwn](https://gist.github.com/Mech0n/2fb8be1392cb6312cbf00d5791e979cc) | House of Orange                  |
| [HITCON-House_of_Orange](https://github.com/Mech0n/Handbook/tree/master/how2heap/house_of_orange) | House of Orange                  |
| [CISCN-Final-2](https://gist.github.com/Mech0n/66df30aa03074bbc94cb3ce7779f2a19) | IO_FILE && Double Free           |
| [ech0_from_your_heart](https://gist.github.com/Mech0n/f955999713df5bd147154dbf7ad14338) | House of Orange && glibc2.24     |
| [sctf2020-coolcode](https://gist.github.com/Mech0n/5d7d4c966835ca2971e25da74408cecd) | Shellcode && retfq 禁用Open的ORW |

#### 【2020-08-2020-11】

以后的WP偷懒写到gist了。

[Mech0n's gist](https://gist.github.com/Mech0n)