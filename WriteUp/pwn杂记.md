---
title: pwn杂记
date: 2019-12-03 22:05:52
tags: pwn
---

# PWN

### 0x0 需要的工具（待补充……）

- pwntools

  [安装参考](https://blog.csdn.net/Eira_H/article/details/80982959)	[doc参考](https://bbs.pediy.com/thread-247217.htm)

- retdec

  用来将汇编代码反编译成c。有IDA  pro插件，和独立的反编译工具（暂时可以替代IDA pro）。

### 0x1 malloc 申请失败

`malloc`申请空间最大值**决定于**程序是x86的还是x64的。

`size_t size` 这个决定了`malloc`的参数 。

- 在x86下为 `0xffffffff` 

- 在x64下为 `0xffffffffffffffff`

### 0x1 大端序 小端序

- 大端序：数据的高位字节存放在地址的低端 低位字节存放在地址高端

- 小端序：数据的高位字节存放在地址的高端 低位字节存放在地址低端

- 举个🌰

  ```assembly
  0x00000001           -- 12
  0x00000002           -- 34
  0x00000003           -- 56
  0x00000004           -- 78
  ;大端序
  ```

  ```assembly
  0x00000001           -- 78
  0x00000002           -- 56
  0x00000003           -- 34
  0x00000004           -- 12
  ;小端序
  ```

  **一个很好的记忆方法是，大端序是按照数字的书写顺序进行存储的，而小端序是颠倒书写顺序进行存储的。**

- [参考](https://www.cnblogs.com/graphics/archive/2011/04/22/2010662.html)

### 0x2 read()函数

- 头文件：`#include <unistd.h>`

- 定义函数：`ssize_t read(int fd, void * buf, size_t count);`

- 函数说明：`read()`会把参数`fd` 所指的文件传送`count` 个字节到`buf` **指针所指的内存中.** 若参数`count` 为`0`, 则`read()`不会有作用并返回`0`. 返回值为实际读取到的字节数, 如果返回`0`, 表示已到达文件尾或是无可读取的数据,此外文件读写位置会随读取到的字节移动.

- 附加说明：
  如果顺利 `read()`会返回实际读到的字节数, 最好能将返回值与参数`count` 作比较, 若返回的字节数比要求读取的字节数少, 则有可能读到了文件尾、被信号中断了读取动作.

- 当有错误发生时则返回`-1`, 错误代码存入`error` 中, 而文件读写位置则无法预期.
- [参考](http://c.biancheng.net/cpp/html/239.html)

### 0x3 GOT覆盖

- 原理：由于GOT表是可写的，把其中的函数地址覆盖为我们shellcode地址，在程序进行调用这个函数时就会执行shellcode。

- GOT表：
  - 概念：每一个外部定义的符号在全局偏移表（Global offset Table ）中有相应的条目，GOT位于ELF的数据段中，叫做GOT段。**GOT表中存的是每个库函数的起始地址**
  - 作用：把位置无关的地址计算重定位到一个绝对地址。程序首次调用某个库函数时，运行时连接编辑器（rtld）找到相应的符号，并将它重定位到GOT之后每次调用这个函数都会将控制权直接转向那个位置，而不再调用rtld。

- [参考](https://syf.ac.cn/2017/08/19/17.08.19/)

### 0x4 汇编指令长度

### 0x5 strncmp() 

- strncmp() 函数的声明：

  `int strncmp(const char *str1, const char *str2, size_t n)`

- 参数:
  - **str1** -- 要进行比较的第一个字符串。
  - **str2** -- 要进行比较的第二个字符串。
  - **n** -- 要比较的最大字符数。
- 返回值
  - 如果返回值 < 0，则表示 str1 小于 str2。
  - 如果返回值 > 0，则表示 str2 小于 str1。
  - 如果返回值 = 0，则表示 str1 等于 str2。
- [参考](https://www.runoob.com/cprogramming/c-function-strncmp.html)

