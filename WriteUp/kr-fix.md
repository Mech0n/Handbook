---
title: kr_fix
date: 2020-02-12 22:37:24
tags:
- pwn
- pwnable.kr
---

# pwnable.kr fix

### 0x0 前置补偿

这里补充一下`int 0x80`的相关知识：

1.[int 80h系统调用方法| 上善若水](https://introspelliam.github.io/2017/08/07/int-80h系统调用方法/)

2.[ctf中关于syscall系统调用的简单分析](https://zhuanlan.zhihu.com/p/106014234)

3.来自[维基百科]([https://zh.wikipedia.org/wiki/%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8](https://zh.wikipedia.org/wiki/系统调用)):

Linux 的系统调用通过 int 80h 实现，用[系统调用号](https://zh.wikipedia.org/w/index.php?title=系统调用号&action=edit&redlink=1)来区分入口函数。操作系统实现系统调用的基本过程是：

1. 应用程序调用库函数（API）；
2. API 将系统调用号存入 EAX，然后通过中断调用使系统进入内核态；
3. 内核中的中断处理函数根据系统调用号，调用对应的内核函数（系统调用）；
4. 系统调用完成相应功能，将返回值存入 EAX，返回到中断处理函数；
5. 中断处理函数返回到 API 中；
6. API 将 EAX 返回给应用程序。

应用程序调用系统调用的过程是：

1. 把系统调用的编号存入 EAX；
2. 把函数参数存入其它通用寄存器；
3. 触发 0x80 号中断（int 0x80）。

### 0x1 分析

待补充。