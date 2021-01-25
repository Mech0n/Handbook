# GLIBC malloc.c 阅读

> 开一个新的坑，来学GLIBC的源码。

主要以glibc/2.23/malloc.c为主体学习源码，然后对照2.27/2.29学习新的防护机制。

##### 【GLIBC-2.23】

- [`malloc(size_t n)`](./2.23-malloc().md)
- [`free(void* ptr)`](./2.23-free().md)

##### 【GLIBC-2.27】

- [`malloc()`](./2.27-malloc().md)
- [`free()`](./2.27-free().md)

##### 【GLIBC-2.29】

- [[EX]Glibc-2.29新增的防护机制](./[EX]Glibc-2.29新增的防护机制.md)

待补充ing

##### Reference

[Introspelliam](https://introspelliam.github.io/categories/pwn/)

[Understanding glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)

[Glibc-2.29 新增的防护机制](http://blog.eonew.cn/archives/1167)

