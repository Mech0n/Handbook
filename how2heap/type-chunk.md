# `chunk`的分类
每一类就是一个`malloc_chunk`结构体，因为这些`chunk`同属于一个堆块，所以在一块连续的内存中，只是通过区域中特定位置的某些标识符加以区分。

**glibc给我们申请的堆块主要分为以下几类：**

- **allocated chunk** ：当前`chunk`是被应用层用户所使用的
- **free chunk**：当前`chunk`是空闲的，没有被应用层用户所使用
- **top chunk**
  - **概念**：当一个`chunk`处于一个`arena`的最顶部(即最高内存地址处)的时候，就称之为`top chunk`
  - **作用**：该`chunk`并不属于任何`bin`，而是在系统当前的所有`free chunk`(无论那种`bin`)都无法满足用户请求的内存大小的时候，将此`chunk`当做一个仓库，分配给用户使用
  - **分配规则**：如果`top chunk`的大小比用户请求的大小要大的话，就将该`top chunk`分作两部分：1) 用户请求的`chunk`；2）剩余的部分成为新的`top chunk`。否则，就需要扩展`heap`或分配新的`heap`了——在`main arena`中通过`sbrk`扩展`heap`，而在`thread arena`中通过`mmap`分配新的`heap`
- **Last remainder chunk**
  - **它是怎么产生的**：当用户请求的是一个`small chunk`，且该请求无法被`small bin、unsorted bin`满足的时候，就通过`binmaps`遍历`bin`查找最合适的`chunk`，如果该`chunk`有剩余部分的话，就将该剩余部分变成一个新的`chunk`加入到`unsorted bin`中，另外，再将该新的`chunk`变成新的`last remainder chunk`
  - **它的作用是什么：**此类型的`chunk`用于提高连续`malloc(small chunk)`的效率，主要是提高内存分配的局部性。那么具体是怎么提高局部性的呢？举例说明。当用户请求一个`small chunk`，且该请求无法被`small bin`满足，那么就转而交由`unsorted bin`处理。同时，假设当前`unsorted bin`中只有一个`chunk`的话——就是`last remainder chunk`，那么就将该`chunk`分成两部分：前者分配给用户，剩下的部分放到`unsorted bin`中，并成为新的`last remainder chunk`。这样就保证了连续`malloc(small chunk)`中，各个`small chun`k在内存分布中是相邻的，即提高了内存分配的局部性。

————————————————
原文链接：https://blog.csdn.net/qq_41453285/article/details/96851282