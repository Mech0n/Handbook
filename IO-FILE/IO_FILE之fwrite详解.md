> **欢迎关注公众号[平凡路上](https://mp.weixin.qq.com/s/TR-JuE2nl3W7ZmufAfpBZA)，平凡路上是一个致力于二进制漏洞分析与利用经验交流的公众号。**

这是IO FILE系列的第三篇文章，主要讲述怎么通过IO向文件描述符进行输出，通过了前两篇的分析，这次对fwrite函数的分析快了不少，看源码调源码还是有点意思的。


前两篇传送门：

* [IO FILE之fopen详解](./IO_FILE之fopen详解.md)
* [IO FILE之fread详解](./IO_FILE之fread详解.md)

## 总体概览

在开始上源码之前，还是将`fwrite`的总体流程先描述一遍，有个总体的概念。有了主线以后，跟进代码后才不会在里面走丢了。

首先要说明的是`fwrite`函数中涉及的几个IO FILE结构体里的指针：

指针|描述|
---|:--:
_IO_buf_base| 输入输出缓冲区基地址
_IO_buf_end| 输入输出缓冲区结束地址
_IO_write_base|输出缓冲区基地址
_IO_write_ptr|输出缓冲区已使用的地址
_IO_write_end |输出缓冲区结束地址

其中`_IO_buf_base`和`_IO_buf_end`是缓冲区建立函数`_IO_doallocbuf`（上一篇详细描述过）会在里面建立输入输出缓冲区，并把基地址保存在`_IO_buf_base`中，结束地址保存在`_IO_buf_end`中。在建立里输入输出缓冲区后，如果缓冲区作为输出缓冲区使用，会将基址址给`_IO_write_base`，结束地址给`_IO_write_end`，同时`_IO_write_ptr`表示为已经使用的地址。即`_IO_write_base`到`_IO_write_ptr`之间的空间是已经使用的缓冲区，`_IO_write_ptr`到`_IO_write_end`之间为剩余的输出缓冲区。

`fwrite`函数的整体流程图如下（函数调用字体有加粗）：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-05-29-IO_FILE_fwrite_analysis/1557480731572.png)



从图中可以看到`fwrite`的主要实现在`_IO_new_file_xsputn`中，整体流程包含四个部分：
1. 首先判断输出缓冲区还有多少剩余，如果有剩余则将目标输出数据拷贝至输出缓冲区。
2. 如果输出缓冲区没有剩余（输出缓冲区未建立也是没有剩余）或输出缓冲区不够则调用`_IO_OVERFLOW`建立输出缓冲区或刷新输出缓冲区。
3. 输出缓冲区刷新后判断剩余的目标输出数据是否超过块的size，如果超过块的size，则不通过输出缓冲区直接以块为单位，使用`new_do_write`输出目标数据。
4. 如果按块输出数据后还剩下一点数据则调用`_IO_default_xsputn`将数据拷贝至输出缓冲区。

下面进行源码分析。

## 源码分析

`fwrite`的函数原型是：
```c
 size_t fwrite(const void *ptr, size_t size, size_t nmemb,FILE *stream);
   The function fwrite() writes nmemb items of data, each size bytes long, to the stream pointed to by stream, obtaining them from the location given by ptr.
```

首先仍然是一个demo程序，往文件中写入一个小数据，使用带符号的glibc 2.23对程序进行调试。：
```c
#include<stdio.h>

int main(){
    char *data=malloc(0x1000);
    FILE*fp=fopen("test","wb");
    
    fwrite(data,1,0x30,fp);
    return 0;
}
```

首先使用进行初步的跟踪，在`fwrite`下断点。看到程序首先断在`_IO_fwrite`函数中，在开始调试之前，仍然是先把传入的IO FILE `fp`值看一看：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-05-29-IO_FILE_fwrite_analysis/1557453529895.png)
以及此时的vtable中的内容：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-05-29-IO_FILE_fwrite_analysis/1557453596738.png)
从图里也看到由于刚经过`fopen`初始化，输入输出缓冲区没有建立，此时的所有指针都为空。

`_IO_fwrite`函数在文件`/libio/iofwrite.c`中：
```c
_IO_size_t
_IO_fwrite (const void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t request = size * count;
  ...
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request);
  ...
}
libc_hidden_def (_IO_fwrite)
```
没有做过多的操作就调用了`_IO_sputn`函数，该函数是`vtable`中的`__xsputn`
（`_IO_new_file_xsputn`）在文件/libio/fileops.c中，这里就不一次性把函数的所有源码都贴在这里，而是按部分贴在下面每个部分的开始的地方，不然感觉有些冗余。

如流程所示，源码分析分四个部分进行，与流程相对应，其中下面每部分刚开始的代码都是`_IO_new_file_xsputn`函数中的源码。


## 将目标输出数据拷贝至输出缓冲区

第一部分所包含的代码如下：
```c
_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{ 

    _IO_size_t count = 0;
...
    ## 判断输出缓冲区还有多少空间
    else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  ## 如果输出缓冲区有空间，则先把数据拷贝至输出缓冲区
  if (count > 0)
    {
      if (count > to_do)
  count = to_do;
  ...
      memcpy (f->_IO_write_ptr, s, count);
      f->_IO_write_ptr += count;
    ## 计算是否还有目标输出数据剩余
      s += count;
      to_do -= count;

```
主要功能就是判断输出缓冲区还有多少空间，其中像`demo`中的程序所示的`f->_IO_write_end`以及`f->_IO_write_ptr`均为0，此时的输出缓冲区为0。

另一部分则是如果输出缓冲区如果仍有剩余空间的话，则将目标输出数据拷贝至输出缓冲区，并计算在输出缓冲区填满后，是否仍然剩余目标输出数据。

### 建立输出缓冲区或flush输出缓冲区
第二部分代码如下：
```c
## 如果还有目标数据剩余，此时则表明输出缓冲区未建立或输出缓冲区已经满了
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      ## 函数实现清空输出缓冲区或建立缓冲区的功能
      if (_IO_OVERFLOW (f, EOF) == EOF)
  
  return to_do == 0 ? EOF : n - to_do;

      ## 检查输出数据是否是大块
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);
```
经过了上一步骤后，如果还有目标输出数据，表明输出缓冲区未建立或输出缓冲区已经满了，此时调用`_IO_OVERFLOW`函数，该函数功能主要是实现刷新输出缓冲区或建立缓冲区的功能，该函数是vtable函数中的`__overflow`（`_IO_new_file_overflow`），文件在`/libio/fileops.c`中：
```c
int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
  ## 判断标志位是否包含_IO_NO_WRITES
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  
  ## 判断输出缓冲区是否为空
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
  {
    ## 分配输出缓冲区
    _IO_doallocbuf (f);
    _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
  }
     
     ## 初始化指针
      if (f->_IO_read_ptr == f->_IO_buf_end)
  f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
      f->_IO_write_ptr = f->_IO_read_ptr;
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
  f->_IO_write_end = f->_IO_write_ptr;
    }
   
  ## 输出输出缓冲区 
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
       f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF) ## 
      return EOF;
  *f->_IO_write_ptr++ = ch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
          f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  return (unsigned char) ch;
}
libc_hidden_ver (_IO_new_file_overflow, _IO_file_overflow)
```
`__overflow`函数首先检测IO FILE的`_flags`是否包含`_IO_NO_WRITES`标志位，如果包含的话则直接返回。

接着判断`f->_IO_write_base`是否为空，如果为空的话表明输出缓冲区尚未建立，就调用`_IO_doallocbuf`函数去分配输出缓冲区，`_IO_doallocbuf`函数源码在上一篇`fread`中已经分析过了就不跟过去了，它的功能是分配输入输出缓冲区并将指针`_IO_buf_base`和`_IO_buf_end`赋值。在执行完`_IO_doallocbuf`分配空间后调用`_IO_setg`宏，该宏的定义为如下，它将输入相关的缓冲区指针赋值为`_IO_buf_base`指针：
```c
#define _IO_setg(fp, eb, g, eg)  ((fp)->_IO_read_base = (eb),\
  (fp)->_IO_read_ptr = (g), (fp)->_IO_read_end = (eg))
```
经过上面这些步骤，此时IO FILE的指针如下图所示，可以看到，`_IO_buf_base`和`_IO_buf_end`被赋值，且输入缓冲区相关指针被赋值为`_IO_buf_base`：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-05-29-IO_FILE_fwrite_analysis/1557458772102.png)

然后代码初始化其他相关指针，最主要的就是将`f->_IO_write_base`以及将`f->_IO_write_ptr`设置成`f->_IO_read_ptr`指针；将`f->_IO_write_end`赋值为`f->_IO_buf_end`指针。

接着就执行`_IO_do_write`来调用系统调用`write`输出输出缓冲区，输出的内容为`f->_IO_write_ptr`到`f->_IO_write_base`之间的内容。跟进去该函数，函数在`/libio/fileops.c`中：
```c
int
_IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0
    || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)
```
该函数调用了`new_do_write`，跟进去，函数在`/libio/fileops.c`中：
```c
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  ...
  ## 额外判断
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      _IO_off64_t new_pos
  = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
  return 0;
      fp->_offset = new_pos;
    }
  ## 调用函数输出输出缓冲区
  count = _IO_SYSWRITE (fp, data, to_do);
  ...
  ## 刷新设置缓冲区指针
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
           && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
           ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```
终于到了调用`_IO_SYSWRITE`的地方，进行一个判断，判断`fp->_IO_read_end`是否等于`fp->_IO_write_base`，如果不等的话，调用`_IO_SYSSEEK`去调整文件偏移，这个函数就不跟进去了，正常执行流程不会过去这里。

接着就调用`_IO_SYSWRITE`函数，该函数是vtable中的`__write`（`_IO_new_file_write`）函数，也是最终执行系统调用的地方，跟进去看，文件在`/libio/fileops.c`中：
```
_IO_ssize_t
_IO_new_file_write (_IO_FILE *f, const void *data, _IO_ssize_t n)
{
  _IO_ssize_t to_do = n;
  while (to_do > 0)
    {
    ## 系统调用write输出
      _IO_ssize_t count = (__builtin_expect (f->_flags2
               & _IO_FLAGS2_NOTCANCEL, 0)
         ? write_not_cancel (f->_fileno, data, to_do)
         : write (f->_fileno, data, to_do));
  ...   
  return n;
}
```
执行完`_IO_SYSWRITE`函数后，回到`new_do_write`函数，刷新设置缓冲区指针并返回。

### 以块为单位直接输出数据
经历了缓冲区建立以及刷新缓冲区，程序返回到`_IO_new_file_xsputn`函数中，进入到如下代码功能块：
```
  ## 检查输出数据是否是大块
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);


      if (do_write)
  {
    ## 如果是大块的话则不使用输出缓冲区而直接输出。
    count = new_do_write (f, s, do_write);
    to_do -= count;
    if (count < do_write)
      return n - to_do;
  }
```
运行到此处，此时已经经过了`_IO_OVERFLOW`函数（对输出缓冲区进行了初始化或者刷新），也就是说此时的IO FILE缓冲区指针的状态是处于刷新的初始化状态，输出缓冲区中也没有数据。

上面这部分代码检查剩余目标输出数据大小，如果超过输入缓冲区`f->_IO_buf_end - f->_IO_buf_base`的大小，则为了提高效率，不再使用输出缓冲区，而是以块为基本单位直接将缓冲区调用`new_do_write`输出。`new_do_write`函数在上面已经跟过了就是输出，并刷新指针设置。

由于demo程序只输出0x60大小的数据，而它的输出缓冲区大小为0x1000，因此不会进入该部分代码。

### 剩余目标输出数据放入输出缓冲区中

在以大块为基本单位把数据直接输出后可能还剩余小块数据，IO采用的策略则是将剩余目标输出数据放入到输出缓冲区里面，相关源码如下：
```
 ## 剩余的数据拷贝至输出缓冲区
      if (to_do)
  to_do -= _IO_default_xsputn (f, s+do_write, to_do);
```
程序调用`_IO_default_xsputn`函数对剩下的`s+do_write`数据进行操作，跟进去该函数，在`/libio/genops.c`中：
```
_IO_size_t
_IO_default_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (char *) data;
  _IO_size_t more = n;
  if (more <= 0)
    return 0;
  for (;;)
    {
      /* Space available. */
      if (f->_IO_write_ptr < f->_IO_write_end)
  {
    _IO_size_t count = f->_IO_write_end - f->_IO_write_ptr;
    if (count > more)
      count = more;
    if (count > 20)
      {
        ## 输出长度大于20，则调用memcpy拷贝
        memcpy (f->_IO_write_ptr, s, count);
        f->_IO_write_ptr += count;
#endif
        s += count;
      }
    else if (count)
      {
        ## 小于20则直接赋值
        char *p = f->_IO_write_ptr;
        _IO_ssize_t i;
        for (i = count; --i >= 0; )
    *p++ = *s++;
        f->_IO_write_ptr = p;
      }
    more -= count;
  }
  ## 如果输出缓冲区为空，则调用`_IO_OVERFLOW`直接输出。
      if (more == 0 || _IO_OVERFLOW (f, (unsigned char) *s++) == EOF)
  break;
      more--;
    }
  return n - more;
}
libc_hidden_def (_IO_default_xsputn)
```
可以看到函数最主要的作用就是将剩余的目标输出数据拷贝到输出缓冲区里。为了性能优化，当长度大于20时，使用memcpy拷贝，当长度小于20时，使用for循环赋值拷贝。如果输出缓冲区为空，则调用`_IO_OVERFLOW`进行输出。

根据源码我们也知道，demo程序中，最终会进入到`_IO_default_xsputn`中，并且把数据拷贝至输出缓冲区里，执行完成后，看到IO 结构体的数据如下：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-05-29-IO_FILE_fwrite_analysis/1557472135424.png)

可以看到此时的`_IO_write_base`为`0xe13250`，而`_IO_write_ptr `为`0xe132b0`，大小正好是0xb0 。

至此源码分析结束。


## 其他输出函数

`fwrite`分析完了，知道它最主要的就是通过vtable函数里面的`_IO_new_file_xsputn`实现功能，且最终的建立以及刷新输出缓冲区是在`_IO_new_file_overflow`函数里面，最终执行系统调用write对数据进行输出是在`new_do_write`函数中。

下面来看一下其他输出函数的栈回溯的情况，应该也都差不多，对于下面的函数，断点下在`write`函数，然后查看栈回溯。

首先是printf函数，它的栈回溯为：
```
write
_IO_new_file_write
new_do_write+51
__GI__IO_do_write
__GI__IO_file_xsputn
vfprintf
printf
main
__libc_start_main
```
也是调用`_IO_new_file_overflow`函数进行的实现。但是`printf`函数里面情况其实也还挺复杂的，篇幅的限制，就不细说了，其他的输出函数应该也差不多。


## 小结

其实还有一个问题没解决，那就是demo程序里面`fwrite`的时候把数据拷贝到了输出缓冲区，并没有调用`write`函数，那什么时候才写到文件里去呢。答案是main函数返回的时候的` _IO_cleanup`中调用的`_IO_flush_all_lockp`函数，这个留在后面IO FILE利用的时候再详细说明。


结束之前仍然总结下`fwrite`在执行系统调用write前对vtable里的哪些函数进行了调用，具体如下：

* `_IO_fwrite`函数调用了vtable的`_IO_new_file_xsputn`。
* `_IO_new_file_xsputn`函数调用了vtable中的`_IO_new_file_overflow`实现缓冲区的建立以及刷新缓冲区。
* vtable中的`_IO_new_file_overflow`函数调用了vtable的`_IO_file_doallocate`以初始化输入缓冲区。
* vtable中的`_IO_file_doallocate`调用了vtable中的`__GI__IO_file_stat`以获取文件信息。
* `new_do_write`中的`_IO_SYSWRITE`调用了vtable`_IO_new_file_write`最终去执行系统调用write。

同时，后续如果想通过IO FILE输出缓冲区实现任意读写的话，最关键的函数应是`_IO_new_file_overflow`，它里面有个标志位的判断，是后面构造利用需要注意的一个比较重要条件：
```
  ## 判断标志位是否包含_IO_NO_WRITES
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
```

文章首发于[跳跳糖](https://www.tttang.com/archive/1279/)社区















