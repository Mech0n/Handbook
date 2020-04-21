

> **欢迎关注公众号[平凡路上](https://mp.weixin.qq.com/s/TR-JuE2nl3W7ZmufAfpBZA)，平凡路上是一个致力于二进制漏洞分析与利用经验交流的公众号。**
>
> ​																														--来自作者


上篇文章描述了vtable check以及绕过vtalbe check的方法之一，利用vtable段中的`_IO_str_jumps`来进行FSOP。本篇则主要描述使用缓冲区指针来进行任意内存读写。

从前面`fread`以及`fwrite`的分析中，我们知道了FILE结构体中的缓冲区指针是用来进行输入输出的，很容易的就想到了如果能过伪造这些缓冲区指针，在一定的条件下应该可以完成任意地址的读写。

本文包括两部分：

* 使用`stdin`标准输入缓冲区进行任意地址写。
* 使用`stdout`标准输出缓冲区进行任意地址读写。

接下来描述这两部分的原理以及给出相应的题目实践，原理介绍部分是基于已经拥有可以伪造IO FILE结构体的缓冲区指针漏洞的基础上进行的。在后续过程假设我们目标写的地址是`write_start`，写结束地址为`write_end`；读的目标地址为`read_start`，读的结束地址为`read_end`。

前几篇传送门：

* [IO FILE之fopen详解](https://ray-cp.github.io/archivers/IO_FILE_fopen_analysis)
* [IO FILE之fread详解](https://ray-cp.github.io/archivers/IO_FILE_fread_analysis)
* [IO FILE之fwrite详解](https://www.tttang.com/archive/1279/)
* [IO FILE之fclose详解](https://ray-cp.github.io/archivers/IO_FILE_fclose_analysis)
* [IO FILE之劫持vtable及FSOP](https://ray-cp.github.io/archivers/IO_FILE_vtable_hajack_and_fsop)
* [IO FILE 之vtable劫持以及绕过](https://ray-cp.github.io/archivers/IO_FILE_vtable_check_and_bypass)




## `stdin`标准输入缓冲区进行任意地址写

这一部分主要阐述的是使用`stdin`标准输入缓冲区指针进行任意地址写的功能。

### 原理分析

先通过`fread`回顾下通过输入缓冲区进行输入的流程：

1. 判断`fp->_IO_buf_base`输入缓冲区是否为空，如果为空则调用的`_IO_doallocbuf`去初始化输入缓冲区。
2. 在分配完输入缓冲区或输入缓冲区不为空的情况下，判断输入缓冲区是否存在数据。
3. 如果输入缓冲区有数据则直接拷贝至用户缓冲区，如果没有或不够则调用`__underflow`函数执行系统调用读取数据到输入缓冲区，再拷贝到用户缓冲区。
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-08-11-IO_FILE_arbitrary_read_write/1558410757174.png)

假设我们能过控制输入缓冲区指针，使得输入缓冲区指向想要写的地址，那么在第三步调用系统调用读取数据到输入缓冲区的时候，也就会调用系统调用读取数据到我们想要写的地址，从而实现任意地址写的目的。

根据`fread`的源码，我们再看下要想实现往`write_start`写长度为`write_end - write_start`的数据具体经历了些什么。

```c
_IO_size_t
_IO_file_xsgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
 ...
  if (fp->_IO_buf_base == NULL)
    {
      ...
      //输入缓冲区为空则初始化输入缓冲区
    }

  while (want > 0)
    {

      have = fp->_IO_read_end - fp->_IO_read_ptr;
      
      if (have > 0) 
        {
          ...
          //memcpy
          
        }
    
      if (fp->_IO_buf_base
          && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
        {
          if (__underflow (fp) == EOF)  ## 调用__underflow读入数据
      ...
        }
      ...
  return n - want;
}
```
上面贴出了一些关键代码，首先是`_IO_file_xsgetn`函数，函数先判断输入缓冲区`_IO_buf_base`是否为空，如果为空的话则调用`_IO_doallocbuf`初始化缓冲区，因此需构造`_IO_buf_base`不为空。

接着函数中当输入缓冲区有剩余时即`_IO_read_end -_IO_read_ptr >0`，会将缓冲区中的数据拷贝至目标中，因此想要利用输入缓冲区实现读写，最好使`_IO_read_end -_IO_read_ptr =0`即`_IO_read_end ==_IO_read_ptr`。

同时还要求读入的数据`size`要小于缓冲区数据的大小，否则为提高效率会调用read直接读。


`_IO_file_xsgetn`函数中当缓冲区不能满足需求时会调用`__underflow`去读取数据，查看`__underflow`。
```c
int
_IO_new_file_underflow (_IO_FILE *fp)
{
  _IO_ssize_t count;
  ...
  ## 如果存在_IO_NO_READS标志，则直接返回
  if (fp->_flags & _IO_NO_READS)
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  ## 如果输入缓冲区里存在数据，则直接返回
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;
  ...

  ##调用_IO_SYSREAD函数最终执行系统调用读取数据
  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
               fp->_IO_buf_end - fp->_IO_buf_base);
  ...

}
libc_hidden_ver (_IO_new_file_underflow, _IO_file_underflow)
```
在`_IO_new_file_underflow`函数中先判断`fp->_IO_read_ptr < fp->_IO_read_end`是否成立，成立则直接返回，因此再次要求伪造的结构体`_IO_read_end ==_IO_read_ptr`，绕过该条件检查。

接着函数会检查`_flags`是否包含`_IO_NO_READS`标志，包含则直接返回。标志的定义是`#define _IO_NO_READS 4`，因此`_flags`不能包含`4`。

最终系统调用`_IO_SYSREAD (fp, fp->_IO_buf_base,fp->_IO_buf_end - fp->_IO_buf_base)`读取数据，因此要想利用`stdin`输入缓冲区需设置FILE结构体中`_IO_buf_base`为`write_start`，`_IO_buf_end`为`write_end`。同时也需将结构体中的`fp->_fileno`设置为0，最终调用`read (fp->_fileno, buf, size))`读取数据。

将上述条件综合表述为：

1. 设置`_IO_read_end`等于`_IO_read_ptr`。
2. 设置`_flag &~ _IO_NO_READS`即`_flag &~ 0x4`。
3. 设置`_fileno`为0。
4. 设置`_IO_buf_base`为`write_start`，`_IO_buf_end`为`write_end`；且使得`_IO_buf_end-_IO_buf_base`大于fread要读的数据。


### 实践

实践的题目是whctf2017的stackoverflow，这一年也是这一种利用方式的兴起之年，这一题是很经典的一题。

题目首先是输入name，并把name输出出来，由于name未进行初始化设置且读取数据后未加入`\x00`，可以由此泄露出libc地址。

接着进入主功能函数，漏洞在先使用temp变量保存了输入的size，但是后续最后写`\x00`的时候使用的是temp，而不是size，因此存在一个溢出写`\x00`的漏洞。

在之前的文章中，我们知道了当申请堆块大小很大时（0x200000），申请出来的堆块会紧挨着libc，因此我们可以利用这个溢出写`\x00`的漏洞往libc的内存中写入一个`\x00`字节。

往哪里写一个`\x00`字节，后续改变整个内存结构而拿到shell？答案时`stdin`结构体中的`\x00`，我们先看下输入之前的stdin结构体中的数据：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-08-11-IO_FILE_arbitrary_read_write/1558426127981.png)
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-08-11-IO_FILE_arbitrary_read_write/1558426295835.png)

可以看到在glibc 2.24中，`stdin`结构体中存储`_IO_buf_end`指针内存地址的末尾刚好为`\x00`，若利用漏洞我们将`_IO_buf_base`末尾写`\x00`，则会使得`_IO_buf_base`指向`stdin`结构体中存储`_IO_buf_end`指针内存地址，即可利用输入缓冲区覆盖`_IO_buf_end`。

我们可将`_IO_buf_end`覆盖为`__malloc_hook+0x8`，则输入时最后控制写的数据为`stdin`中的`_IO_buf_end`指针位置到`__malloc_hook+0x8`，以实现控制`__malloc_hook`。

原理就是如此，需要多提两点。

一是`IO_getc`函数的作用是刷新`_IO_read_ptr`，每次会从输入缓冲区读一个字节数据即将`_IO_read_ptr`加一，当`_IO_read_ptr`等于`_IO_read_end`的时候便会调用`read`读数据到`_IO_buf_base`地址中。

二是往malloc_hook写什么，由于`one gadget`用不了，因此在栈中找到了一个gadget，地址为`0x400a23`，可以读取数据形成栈溢出，从而进行ROP，拿到shell。
​```c
.text:0000000000400A23                 lea     rax, [rbp+name]
.text:0000000000400A27                 mov     esi, 50h        ; count
.text:0000000000400A2C                 mov     rdi, rax        ; input
.text:0000000000400A2F                 call    input_data
​```


## `stdout`标准输入缓冲区进行任意地址读写

上半部分使用了`stdin`进行任意地址写，这部分主要阐述`stdout`来进行任意地址读写。`stdin`只能输入数据到缓冲区，因此只能进行写。而`stdout`会将数据拷贝至输出缓冲区，并将输出缓冲区中的数据输出出来，所以如果可控`stdout`结构体，通过构造可实现利用其进行任意地址读以及任意地址写。


### 任意写

任意写的主要原理为：构造好输出缓冲区将其改为想要任意写的地址，当输出数据可控时，会将数据拷贝至输出缓冲区，即实现了将可控数据拷贝至我们想要写的地址。

想要实现上述功能，查看`fwrite`源码中如何才能实现该功能：
```c
_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{ 
...
    ## 判断输出缓冲区还有多少空间
    else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  ## 如果输出缓冲区有空间，则先把数据拷贝至输出缓冲区
  if (count > 0)
    {
    ...
      memcpy (f->_IO_write_ptr, s, count);
```
任意写功能的实现在于IO缓冲区没有满时，会先将要输出的数据复制到缓冲区中，可通过这一点来实现任意地址写的功能。可以看到任意写好像很简单，只需将`_IO_write_ptr`指向`write_start`，`_IO_write_end`指向`write_end`即可。

### 任意读

利用`stdout`进行任意地址读的原理为：控制输出缓冲区指针指向我们输入的地址，构造好条件，使得输出缓冲区为已经满的状态，再次调用输出函数时，程序会刷新输出缓冲区即会输出我们想要的数据，实现任意读。

仍然是查看`fwrite`源码中如何才能实现该功能：
​```c
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
    ...
    //memcpy
    }
    if (to_do + must_flush > 0)
    {
      if (_IO_OVERFLOW (f, EOF) == EOF)
​```
当`f->_IO_write_end > f->_IO_write_ptr`时，会调用memcpy拷贝数据，因此最好构造条件`f->_IO_write_end`等于`f->_IO_write_ptr`。

接着进入`_IO_OVERFLOW`函数，去刷新输出缓冲区，跟进去：
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
      ...
    }

  ## 输出输出缓冲区 
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
             f->_IO_write_ptr - f->_IO_write_base);
  return (unsigned char) ch;
}
libc_hidden_ver (_IO_new_file_overflow, _IO_file_overflow)
```
可以看到`_IO_new_file_overflow`，首先判断`_flags`是否包含`_IO_NO_WRITES`，如果包含则直接返回，因此需构造`_flags`不包含`_IO_NO_WRITES`，其定义为`#define _IO_NO_WRITES 8`；

接着判断缓冲区是否为空以及是否包含`_IO_CURRENTLY_PUTTING`标志位，如果包含的话则做一些多余的操作，可能不可控，因此最好定义`_flags`不包含`_IO_CURRENTLY_PUTTING`，其定义为`#define _IO_CURRENTLY_PUTTING 0x800`。

接着调用`_IO_do_write`去输出输出缓冲区，其传入的参数是`f->_IO_write_base`，大小为`f->_IO_write_ptr - f->_IO_write_base`。因此若想实现任意地址读，应构造`_IO_write_base`为`read_start`，构造`_IO_write_ptr`为`read_end`。

跟进去`_IO_do_write`，看该函数的关键代码：
```c
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  ...
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    fp->_offset = _IO_pos_BAD;
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

  return count;
}
```
看到在调用`_IO_SYSWRITE`之前还判断了`fp->_IO_read_end != fp->_IO_write_base`，因此需要构造结构体使得`_IO_read_end`等于`_IO_write_base`。

也可以构造`_flags`包含`_IO_IS_APPENDING`，`_IO_IS_APPENDING`的定义为`#define _IO_IS_APPENDING 0x1000`，这样就不会走后面的这个判断而直接执行到`_IO_SYSWRITE`了，一般我都是设置`_IO_read_end`等于`_IO_write_base`。

最后`_IO_SYSWRITE`调用`write (f->_fileno, data, to_do)`输出数据，因此还需构造`_fileno`为标准输出描述符1。

将上述条件综合描述为：

1. 设置`_flag &~ _IO_NO_WRITES`即`_flag &~ 0x8`。
2. 设置`_flag & _IO_CURRENTLY_PUTTING`即`_flag | 0x800`
3. 设置`_fileno`为1。
4. 设置`_IO_write_base`指向想要泄露的地方；`_IO_write_ptr`指向泄露结束的地址。
5. 设置`_IO_read_end`等于`_IO_write_base`或设置`_flag & _IO_IS_APPENDING`即`_flag | 0x1000`。
6. 设置`_IO_write_end`等于`_IO_write_ptr`（非必须）。

 满足上述五个条件，可实现任意读。

### 实践

使用`stdout`进行任意读写比较经典的一题应该是hctf2018的`babyprintf_ver2`了，下面来进行利用描述。

题目直接给出了程序基址。

然后存在明显的溢出，可以覆盖`stdout`，但是无法覆盖`stdout`的vtable，因为它会修正。

具体该如何利用呢，首先使用`stdout`任意读来泄露libc地址。构造的FILE结构体如下（使用[pwn_debug](https://github.com/ray-cp/pwn_debug)的`IO_FILE_plus`模块）：
```c
io_stdout_struct=IO_FILE_plus()
flag=0
flag&=~8
flag|=0x800
flag|=0x8000
io_stdout_struct._flags=flag
io_stdout_struct._IO_write_base=pro_base+elf.got['read']
io_stdout_struct._IO_read_end=io_stdout_struct._IO_write_base
io_stdout_struct._IO_write_ptr=pro_base+elf.got['read']+8
io_stdout_struct._fileno=1
​```
以此来泄露read的地址。

接着使用`stdout`的任意地址写来写`__malloc_hook`，构造的FILE结构体如下：
​```c
io_stdout_struct=IO_FILE_plus()
flag=0
flag&=~8
flag|=0x8000
io_stdout_write=IO_FILE_plus()
io_stdout_write._flags=flag
io_stdout_write._IO_write_ptr=malloc_hook
io_stdout_write._IO_write_end=malloc_hook+8
```
最终将one gaget 写入`malloc_hook`。如何触发malloc呢，可以使用输出较大的字符打印来触发malloc函数或是`%n`来触发，其中`%n`可触发malloc的原因是在于`__readonly_area`会通过`fopen`打开`maps`文件来读取内容来判断地址段是否可写，而`fopen`会调用`malloc`函数申请空间，因此触发。

可能会有人对于觉得`flag|=0x8000`这行构造代码觉得比较奇怪，需要解释下，在`printf`函数中会调用`_IO_acquire_lock_clear_flags2 (stdout)`来获取`lock`从而继续程序，如果没有`_IO_USER_LOCK`标志的话，程序会一直在循环，而`_IO_USER_LOCK`定义为`#define _IO_USER_LOCK 0x8000`，因此需要设置`flag|=0x8000`才能够使exp顺利进行。`_IO_acquire_lock_clear_flags2 (stdout)`的汇编代码如下：
```c
0x7f0bcf15d850 <__printf_chk+96>     mov    rbp, qword ptr [rip + 0x2a16f9]
0x7f0bcf15d857 <__printf_chk+103>    mov    rbx, qword ptr [rbp]
0x7f0bcf15d85b <__printf_chk+107>    mov    eax, dword ptr [rbx]
0x7f0bcf15d85d <__printf_chk+109>    and    eax, 0x8000
0x7f0bcf15d862 <__printf_chk+114>    jne    __printf_chk+202 <0x7f0bcf15d8ba>
```

## 小结

使用IO FILE来进行任意内存读写真的是个很强大的功能，构造起来也比较容易。但是对于FILE结构体的伪造，个人感觉可能最容易出问题的地方还是`_flags`字段的构造，可能某个地方不注意就导致程序走偏了，因此感觉可能还是把默认的`stdout`和`stdin`直接拷贝出来用会比较好一些，同时`pwn_debug`的`IO_FILE_plus`模块提供了api`arbitrary_write_check`以及`arbitrary_read_check`来进行相应检测，看相应字段是否设置正确。

至此IO FILE系列描述完毕，前四篇对IO函数fopen、fread、fwrite以及fclose的源码分析；后面三篇介绍了针对IO FILE的相关利用，包括劫持vtable、vtable引入的check机制以及相应的后续利用方式。在整个过程中为方便构造IO 结构体还在`pwn_debug`中加入了`IO_FILE_plus`模块。

最后一句，阅读源码对于学习是一件很有帮助的事情。

相关文件及脚本[链接](https://github.com/ray-cp/pwn_category/tree/master/IO_FILE/arbitrary_read_write)

文章首发于[先知社区](https://xz.aliyun.com/t/5853)

##参考链接

1. [HCTF 2018 部分 PWN writeup--babyprinf_ver2](https://ray-cp.github.io/archivers/HCTF-2018-PWN-writeup#babyprintf_ver2)
2. [浅析IO_FILE结构及利用](https://xz.aliyun.com/t/3344#toc-1)
3. [教练！那根本不是IO！——从printf源码看libc的IO](https://www.anquanke.com/post/id/86945)