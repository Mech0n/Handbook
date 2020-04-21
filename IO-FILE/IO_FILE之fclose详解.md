---
layout: post
title:  "IO FILE之fclose详解"
date:   2019-06-27 08:00:00
categories: ctf
permalink: /archivers/IO_FILE_fclose_analysis
---

**欢迎关注公众号[平凡路上](https://mp.weixin.qq.com/s/TR-JuE2nl3W7ZmufAfpBZA)，平凡路上是一个致力于二进制漏洞分析与利用经验交流的公众号。**

这是本系列的第四篇文章，经过`fwrite`以及`fread`的分析，在进行fclose调试之前，已经知道IO FILE结构体包括两个堆结构，一个是保存IO FILE结构体的堆，一个是输入输出缓冲区的堆。对于fclose的分析，主要有两个关注点，一个是函数的流程，一个就是对于堆块的处理（何时释放，如何释放）。

传送门：

* [IO FILE之fopen详解](https://ray-cp.github.io/archivers/IO_FILE_fopen_analysis)
* [IO FILE之fread详解](https://ray-cp.github.io/archivers/IO_FILE_fread_analysis)
* [IO FILE之fwrite详解](https://ray-cp.github.io/archivers/IO_FILE_fwrite_analysis)

##总体概览

还是首先把fclose的总体的流程描述一遍，从fopen的流程中，我们知道了fopen主要是建立了FILE结构体以及将其链接进入了`_IO_list_all`链表中，同时fread或fwrite会建立输入输出缓冲区，所以在fclose时会对这些操作进行相应的释放。

`fclose`函数实现主要是在`_IO_new_fclose`函数中，大致可分为三步，基本上可以与`fopen`相对应：

1. 调用`_IO_un_link`将文件结构体从`_IO_list_all`链表中取下。
2. 调用`_IO_file_close_it`关闭文件并释放缓冲区。
3. 释放FILE内存以及确认文件关闭。

下面进行具体的源码分析。

## 源码分析

fclose的函数原型为：
```c
int close(int fd);

DESCRIPTION: close()  closes  a  file descriptor, so that it no longer refers to any file and may be reused.  Any record locks (see fcntl(2))  held  on  the file  it  was  associated  with,  and owned by the process, are removed (regardless of the file descriptor that was used to obtain the lock).
```
demo程序如下,仍然是使用带调试符号的glibc2.23对代码进行调试：
```c
#include<stdio.h>

int main(){
    char *data=malloc(0x1000);
    FILE*fp=fopen("test","wb"); 
    fwrite(data,1,0x60,fp);
    fclose(fp);
    return 0;
}

```

断点下在fclose函数。断下来以后以后，在调试之前将所需关注的内存结构先给出来，首先是此时的`_IO_list_all`的值为此时的IO FILE结构体：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-06-27-IO_FILE_fclose_analysis/1557803145061.png)
第二个是IO FILE结构体的值，其中需要留意的是经过`fwrite`的函数调用，此时输出缓冲区中是存在内容的，即`_IO_write_base`小于`_IO_write_ptr`：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-06-27-IO_FILE_fclose_analysis/1557803480555.png)


可以看到程序断在`_IO_new_fclose`函数，文件在`/libio/iofclose.c`中。可以看到`_IO_new_fclose`函数就是实现`fclose`的核心部分了：
```c
int
_IO_new_fclose (_IO_FILE *fp)
{
  int status;

  ... 
  
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);//将fp从_IO_list_all链表中取下

  ...
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);  //关闭文件，并释放缓冲区。
  ...
  _IO_FINISH (fp);  //确认FILE结构体从链表中删除以及缓冲区被释放
  ...
  if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
    {
      fp->_IO_file_flags = 0;
      free(fp);
    }

  return status;
}
```
和fopen一样，代码的核心部分也比较少。


### _IO_un_link将结构体从_IO_list_all链表中取下

第一部分，调用`_IO_un_link`函数将IO FILE结构体从`_IO_list_all`链表中取下，跟进去该函数，函数在`/libio/genops.c`中：
```c
void
_IO_un_link (struct _IO_FILE_plus *fp)
{
  if (fp->file._flags & _IO_LINKED) // 检查标志位
    {
      ...
      if (_IO_list_all == NULL) // 判断_IO_list_all是否为空
  ;
      else if (fp == _IO_list_all) // fp为链表的头
  {
    _IO_list_all = (struct _IO_FILE_plus *) _IO_list_all->file._chain;
    ++_IO_list_all_stamp;
  }
      else    // fp为链表中间节点
  for (f = &_IO_list_all->file._chain; *f; f = &(*f)->_chain)
    if (*f == (_IO_FILE *) fp)
      {
        *f = fp->file._chain;
        ++_IO_list_all_stamp;
        break;
      }
      fp->file._flags &= ~_IO_LINKED; //修改标志位
      ...
      }
}
libc_hidden_def (_IO_un_link)
```
函数先检查标志位是否包含`_IO_LINKED`标志，该标志的定义是`#define _IO_LINKED 0x80`，表示该结构体是否被链接到了`_IO_list_all`链表中。

如果没有`_IO_LINKED`标志（不在`_IO_list_all`链表中）或者`_IO_list_all`链表为空，则直接返回。

否则的话即表示结构体为`_IO_list_all`链表中某个节点，所要做的就是将这个节点取下来，接下来就是单链表的删除节点的操作，首先判断是不是`_IO_list_all`链表头，如果是的话直接将`_IO_list_all`指向`_IO_list_all->file._chain`就好了，如果不是链表头则遍历链表，找到该结构体，再将其取下。

最后返回之前设置`file._flags`为`~_IO_LINKED`表示该结构体不在`_IO_list_all`链表中。

经过了这个函数，此时IO FILE已从`_IO_list_all`链表取下，此时的`_IO_list_all`中的值为：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-06-27-IO_FILE_fclose_analysis/1557803801638.png)

### _IO_file_close_it关闭文件并释放缓冲区


第二部分就是调用`_IO_file_close_it`关闭文件，释放缓冲区，并清空缓冲区指针。跟进去该函数，文件在`/libio/fileops.c`中：
```c
int
_IO_new_file_close_it (_IO_FILE *fp)
{
  int write_status;
  if (!_IO_file_is_open (fp))
    return EOF;
    
  if ((fp->_flags & _IO_NO_WRITES) == 0
      && (fp->_flags & _IO_CURRENTLY_PUTTING) != 0)
    write_status = _IO_do_flush (fp); //刷新输出缓冲区
 ...
  int close_status = ((fp->_flags2 & _IO_FLAGS2_NOCLOSE) == 0
          ? _IO_SYSCLOSE (fp) : 0); //调用vtable __close关闭文件

  ...
  //释放输入输出缓冲区以及设置指针。
  /* Free buffer. */
  _IO_setb (fp, NULL, NULL, 0); //设置base指针，并释放缓冲区
  _IO_setg (fp, NULL, NULL, NULL); //置零输入缓冲区
  _IO_setp (fp, NULL, NULL);  //置零输出缓冲区

  //确保结构体已从_IO_list_all中取下
  _IO_un_link ((struct _IO_FILE_plus *) fp);
  fp->_flags = _IO_MAGIC|CLOSED_FILEBUF_FLAGS;
  fp->_fileno = -1;  //设置文件描述符为-1
  fp->_offset = _IO_pos_BAD;

  return close_status ? close_status : write_status;
}
libc_hidden_ver (_IO_new_file_close_it, _IO_file_close_it)
```
这个函数也做了很多事情，首先是调用`_IO_file_is_open`宏检查该文件是否处于打开的状态，宏的定义为`#define _IO_file_is_open(__fp) ((__fp)->_fileno != -1)`，只是简单的判断`_fileno`。

接着判断是不是输出缓冲区，如果是的话，则调用`_IO_do_flush`刷新此时的输出缓冲区，`_IO_do_flush`也是一个宏定义：
```c
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
# define _IO_do_flush(_f) \
  ((_f)->_mode <= 0                   \
   ? _IO_do_write(_f, (_f)->_IO_write_base,             \
      (_f)->_IO_write_ptr-(_f)->_IO_write_base)         \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,          \
       ((_f)->_wide_data->_IO_write_ptr           \
        - (_f)->_wide_data->_IO_write_base)))
```
可以看到它对应的是调用`_IO_do_write`函数去输出此时的输出缓冲区，`_IO_do_write`函数已经在`fwrite`这篇文章中跟过了，主要的作用就是调用系统调用输出缓冲区，并刷新输出缓冲区的值。经过`_IO_do_write`函数，缓冲区中的内容已被输出到相应文件中，并且此时的指针已经刷新：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-06-27-IO_FILE_fclose_analysis/1557805431547.png)
回到`_IO_new_file_close_it`函数中，可以看到在调用了`_IO_do_flush`后，代码调用了`_IO_SYSCLOSE`函数，该函数是vtable中的`__close`函数，跟进去该函数，在`libio/fileops.c`中：
```c
int
_IO_file_close (_IO_FILE *fp)
{
  /* Cancelling close should be avoided if possible since it leaves an
     unrecoverable state behind.  */
  return close_not_cancel (fp->_fileno);
}
libc_hidden_def (_IO_file_close)
```
`close_not_cancel`的定义为`#define close_not_cancel(fd) \  __close (fd)`该函数直接调用了系统调用`close`关闭文件描述符。

在调用了`_IO_SYSCLOSE`函数关闭文件描述符后，`_IO_new_file_close_it`函数开始释放输入输出缓冲区并置零输入输出缓冲区。一口气调用了`_IO_setb`、` _IO_setg`、`_IO_setp`三个函数，这三个函数在缓冲区建立的时候都看过了，`_IO_setb`是设置结构体的buf指针，` _IO_setg`是设置read相关的指针，`_IO_setp`是设置write相关的指针，在这里还需要重新看下`_IO_setb`函数，因为在这个函数里还释放了缓冲区，函数在`libio/genops.c`中：
```c
void
_IO_setb (_IO_FILE *f, char *b, char *eb, int a)
{
  if (f->_IO_buf_base && !(f->_flags & _IO_USER_BUF))
    free (f->_IO_buf_base); //释放缓冲区
  f->_IO_buf_base = b;
  f->_IO_buf_end = eb;
  if (a)
    f->_flags &= ~_IO_USER_BUF;
  else
    f->_flags |= _IO_USER_BUF;
}
libc_hidden_def (_IO_setb)
```
可以看到在`_IO_setb`释放的缓冲区，并置零了buf指针。找到了释放缓冲区的地方了，之前看fread和fwrite的时候都没注意到这里。执行完这一段之后，指针被清零了：
![Alt text](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2019-06-27-IO_FILE_fclose_analysis/1557815677408.png)

继续往下看，其调用了`_IO_un_link`函数，确保结构体从`_IO_list_all`链表中取了下来。然后将文件描述符设置为`-1`。

### 释放FILE内存以及确认文件关闭

结束`_IO_file_close_it`函数后，程序回到`_IO_new_fclose`中，开始第三部分代码，调用`_IO_FINISH`进行最后的确认，跟进去该函数，该函数是vtable中的`__finish`函数，在`/libio/fileops.c`中：
```
void
_IO_new_file_finish (_IO_FILE *fp, int dummy)
{
  if (_IO_file_is_open (fp))
    {
      _IO_do_flush (fp);
      if (!(fp->_flags & _IO_DELETE_DONT_CLOSE))
  _IO_SYSCLOSE (fp);
    }
  _IO_default_finish (fp, 0);
}
libc_hidden_ver (_IO_new_file_finish, _IO_file_finish)
```
可以看到代码首先检查了文件描述符是否打开，在第二步中已经将其设置为-1，所以不会进入该流程。如果文件打开的话则会调用`_IO_do_flush`和`_IO_SYSCLOSE`刷新缓冲区以及关闭文件。

接着调用`_IO_default_finish`确认缓冲区确实被释放，以及结构体从`_IO_list_all`中取了下来，并设置指针，函数源码在`libio/genops.c`中：
```
void
_IO_default_finish (_IO_FILE *fp, int dummy)
{
  struct _IO_marker *mark;
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    {
      free (fp->_IO_buf_base);
      fp->_IO_buf_base = fp->_IO_buf_end = NULL;
    }

  for (mark = fp->_markers; mark != NULL; mark = mark->_next)
    mark->_sbuf = NULL;

  if (fp->_IO_save_base)
    {
      free (fp->_IO_save_base);
      fp->_IO_save_base = NULL;
    }

  _IO_un_link ((struct _IO_FILE_plus *) fp);
}
libc_hidden_def (_IO_default_finish)
```
感觉`_IO_FINISH`函数并没有做什么操作，都是之前已经进行过的，有些冗余。

程序回到`_IO_new_fclose`中，到此时已经将结构体从链表中删除，刷新了缓冲区，释放了缓冲区内存，只剩下结构体内存尚未释放，因此代码也剩下最后一段代码，即调用`free`释放结构体内存。

到此，源码分析结束。

## 小结

分析完成后，回头看fclose函数的功能，主要就是刷新输出缓冲区并释放缓冲区内存、释放结构体内存。仍然总结下调用了vtable中的函数：

* 在清空缓冲区的`_IO_do_write`函数中会调用vtable中的函数。
* 关闭文件描述符`_IO_SYSCLOSE`函数为vtable中的`__close`函数。
* `_IO_FINISH`函数为vtable中的`__finish`函数。

fclose函数分析完成后，对于IO FILE源码分析的主体部分就完成了，后续会进入利用的部分。主要包括通过虚表的劫持来控制程序流、vtable的检查以及绕过、通过结构体的指针实现内存读写等技巧。


文章首发于[先知](https://xz.aliyun.com/t/5445)社区















