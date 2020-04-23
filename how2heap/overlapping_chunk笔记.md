# how2heap总结系列三

一月 20, 2020

> 接上一篇的unink,继续复习计划

# 参考网站

```
https://ctf-wiki.github.io/ctf-wiki/
```

# 0x0 overlapping_chunk

## 序

overlapping在平常算是最常用的技巧了,几乎每一道题都需要构造overlap

而提到overlapping就不得不说chunk shrink和chunk extend了,其实这两个都是依靠更改chunk的pre_size域和size域来欺骗ptmalloc的

详情可见,[文章一](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/chunk_extend_overlapping-zh/#4extendoverlapping),[文章二](https://nightrainy.github.io/2019/07/25/chunk-extend-and-overlapping/)

好了,回过来,我们继续看本例

## 源代码

我们还是先看源代码吧,同样的,我删了写东西并加了一小点翻译(雾

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int argc , char* argv[]){
        intptr_t *p1,*p2,*p3,*p4;

        p1 = malloc(0x100 - 8);
        p2 = malloc(0x100 - 8);
        p3 = malloc(0x80 - 8);

        fprintf(stderr, "The 3 chunks have been allocated here:\np1=%p\np2=%p\np3=%p\n", p1, p2, p3);

        memset(p1, '1', 0x100 - 8);
        memset(p2, '2', 0x100 - 8);
        memset(p3, '3', 0x80 - 8);

        free(p2);
        // p2现在在unsorted bin中,时刻准备为新的malloc服务
        fprintf(stderr, "The chunk p2 is now in the unsorted bin ready to serve possible\nnew malloc() of its size\n");                   

        // 现在模拟一下溢出来覆写p2的size                                                                               
        fprintf(stderr, "Now let's simulate an overflow that can overwrite the size of the\nchunk freed p2.\n");     
        
        //对实例程序而言,最后三个字节是什么并不重要,然而,我们最好还是维持一下堆的稳定性
        fprintf(stderr, "For a toy program, the value of the last 3 bits is unimportant;"
                " however, it is best to maintain the stability of the heap.\n");

        //为了维持堆的稳定性,我们还是要把prev_inuse标志位设位1来确保我们的p1不会被错误的认为是一个free chunk
        fprintf(stderr, "To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse),"
                " to assure that p1 is not mistaken for a free chunk.\n");

        int evil_chunk_size = 0x181;
        int evil_region_size = 0x180 - 8;
        fprintf(stderr, "We are going to set the size of chunk p2 to to %d, which gives us\na region size of %d\n",                                                                                                                       evil_chunk_size, evil_region_size);

        *(p2-1) = evil_chunk_size; // we are overwriting the "size" field of chunk p2

        //现在我们分配一个和p2被注入的size一样的大小的chunk
        fprintf(stderr, "\nNow let's allocate another chunk with a size equal to the data\n"
               "size of the chunk p2 injected size\n");

        这次的malloc将会从我们刚刚修改过size的unsoted bin中取出free chunk
        fprintf(stderr, "This malloc will be served from the previously freed chunk that\n"
               "is parked in the unsorted bin which size has been modified by us\n");
        p4 = malloc(evil_region_size);

        fprintf(stderr, "\np4 has been allocated at %p and ends at %p\n", (char *)p4, (char *)p4+evil_region_size);
        fprintf(stderr, "p3 starts at %p and ends at %p\n", (char *)p3, (char *)p3+0x80-8);
        fprintf(stderr, "p4 should overlap with p3, in this case p4 includes all p3.\n");

        //现在我们写进p4的内容就可以覆盖p3啦,同时,我们写到p3里的内容也可以修改p4的内容
        fprintf(stderr, "\nNow everything copied inside chunk p4 can overwrites data on\nchunk p3,"
                " and data written to chunk p3 can overwrite data\nstored in the p4 chunk.\n\n");

        fprintf(stderr, "Let's run through an example. Right now, we have:\n");
        fprintf(stderr, "p4 = %s\n", (char *)p4);
        fprintf(stderr, "p3 = %s\n", (char *)p3);

        fprintf(stderr, "\nIf we memset(p4, '4', %d), we have:\n", evil_region_size);
        memset(p4, '4', evil_region_size);
        fprintf(stderr, "p4 = %s\n", (char *)p4);
        fprintf(stderr, "p3 = %s\n", (char *)p3);

        fprintf(stderr, "\nAnd if we then memset(p3, '3', 80), we have:\n");
        memset(p3, '3', 80);
        fprintf(stderr, "p4 = %s\n", (char *)p4);
        fprintf(stderr, "p3 = %s\n", (char *)p3);
}
```

## 运行结果

```shell
This is a simple chunks overlapping problem

Let's start to allocate 3 chunks on the heap
The 3 chunks have been allocated here:
p1=0x7aa010
p2=0x7aa110
p3=0x7aa210

Now let's free the chunk p2
The chunk p2 is now in the unsorted bin ready to serve possible
new malloc() of its size
Now let's simulate an overflow that can overwrite the size of the
chunk freed p2.
For a toy program, the value of the last 3 bits is unimportant; however, it is best to maintain the stability of the heap.
To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse), to assure that p1 is not mistaken for a free chunk.
We are going to set the size of chunk p2 to to 385, which gives us
a region size of 376

Now let's allocate another chunk with a size equal to the data
size of the chunk p2 injected size
This malloc will be served from the previously freed chunk that
is parked in the unsorted bin which size has been modified by us

p4 has been allocated at 0x7aa110 and ends at 0x7aa288
p3 starts at 0x7aa210 and ends at 0x7aa288
p4 should overlap with p3, in this case p4 includes all p3.

Now everything copied inside chunk p4 can overwrites data on
chunk p3, and data written to chunk p3 can overwrite data
stored in the p4 chunk.

Let's run through an example. Right now, we have:
p4 = xK<5       
3 = 333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333

If we memset(p4, '4', 376), we have:
p4 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444
3 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444

And if we then memset(p3, '3', 80), we have:
p4 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444333333333333333333333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444
3 = 333333333333333333333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444
```

## 调试

因为程序比较简单,我这里就仅作几个断点来调试本例

```shell
► 24   p3 = malloc(0x80 - 8);

  28   memset(p1, '1', 0x100 - 8);
  29   memset(p2, '2', 0x100 - 8);
  30   memset(p3, '3', 0x80 - 8);
  31
► 32   fprintf(stderr, "\nNow let's free the chunk p2\n");

  33   free(p2);
► 34   fprintf(stderr, "The chunk p2 is now in the unsorted bin ready to serve possible\nnew malloc() of its size\n");

  47   *(p2-1) = evil_chunk_size; // we are overwriting the "size" field of chunk p2
  48
► 49   fprintf(stderr, "\nNow let's allocate another chunk with a size equal to the data\n"

  53   p4 = malloc(evil_region_size);
  54
► 55   fprintf(stderr, "\np4 has been allocated at %p and ends at %p\n", (char *)p4, (char *)p4+evil_region_size);

► 67   memset(p4, '4', evil_region_size);

  71   fprintf(stderr, "\nAnd if we then memset(p3, '3', 80), we have:\n");
► 72   memset(p3, '3', 80);

► 72   memset(p3, '3', 80);
  73   fprintf(stderr, "p4 = %s\n", (char *)p4);
  74   fprintf(stderr, "p3 = %s\n", (char *)p3);
```

好了,先malloc3个chunk,p1,p2,p3,此时的堆

```shell
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0,
  size = 257,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x603100 PREV_INUSE {
  prev_size = 0,
  size = 257,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x603200 FASTBIN {
  prev_size = 0,
  size = 129,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x603280 PREV_INUSE {
  prev_size = 0,
  size = 134529,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
```

然后给三个chunk赋初值

```shell
pwndbg> x/10gx p1
0x603010:       0x3131313131313131      0x3131313131313131
0x603020:       0x3131313131313131      0x3131313131313131
0x603030:       0x3131313131313131      0x3131313131313131
0x603040:       0x3131313131313131      0x3131313131313131
0x603050:       0x3131313131313131      0x3131313131313131
pwndbg> x/10gx p2
0x603110:       0x3232323232323232      0x3232323232323232
0x603120:       0x3232323232323232      0x3232323232323232
0x603130:       0x3232323232323232      0x3232323232323232
0x603140:       0x3232323232323232      0x3232323232323232
0x603150:       0x3232323232323232      0x3232323232323232
pwndbg> x/10gx p3
0x603210:       0x3333333333333333      0x3333333333333333
0x603220:       0x3333333333333333      0x3333333333333333
0x603230:       0x3333333333333333      0x3333333333333333
0x603240:       0x3333333333333333      0x3333333333333333
0x603250:       0x3333333333333333      0x3333333333333333
```

这些都没啥好看的,我们直接往下走,此时我们free掉了chunk2,chunk2被放进了unsorted bin中

```shell
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x603100 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x603100
smallbins
empty
largebins
empty
pwndbg>
```

紧接着我们假设我们溢出了chunk1,成功修改了chunk2的size为0x181

```shell
pwndbg> x/10gx 0x603100
0x603100:       0x3131313131313131      0x0000000000000181
0x603110:       0x00007ffff7dd1b78      0x00007ffff7dd1b78
0x603120:       0x3232323232323232      0x3232323232323232
0x603130:       0x3232323232323232      0x3232323232323232
0x603140:       0x3232323232323232      0x3232323232323232
```

之后程序malloc了p4,此时的堆

```shell
0x603000 PREV_INUSE {
  prev_size = 0,
  size = 257,
  fd = 0x3131313131313131,
  bk = 0x3131313131313131,
  fd_nextsize = 0x3131313131313131,
  bk_nextsize = 0x3131313131313131
}
0x603100 PREV_INUSE {
  prev_size = 3544668469065756977,
  size = 385,
  fd = 0x7ffff7dd1b78 <main_arena+88>,
  bk = 0x7ffff7dd1b78 <main_arena+88>,
  fd_nextsize = 0x3232323232323232,
  bk_nextsize = 0x3232323232323232
}
0x603280 PREV_INUSE {
  prev_size = 3689348814741910323,
  size = 134529,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
```



可以看到我们0x603100也就是p4的size是0x181,此时的p3,p4分别在

```shell
pwndbg> p/x p3
$1 = 0x603210
pwndbg> p/x p4
$2 = 0x603110
```

而这又意味这什么呢?

我们回想一下,p3的大小是0x100,而p4的大小为0x181,而这两个只相差0x100

```shell
pwndbg> p/x 0x603210-0x603110
$3 = 0x100
```

这样我们就成功的构造了overlapping,也就是说,我们的p4将整个p3都包了进去

## 总结

程序先是malloc了2个0x100大小的chunk,p1,p2,和一个大小为0x80的chunk,p3

紧接着,程序初始化了三个chunk,里面的值分别为1,2,3

之后程序free掉了p2,并假设拥有溢出的能力,通过溢出p1修改了p2的size域

此时p2的size是0x181,系统会认为我们有一个大小为0x180的在unsorted bin中的fake chunk

紧接着,我们再申请了一个大小为0x180的chunk p4,这样系统就会把我们unsorted bin中的free chunk也就是我们构造好的大小为0x180的fake chunk拿出来给p4

此时p4的后0x80的空间就和p3共享了,这就构成了overlapping_chunk! 堆重叠

# overlapping_chunks_2

这里是overlapping的第二个,我们先看看源代码吧

## 源代码

我删除了一些无关语句,并加了一些注释(理解不对的地方多包涵2333

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main(){

  intptr_t *p1,*p2,*p3,*p4,*p5,*p6;
  unsigned int real_size_p1,real_size_p2,real_size_p3,real_size_p4,real_size_p5,real_size_p6;
  int prev_in_use = 0x1;

  //这个也被称为不相邻的free chunk conslidation 攻击(这里就不强翻了,没呢味儿
  fprintf(stderr, "\nThis is also referenced as Nonadjacent Free Chunk Consolidation Attack\n");
  fprintf(stderr, "\nLet's start to allocate 5 chunks on the heap:");

  p1 = malloc(1000);
  p2 = malloc(1000);
  p3 = malloc(1000);
  p4 = malloc(1000);
  p5 = malloc(1000);

  //malloc_usable_size函数可以获取chunk实际分配的内存大小
  real_size_p1 = malloc_usable_size(p1);
  real_size_p2 = malloc_usable_size(p2);
  real_size_p3 = malloc_usable_size(p3);
  real_size_p4 = malloc_usable_size(p4);
  real_size_p5 = malloc_usable_size(p5);

  fprintf(stderr, "\n\nchunk p1 from %p to %p", p1, (unsigned char *)p1+malloc_usable_size(p1));
  fprintf(stderr, "\nchunk p2 from %p to %p", p2,  (unsigned char *)p2+malloc_usable_size(p2));
  fprintf(stderr, "\nchunk p3 from %p to %p", p3,  (unsigned char *)p3+malloc_usable_size(p3));
  fprintf(stderr, "\nchunk p4 from %p to %p", p4, (unsigned char *)p4+malloc_usable_size(p4));
  fprintf(stderr, "\nchunk p5 from %p to %p\n", p5,  (unsigned char *)p5+malloc_usable_size(p5));

  //为了便于看攻击效果,所以五个chunk分别为A,B,C,D,E
  memset(p1,'A',real_size_p1);
  memset(p2,'B',real_size_p2);
  memset(p3,'C',real_size_p3);
  memset(p4,'D',real_size_p4);
  memset(p5,'E',real_size_p5);

  //我们现在Free一下p4,在有p5邻接top chunk的情况下,我们释放p4不会引起p4与top chunk的合并
  fprintf(stderr, "\nLet's free the chunk p4.\nIn this case this isn't coealesced with top chunk since we have p5 bordering top chunk after p4\n");

  free(p4);

  //现在我们通过溢出chunk p1将chunk p2的size改成p2+p3的大小并且将标注为设为正在使用来触发漏洞
  fprintf(stderr, "\nLet's trigger the vulnerability on chunk p1 that overwrites the size of the in use chunk p2\nwith the size of chunk_p2 + size of chunk_p3\n");

  *(unsigned int *)((unsigned char *)p1 + real_size_p1 ) = real_size_p2 + real_size_p3 + prev_in_use + sizeof(size_t) * 2; //<--- BUG HERE

  现在我们再free p2,这个时候ptmalloc就会认为下一个chunk是p4(p2的size已经被我们更改为p2+p3的大小了
  fprintf(stderr, "\nNow during the free() operation on p2, the allocator is fooled to think that \nthe nextchunk is p4 ( since p2 + size_p2 now point to p4 ) \n");
  
  //这样就会创建一个大的错误包含p3的free chunk
  fprintf(stderr, "\nThis operation will basically create a big free chunk that wrongly includes p3\n");
  free(p2);

  //现在我们再创建一个新的大小正好是我们创建的fake free chunk的新chunk
  fprintf(stderr, "\nNow let's allocate a new chunk with a size that can be satisfied by the previously freed chunk\n");

  p6 = malloc(2000);
  real_size_p6 = malloc_usable_size(p6);

  fprintf(stderr, "\nOur malloc() has been satisfied by our crafted big free chunk, now p6 and p3 are overlapping and \nwe can overwrite data in p3 by writing on chunk p6\n");
  fprintf(stderr, "\nchunk p6 from %p to %p", p6,  (unsigned char *)p6+real_size_p6);
  fprintf(stderr, "\nchunk p3 from %p to %p\n", p3, (unsigned char *) p3+real_size_p3);

  fprintf(stderr, "\nData inside chunk p3: \n\n");
  fprintf(stderr, "%s\n",(char *)p3);

  fprintf(stderr, "\nLet's write something inside p6\n");
  memset(p6,'F',1500);

  fprintf(stderr, "\nData inside chunk p3: \n\n");
  fprintf(stderr, "%s\n",(char *)p3);


}
```

## 程序运行结果

```shell
chunk p1 from 0x220f010 to 0x220f3f8
chunk p2 from 0x220f400 to 0x220f7e8
chunk p3 from 0x220f7f0 to 0x220fbd8
chunk p4 from 0x220fbe0 to 0x220ffc8
chunk p5 from 0x220ffd0 to 0x22103b8

Let's free the chunk p4.
In this case this isn't coealesced with top chunk since we have p5 bordering top chunk after p4

Let's trigger the vulnerability on chunk p1 that overwrites the size of the in use chunk p2
with the size of chunk_p2 + size of chunk_p3

Now during the free() operation on p2, the allocator is fooled to think that
the nextchunk is p4 ( since p2 + size_p2 now point to p4 )

This operation will basically create a big free chunk that wrongly includes p3

Now let's allocate a new chunk with a size that can be satisfied by the previously freed chunk

Our malloc() has been satisfied by our crafted big free chunk, now p6 and p3 are overlapping and
we can overwrite data in p3 by writing on chunk p6

chunk p6 from 0x220f400 to 0x220fbd8
chunk p3 from 0x220f7f0 to 0x220fbd8

Data inside chunk p3:

CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC

Let's write something inside p6

Data inside chunk p3:

FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```

## 关键部分调试

因为和之前的很类似,这里我仅下几个断点

```shell
  28   p2 = malloc(1000);
  29   p3 = malloc(1000);
  30   p4 = malloc(1000);
  31   p5 = malloc(1000);
  32
► 33   real_size_p1 = malloc_usable_size(p1);

  53   free(p4);
  54
► 55   fprintf(stderr, "\nLet's trigger the vulnerability on chunk p1 that overwrites the size of the in use chunk p2\nwith the size of chunk_p2 + size of chunk_p3\n");

  57   *(unsigned int *)((unsigned char *)p1 + real_size_p1 ) = real_size_p2 + real_size_p3 + prev_in_use + sizeof(size_t) * 2; //<--- BUG HERE
  58
► 59   fprintf(stderr, "\nNow during the free() operation on p2, the allocator is fooled to think that \nthe nextchunk is p4 ( since p2 + size_p2 now point to p4 ) \n");
  
  61   free(p2);
  62
► 63   fprintf(stderr, "\nNow let's allocate a new chunk with a size that can be satisfied by the previously freed chunk\n");

  65   p6 = malloc(2000);
► 66   real_size_p6 = malloc_usable_size(p6);
```

好了我们先运行一下分配下5个chunk

```shell
 pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0,
  size = 1009,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x6033f0 PREV_INUSE {
  prev_size = 0,
  size = 1009,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x6037e0 PREV_INUSE {
  prev_size = 0,
  size = 1009,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x603bd0 PREV_INUSE {
  prev_size = 0,
  size = 1009,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x603fc0 PREV_INUSE {
  prev_size = 0,
  size = 1009,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x6043b0 PREV_INUSE {
  prev_size = 0,
  size = 130129,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
pwndbg>
```

可以看到已经分配了5个堆块p1,p2,p3,p4,p5

分别从0x603000,0x6033f0,0x6037e0,0x603bd0,0x603fc0,0x6043b0处开始

然后我们继续运行一下,free掉p2,此时

```shell
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x603bd0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x603bd0
smallbins
empty
largebins
empty
```

此时的chunk p2

```shell
pwndbg> x/10gx 0x6033f0
0x6033f0:       0x4141414141414141      0x00000000000003f1
0x603400:       0x4242424242424242      0x4242424242424242
0x603410:       0x4242424242424242      0x4242424242424242
0x603420:       0x4242424242424242      0x4242424242424242
0x603430:       0x4242424242424242      0x4242424242424242
pwndbg> p/x 0x3f1
$4 = 0x3f1
pwndbg> p 0x3f1
$5 = 1009
```

可以看到其size此时为0x3f1,而pre_size为chunk1所复用,紧接着我们继续,程序现在已经更改了chunk p2的size域

```shell
pwndbg> x/10gx 0x6033f0
0x6033f0:       0x4141414141414141      0x00000000000007e1
0x603400:       0x4242424242424242      0x4242424242424242
0x603410:       0x4242424242424242      0x4242424242424242
0x603420:       0x4242424242424242      0x4242424242424242
0x603430:       0x4242424242424242      0x4242424242424242
pwndbg>
```

好了,现在我们free掉chunk2并malloc一个新的chunk p6

```shell
0x6033f0 PREV_INUSE {
  prev_size = 4702111234474983745,
  size = 2017,
  fd = 0x7ffff7dd2158 <main_arena+1592>,
  bk = 0x7ffff7dd2158 <main_arena+1592>,
  fd_nextsize = 0x6033f0,
  bk_nextsize = 0x6033f0
}
```

此时的p6 size大小为2017,我们看下

```shell
pwndbg> p p6
$8 = (intptr_t *) 0x603400
pwndbg> p p3
$9 = (intptr_t *) 0x6037f0
pwndbg> p/x 2017
$10 = 0x7e1
pwndbg> p p6+0x7e1
$11 = (intptr_t *) 0x607308
```

此时的p3已经成功被包在p6中了:)

## 总结

好了,程序首先malloc了5块大小为1008的chunk,p1,p2,p3,p4,p5

紧接着,程序free掉了p4,因为还有p5 紧邻着top chunk,因此p4并不会被合并到topchunk中

**这里要注意,在本例中,是否free p4的效果是一样的**

之后呢,为便于直观的看一下效果,将chunk按次序填满了A,B,C,D,E

紧接着,程序修改了chunk p2的size域大小为p2+p3,然后free掉了chunk p2

这个时候,系统会错误的把p2和p3合并的大chunk放进unsorted bin中并与我们的free chunk p4合并

然后申请了p2+p3大小的新chunk p6(所以我说其实不用free p4的…甚至都不用malloc p5 2333

此时p6的后半部分也就是p3大小的部分就与之前未free的p3重叠了:)

这里也做一下overlapping_chunks和overlapping_chunks_2的比较

overlapping_chunks中,程序更改了已经释放掉的chunk的size域而2则是修改了还未释放的chunk的size域,但是效果都是一样的,都是构造了一个重叠块 (overlapping chunk!

文章首发于安全客，转载请著名出处，文章链接https://www.anquanke.com/post/id/197583

查看评论