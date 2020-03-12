# tcache 学习笔记

记录一下glib-2.26之后的tcache机制，笔记可能会杂乱无章。

### 0x10 较之前的改变

增加了两个结构体

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;


typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread char tcache_shutting_down = 0;
static __thread tcache_perthread_struct *tcache = NULL;
```

两个重要函数：

```c
static void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

static void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```

相关宏定义：

```c
# define TCACHE_MAX_BINS		64
# define MAX_TCACHE_SIZE	tidx2usize (TCACHE_MAX_BINS-1)

/* Only used to pre-fill the tunables.  */
# define tidx2usize(idx)	(((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */

/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7
```

`tcache_entry`是`tcache_pthread_struct`中的单链表指针。

`tcache_pthread_struct`中每个指针代表一个`bin`，每个`bin`的最大容量为$7$，

另外，`tcache_pthread_struct`链表结点结构体很简单，就是一个`next`指针指向链表中下一个堆块（的用户数据区）；然后定义了一个线程的完整tcache结构体，由两部分组成，第一部分是计数表，记录了$64$个tcache链表中每个链表内已有的堆块个数$(0-7)$，第二部分是入口表，用来记录$64$个tcache链表中每条链表的入口地址（即链表中第一个堆块的用户区地址）；最后一行则是初始化了一个线程的tcache，存储在堆空间起始处的tcache在这一步后就完成了分配，由于tcache本身也在堆区故也是一个大chunk，因此其大小是`size_chunkhead + size_counts + size_entries = 16 + 64 + 64*8 = 592 = 0x250​`

因此在libc2.26及以后的版本中，堆空间起始部分都会有一块先于用户申请分配的堆空间，大小为`0x250`，这就是tcache`（0x000-0x24F）`，也就是说用户申请第一块堆内存的起始地址的最低位字节是`0x50`。

2.29之后又加入了些许改变：修改了对double free的检查：

```c
index 6d7a6a8..f730d7a 100644 (file)
--- a/malloc/malloc.c
+++ b/malloc/malloc.c
@@ -2967,6 +2967,8 @@ mremap_chunk (mchunkptr p, size_t new_size)
 typedef struct tcache_entry
 {
   struct tcache_entry *next;
+  /* This field exists to detect double frees.  */
+  struct tcache_perthread_struct *key;
 } tcache_entry;

 /* There is one of these for each thread, which contains the
@@ -2990,6 +2992,11 @@ tcache_put (mchunkptr chunk, size_t tc_idx)
 {
   tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
   assert (tc_idx < TCACHE_MAX_BINS);
+
+  /* Mark this chunk as "in the tcache" so the test in _int_free will
+     detect a double free.  */
+  e->key = tcache;
+
   e->next = tcache->entries[tc_idx];
   tcache->entries[tc_idx] = e;
   ++(tcache->counts[tc_idx]);
@@ -3005,6 +3012,7 @@ tcache_get (size_t tc_idx)
   assert (tcache->entries[tc_idx] > 0);
   tcache->entries[tc_idx] = e->next;
   --(tcache->counts[tc_idx]);
+  e->key = NULL;
   return (void *) e;
 }

@@ -4218,6 +4226,26 @@ _int_free (mstate av, mchunkptr p, int have_lock)
   {
     size_t tc_idx = csize2tidx (size);

+    /* Check to see if it's already in the tcache.  */
+    tcache_entry *e = (tcache_entry *) chunk2mem (p);
+
+    /* This test succeeds on double free.  However, we don't 100%
+       trust it (it also matches random payload data at a 1 in
+       2^<size_t> chance), so verify it's not an unlikely coincidence
+       before aborting.  */
+    if (__glibc_unlikely (e->key == tcache && tcache))
+      {
+       tcache_entry *tmp;
+       LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
+       for (tmp = tcache->entries[tc_idx];
+            tmp;
+            tmp = tmp->next)
+         if (tmp == e)
+           malloc_printerr ("free(): double free detected in tcache 2");
+       /* If we get here, it was a coincidence.  We've wasted a few
+          cycles, but don't abort.  */
+      }
+
     if (tcache
        && tc_idx < mp_.tcache_bins
        && tcache->counts[tc_idx] < mp_.tcache_count)
```

在这里还给`tcache_entry`添加了一个变量`key`,在bk指针的位置。

### 0x20 _int_malloc部分的改变

在内存分配的 malloc 函数中有多处，会将内存块移入 tcache 中。

- 首先，申请的内存块符合 **fastbin** 大小时并且在 fastbin 内找到可用的空闲块时，会把该 fastbin 链上的其他内存块放入 tcache 中。
- 其次，申请的内存块符合 **smallbin** 大小时并且在 smallbin 内找到可用的空闲块时，会把该 smallbin 链上的其他内存块放入 tcache 中。
- 当在 **unsorted bin** 链上循环处理时，当找到大小合适的链时，并不直接返回，而是先放到 tcache 中，继续处理。

具体的请查阅[Tcache Attack](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/tcache_attack-zh/#0x02-tcache-usage)和[Pwn Heap With Tcache](https://www.secpulse.com/archives/71958.html)

### 0x30 free相关

在free函数的最先处理部分，首先是检查释放块是否页对齐及前后堆块的释放情况，便优先放入tcache结构中。

### 0x40 位置

tcache存储在堆区：tcache的位置位于堆区的起始处，一共有64个链表，这64个链表的索引结点（也就是链首结点用于存放链表中第一个堆块地址的结点）依次存放在堆区起始处；每个链表最多维护7个堆块。

### 0x50 利用

待续……