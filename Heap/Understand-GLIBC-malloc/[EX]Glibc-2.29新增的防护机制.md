# Glibc-2.29 新增的防护机制

下面我介绍几种在 glibc-2.29 中增加的防护机制。

### free

#### tcache机制

最明显的就是`tcache`。

```c
/* This test succeeds on double free.  However, we don't 100%
    trust it (it also matches random payload data at a 1 in
    2^<size_t> chance), so verify it's not an unlikely
    coincidence before aborting.  */
if (__glibc_unlikely (e->key == tcache))
  {
    tcache_entry *tmp;
    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
    for (tmp = tcache->entries[tc_idx];
    tmp;
    tmp = tmp->next)
      if (tmp == e)
  malloc_printerr ("free(): double free detected in tcache 2");
    /* If we get here, it was a coincidence.  We've wasted a
        few cycles, but don't abort.  */
  }
```

这里会对`tcache`链表上的所有``chunk`进行对比，检测是否有重复，这让原本在`glibc-2.27`和`glibc-2.28`肆虐的`tcache double free`攻击很难实施，但是鉴于`tcache`的特性，`tcache`的利用还是要比其他的`bins`方便很多。

#### chunk extend

`chunk extend`也是很好用的攻击方式之一，但是在`glibc-2.29`中增加了新的检查，这将会增大`chunk extend`的难度。

```c++
/* consolidate backward */
if (!prev_inuse(p)) {
  prevsize = prev_size (p);
  size += prevsize;
  p = chunk_at_offset(p, -((long) prevsize));
  if (__glibc_unlikely (chunksize(p) != prevsize))
    malloc_printerr ("corrupted size vs. prev_size while consolidating");
  unlink_chunk (av, p);
}
```

在`glibc-2.29`中新增了`prevsize`的检查机制，在合并的时候会判断`prev_size`和要合并`chunk`的`size`是否相同。

### malloc

#### unsorted bin

原本这里仅仅有`size`检查。

来自源码：glibc-2.29/malloc/malloc.c:3742

```c++
bck = victim->bk;
size = chunksize (victim);
mchunkptr next = chunk_at_offset (victim, size);

if (__glibc_unlikely (size <= 2 * SIZE_SZ)
    || __glibc_unlikely (size > av->system_mem))
  malloc_printerr ("malloc(): invalid size (unsorted)");
if (__glibc_unlikely (chunksize_nomask (next) < 2 * SIZE_SZ)
    || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
  malloc_printerr ("malloc(): invalid next size (unsorted)");
if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
  malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
if (__glibc_unlikely (bck->fd != victim)
    || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
  malloc_printerr ("malloc(): unsorted double linked list corrupted");
if (__glibc_unlikely (prev_inuse (next)))
  malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
```

然后在`glibc-2.29`中，增加了如下检查：

1. 对下一个相邻`chunk`的`size`检查
2. 对下一个相邻`chunk`的`prev_size`进行检查
3. 检查`unsorted bin`双向链表的完整性，对`unsorted bin attack`可以说是很致命的检查
4. 对下一个`chunk`的`prev_inuse`位进行检查

这么多的检查，将使得`unsorted bin`更难利用。

下面这个检查早在`glibc-2.28`就有了，这里提一下，主要是防护`unsorted bin attack`。

```c++
/* remove from unsorted list */
if (__glibc_unlikely (bck->fd != victim))
  malloc_printerr ("malloc(): corrupted unsorted chunks 3");
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```

## top chunk

对于`top chunk`增加了`size`检查，遏制了`House of Force`攻击。

```c++
victim = av->top;
size = chunksize (victim);

if (__glibc_unlikely (size > av->system_mem))
  malloc_printerr ("malloc(): corrupted top size");
```