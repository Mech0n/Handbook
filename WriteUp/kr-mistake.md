---
title: kr_mistake
date: 2020-01-26 20:47:15
tags:
- pwn
- pwnable.kr
---

# pwnable.kr mistake

由于自己实在太菜了。决定找一个网站从头开始刷题。🤷‍♂️

### 0x0 补充知识

**运算符从顶到底以降序列出。**

|                            优先级                            | 运算符                                                       | 描述                                                         | 结合性   |
| :----------------------------------------------------------: | :----------------------------------------------------------- | :----------------------------------------------------------- | :------- |
|                              1                               | `++` `--`                                                    | 后缀自增与自减                                               | 从左到右 |
|                             `()`                             | 函数调用                                                     |                                                              |          |
|                             `[]`                             | 数组下标                                                     |                                                              |          |
|                             `.`                              | 结构体与联合体成员访问                                       |                                                              |          |
|                             `->`                             | 结构体与联合体成员通过指针访问                               |                                                              |          |
|                      `(*type*){*list*}`                      | 复合字面量(C99)                                              |                                                              |          |
|                              2                               | `++` `--`                                                    | 前缀自增与自减[[注 1\]](https://zh.cppreference.com/w/c/language/operator_precedence#cite_note-1) | 从右到左 |
|                           `+` `-`                            | 一元加与减                                                   |                                                              |          |
|                           `!` `~`                            | 逻辑非与逐位非                                               |                                                              |          |
|                          `(*type*)`                          | 类型转型                                                     |                                                              |          |
|                             `*`                              | 间接（解引用）                                               |                                                              |          |
|                             `&`                              | 取址                                                         |                                                              |          |
|                           `sizeof`                           | 取大小[[注 2\]](https://zh.cppreference.com/w/c/language/operator_precedence#cite_note-2) |                                                              |          |
|                          `_Alignof`                          | 对齐要求(C11)                                                |                                                              |          |
|                              3                               | `*` `/` `%`                                                  | 乘法、除法及余数                                             | 从左到右 |
|                              4                               | `+` `-`                                                      | 加法及减法                                                   |          |
|                              5                               | `<<` `>>`                                                    | 逐位左移及右移                                               |          |
|                              6                               | `<` `<=`                                                     | 分别为 < 与 ≤ 的关系运算符                                   |          |
|                           `>` `>=`                           | 分别为 > 与 ≥ 的关系运算符                                   |                                                              |          |
|                              7                               | `==` `!=`                                                    | 分别为 = 与 ≠ 关系                                           |          |
|                              8                               | `&`                                                          | 逐位与                                                       |          |
|                              9                               | `^`                                                          | 逐位异或（排除或）                                           |          |
|                              10                              | `|`                                                          | 逐位或（包含或）                                             |          |
|                              11                              | `&&`                                                         | 逻辑与                                                       |          |
|                              12                              | `||`                                                         | 逻辑或                                                       |          |
|                              13                              | `?:`                                                         | 三元条件[[注 3\]](https://zh.cppreference.com/w/c/language/operator_precedence#cite_note-3) | 从右到左 |
| 14[[注 4\]](https://zh.cppreference.com/w/c/language/operator_precedence#cite_note-4) | `=`                                                          | 简单赋值                                                     |          |
|                          `+=` `-=`                           | 以和及差赋值                                                 |                                                              |          |
|                        `*=` `/=` `%=`                        | 以积、商及余数赋值                                           |                                                              |          |
|                         `<<=` `>>=`                          | 以逐位左移及右移赋值                                         |                                                              |          |
|                        `&=` `^=` `|=`                        | 以逐位与、异或及或赋值                                       |                                                              |          |
|                              15                              | `,`                                                          | 逗号                                                         | 从左到右 |

### 0x1 分析

这道题给了`hint`和c文件。

直接看吧。

`hint :  operator priority`.

```c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
        int i;
        for(i=0; i<len; i++){
                s[i] ^= XORKEY;
        }
}

int main(int argc, char* argv[]){

        int fd;
        if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
                printf("can't open password %d\n", fd);
                return 0;
        }

        printf("do not bruteforce...\n");
        sleep(time(0)%20);

        char pw_buf[PW_LEN+1];
        int len;
        if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
                printf("read error\n");
                close(fd);
                return 0;
        }

        char pw_buf2[PW_LEN+1];
        printf("input password : ");
        scanf("%10s", pw_buf2);

        // xor your input
        xor(pw_buf2, 10);

        if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
                printf("Password OK\n");
                system("/bin/cat flag\n");
        }
        else{
                printf("Wrong Password\n");
        }

        close(fd);
        return 0;
}
```

按逻辑来说。我们如果能够查看`password`文件最好不过了。但是。想的美！23333.

但是按照暗示，可以关注一下操作符优先级问题。

嘿嘿。找到了。看这句：`fd=open("/home/mistake/password",O_RDONLY,0400) < 0`。比较运算符先于赋值运算符。那么`fd`就是`0`了。也就是标准输入`stdin`。

问题解决了。

### 0x2 EXP

这道题不太需要代码解决。第一次输入10个字符，第二次输入这10个字符的异或就好。

`echo 1111111111 0000000000 | ./mistake`





