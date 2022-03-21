### FMT利用 && Python3-Exp

[toc]

### FMT利用

**抄自wiki：**

##### 写入现有地址中数据：

第 6 个参数处的值就是存储变量 c 的地址，我们便可以利用 %n 的特征来修改 c 的值。payload 如下

```
[addr of c]%012d%6$n
```

addr of c 的长度为 4，故而我们得再输入 12 个字符才可以达到 16 个字符，以便于来修改 c 的值为 16。

##### 写入特定地址：

`fmtstr_payload`函数：

- `offset`:指的是这个字符串在你内存中的偏移，比如 ，这个字符串目前的地址在栈顶，那么这个参数就是`6`，以此类推。

- `writes`:例子：`fmtstr_payload(6, {leak - 0x218 : pie + 0x0000000000001180})`
- 其余参考文档。

### Python3-Exp

善用`flat`打包`payload`。

例子：

```python
payload = b'a' * 0x108 + flat([canary, canary, canary, canary, pie + 0x000000000000101a, pop_rdi_ret, binsh, system])
```