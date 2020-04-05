# pwn 运维小记

### 0x1 常用的docker框架

[xinetd](https://github.com/Eadom/ctf_xinetd)

```shell
git clone git@github.com:Eadom/ctf_xinetd.git
cd ctf_xinetd
#change /bin/flag && /bin/flag
docker build -t <your-ID/name> ./
docker run -d -p 0.0.0.0:1000:9999 -t <your-ID/name>
```

### 0x2 考虑的问题

有的时候需要考虑换国内源的问题

### 0x3 避免缓冲区干扰

```c
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
```

