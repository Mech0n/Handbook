# Radare2

## 简介

IDA Pro 昂贵的价格令很多二进制爱好者望而却步，于是在开源世界中催生出了一个新的逆向工程框架——Radare2，它拥有非常强大的功能，包括反汇编、调试、打补丁、虚拟化等等，而且可以运行在几乎所有的主流平台上（GNU/Linux、Windows、BSD、iOS、OSX……）。Radare2 开发之初仅提供了基于命令行的操作，尽管现在也有非官方的GUI，但我更喜欢直接在终端上运行它，当然这也就意味着更高陡峭的学习曲线。Radare2　是由一系列的组件构成的，这些组件赋予了 Radare2 强大的分析能力，可以在 Radare2 中或者单独被使用。

这里是 Radare2 与其他二进制分析工具的对比。（[Comparison Table](http://rada.re/r/cmp.html)）

## 安装

```bash
$ git clone https://github.com/radare/radare2.git
$ cd radare2
$ ./sys/install.sh
```

### 更新

```bash
$ ./sys/install.sh
```

### 卸载

```bash
$ make uninstall
$ make purge
```

## 命令行使用方法

Radare2 在命令行下有一些小工具可供使用：

- radare2：十六进制编辑器和调试器的核心，通常通过它进入交互式界面。
- rabin2：从可执行二进制文件中提取信息。
- rasm2：汇编和反汇编。
- rahash2：基于块的哈希工具。
- radiff2：二进制文件或代码差异比对。
- rafind2：查找字节模式。
- ragg2：r_egg 的前端，将高级语言编写的简单程序编译成x86、x86-64和ARM的二进制文件。
- rarun2：用于在不同环境中运行程序。
- rax2：数据格式转换。

### radare2/r2

```text
$ r2 -h
Usage: r2 [-ACdfLMnNqStuvwzX] [-P patch] [-p prj] [-a arch] [-b bits] [-i file]
          [-s addr] [-B baddr] [-M maddr] [-c cmd] [-e k=v] file|pid|-|--|=
 --           run radare2 without opening any file
 -            same as 'r2 malloc://512'
 =            read file from stdin (use -i and -c to run cmds)
 -=           perform !=! command to run all commands remotely
 -0           print \x00 after init and every command
 -a [arch]    set asm.arch
 -A           run 'aaa' command to analyze all referenced code
 -b [bits]    set asm.bits
 -B [baddr]   set base address for PIE binaries
 -c 'cmd..'   execute radare command
 -C           file is host:port (alias for -c+=http://%s/cmd/)
 -d           debug the executable 'file' or running process 'pid'
 -D [backend] enable debug mode (e cfg.debug=true)
 -e k=v       evaluate config var
 -f           block size = file size
 -F [binplug] force to use that rbin plugin
 -h, -hh      show help message, -hh for long
 -H ([var])   display variable
 -i [file]    run script file
 -I [file]    run script file before the file is opened
 -k [k=v]     perform sdb query into core->sdb
 -l [lib]     load plugin file
 -L           list supported IO plugins
 -m [addr]    map file at given address (loadaddr)
 -M           do not demangle symbol names
 -n, -nn      do not load RBin info (-nn only load bin structures)
 -N           do not load user settings and scripts
 -o [OS/kern] set asm.os (linux, macos, w32, netbsd, ...)
 -q           quiet mode (no prompt) and quit after -i
 -p [prj]     use project, list if no arg, load if no file
 -P [file]    apply rapatch file and quit
 -R [rarun2]  specify rarun2 profile to load (same as -e dbg.profile=X)
 -s [addr]    initial seek
 -S           start r2 in sandbox mode
 -t           load rabin2 info in thread
 -u           set bin.filter=false to get raw sym/sec/cls names
 -v, -V       show radare2 version (-V show lib versions)
 -w           open file in write mode
 -X [rr2rule] specify custom rarun2 directive
 -z, -zz      do not load strings or load them even in raw
```

参数很多，这里最重要是 `file`。如果你想 attach 到一个进程上，则使用 `pid`。常用参数如下：

- `-A`：相当于在交互界面输入了 `aaa`。
- `-c`：运行 radare 命令。（`r2 -A -q -c 'iI~pic' file`）
- `-d`：调试二进制文件或进程。
- `-a`,`-b`,`-o`：分别指定体系结构、位数和操作系统，通常是自动的，但也可以手动指定。
- `-w`：使用可写模式打开。

### rabin2

```text
$ rabin2 -h
Usage: rabin2 [-AcdeEghHiIjlLMqrRsSvVxzZ] [-@ at] [-a arch] [-b bits] [-B addr]
              [-C F:C:D] [-f str] [-m addr] [-n str] [-N m:M] [-P[-P] pdb]
              [-o str] [-O str] [-k query] [-D lang symname] | file
 -@ [addr]       show section, symbol or import at addr
 -A              list sub-binaries and their arch-bits pairs
 -a [arch]       set arch (x86, arm, .. or <arch>_<bits>)
 -b [bits]       set bits (32, 64 ...)
 -B [addr]       override base address (pie bins)
 -c              list classes
 -C [fmt:C:D]    create [elf,mach0,pe] with Code and Data hexpairs (see -a)
 -d              show debug/dwarf information
 -D lang name    demangle symbol name (-D all for bin.demangle=true)
 -e              entrypoint
 -E              globally exportable symbols
 -f [str]        select sub-bin named str
 -F [binfmt]     force to use that bin plugin (ignore header check)
 -g              same as -SMZIHVResizcld (show all info)
 -G [addr]       load address . offset to header
 -h              this help message
 -H              header fields
 -i              imports (symbols imported from libraries)
 -I              binary info
 -j              output in json
 -k [sdb-query]  run sdb query. for example: '*'
 -K [algo]       calculate checksums (md5, sha1, ..)
 -l              linked libraries
 -L [plugin]     list supported bin plugins or plugin details
 -m [addr]       show source line at addr
 -M              main (show address of main symbol)
 -n [str]        show section, symbol or import named str
 -N [min:max]    force min:max number of chars per string (see -z and -zz)
 -o [str]        output file/folder for write operations (out by default)
 -O [str]        write/extract operations (-O help)
 -p              show physical addresses
 -P              show debug/pdb information
 -PP             download pdb file for binary
 -q              be quiet, just show fewer data
 -qq             show less info (no offset/size for -z for ex.)
 -Q              show load address used by dlopen (non-aslr libs)
 -r              radare output
 -R              relocations
 -s              symbols
 -S              sections
 -u              unfiltered (no rename duplicated symbols/sections)
 -v              display version and quit
 -V              Show binary version information
 -x              extract bins contained in file
 -X [fmt] [f] .. package in fat or zip the given files and bins contained in file
 -z              strings (from data section)
 -zz             strings (from raw bins [e bin.rawstr=1])
 -zzz            dump raw strings to stdout (for huge files)
 -Z              guess size of binary program
```

当我们拿到一个二进制文件时，第一步就是获取关于它的基本信息，这时候就可以使用 rabin2。rabin2 可以获取包括 ELF、PE、Mach-O、Java CLASS 文件的区段、头信息、导入导出表、数据段字符串、入口点等信息，并且支持多种格式的输出。

下面介绍一些常见的用法：（我还会列出其他实现类似功能工具的用法，你可以对比一下它们的输出）

- `-I`：最常用的参数，它可以打印出二进制文件信息，其中我们需要重点关注其使用的安全防护技术，如 canary、pic、nx 等。（`file`、`chekcsec -f`）
- `-e`：得到二进制文件的入口点。（｀readelf -h`）
- `-i`：获得导入符号表，RLT中的偏移等。（`readelf -r`）
- `-E`：获得全局导出符号表。
- `-s`：获得符号表。（`readelf -s`）
- `-l`：获得二进制文件使用到的动态链接库。（`ldd`）
- `-z`：从 ELF 文件的 .rodare 段或 PE 文件的 .text 中获得字符串。（`strings -d`）
- `-S`：获得完整的段信息。（`readelf -S`）
- `-c`：列出所有类，在分析 Java 程序是很有用。

最后还要提到的一个参数 `-r`，它可以将我们得到的信息以 radare2 可读的形式输出，在后续的分析中可以将这样格式的信息输入 radare2，这是非常有用的。

### rasm2

```text
$ rasm2 -h
Usage: rasm2 [-ACdDehLBvw] [-a arch] [-b bits] [-o addr] [-s syntax]
             [-f file] [-F fil:ter] [-i skip] [-l len] 'code'|hex|-
 -a [arch]    Set architecture to assemble/disassemble (see -L)
 -A           Show Analysis information from given hexpairs
 -b [bits]    Set cpu register size (8, 16, 32, 64) (RASM2_BITS)
 -c [cpu]     Select specific CPU (depends on arch)
 -C           Output in C format
 -d, -D       Disassemble from hexpair bytes (-D show hexpairs)
 -e           Use big endian instead of little endian
 -E           Display ESIL expression (same input as in -d)
 -f [file]    Read data from file
 -F [in:out]  Specify input and/or output filters (att2intel, x86.pseudo, ...)
 -h, -hh      Show this help, -hh for long
 -i [len]     ignore/skip N bytes of the input buffer
 -k [kernel]  Select operating system (linux, windows, darwin, ..)
 -l [len]     Input/Output length
 -L           List Asm plugins: (a=asm, d=disasm, A=analyze, e=ESIL)
 -o [offset]  Set start address for code (default 0)
 -O [file]    Output file name (rasm2 -Bf a.asm -O a)
 -p           Run SPP over input for assembly
 -s [syntax]  Select syntax (intel, att)
 -B           Binary input/output (-l is mandatory for binary input)
 -v           Show version information
 -w           What's this instruction for? describe opcode
 -q           quiet mode
```

rasm2 是一个内联汇编、反汇编程序。它的主要功能是获取给定机器指令操作码对应的字节。

下面是一些重要的参数：

- `-L`：列出目标体系结构所支持的插件，输出中的第一列说明了插件提供的功能（a=asm, d=disasm, A=analyze, e=ESIL）。
- `-a`：知道插件的名字后，就可以使用 -a` 来进行设置。
- `-b`：设置CPU寄存器的位数。
- `-d`：反汇编十六进制对字符串。
- `-D`：反汇编并显示十六进制对和操作码。
- `-C`：汇编后以 C 语言风格输出。
- `-f`：从文件中读入汇编代码。

例子：

```text
$ rasm2 -a x86 -b 32 'mov eax,30'
b81e000000
$ rasm2 -a x86 -b 32 'mov eax,30' -C
"\xb8\x1e\x00\x00\x00"

$ rasm2 -d b81e000000
mov eax, 0x1e
$ rasm2 -D b81e000000
0x00000000   5               b81e000000  mov eax, 0x1e
$ rasm2 -a x86 -b 32 -d 'b81e000000'
mov eax, 0x1e

$ cat a.asm
mov eax,30
$ rasm2 -f a.asm
b81e000000
```

### rahash2

```text
$ rahash2 -h
Usage: rahash2 [-rBhLkv] [-b S] [-a A] [-c H] [-E A] [-s S] [-f O] [-t O] [file] ...
 -a algo     comma separated list of algorithms (default is 'sha256')
 -b bsize    specify the size of the block (instead of full file)
 -B          show per-block hash
 -c hash     compare with this hash
 -e          swap endian (use little endian)
 -E algo     encrypt. Use -S to set key and -I to set IV
 -D algo     decrypt. Use -S to set key and -I to set IV
 -f from     start hashing at given address
 -i num      repeat hash N iterations
 -I iv       use give initialization vector (IV) (hexa or s:string)
 -S seed     use given seed (hexa or s:string) use ^ to prefix (key for -E)
             (- will slurp the key from stdin, the @ prefix points to a file
 -k          show hash using the openssh's randomkey algorithm
 -q          run in quiet mode (-qq to show only the hash)
 -L          list all available algorithms (see -a)
 -r          output radare commands
 -s string   hash this string instead of files
 -t to       stop hashing at given address
 -x hexstr   hash this hexpair string instead of files
 -v          show version information
```

rahash2 用于计算检验和，支持字节流、文件、字符串等形式和多种算法。

重要参数：

- `-a`：指定算法。默认为 sha256，如果指定为 all，则使用所有算法。
- `-b`：指定块的大小（而不是整个文件）
- `-B`：打印处每个块的哈希
- `-s`：指定字符串（而不是文件）
- `-a entropy`：显示每个块的熵（`-B -b 512 -a entropy`）

### radiff2

```text
$ radiff2 -h
Usage: radiff2 [-abcCdjrspOxuUvV] [-A[A]] [-g sym] [-t %] [file] [file]
  -a [arch]  specify architecture plugin to use (x86, arm, ..)
  -A [-A]    run aaa or aaaa after loading each binary (see -C)
  -b [bits]  specify register size for arch (16 (thumb), 32, 64, ..)
  -c         count of changes
  -C         graphdiff code (columns: off-A, match-ratio, off-B) (see -A)
  -d         use delta diffing
  -D         show disasm instead of hexpairs
  -e [k=v]   set eval config var value for all RCore instances
  -g [sym|off1,off2]   graph diff of given symbol, or between two offsets
  -G [cmd]   run an r2 command on every RCore instance created
  -i         diff imports of target files (see -u, -U and -z)
  -j         output in json format
  -n         print bare addresses only (diff.bare=1)
  -O         code diffing with opcode bytes only
  -p         use physical addressing (io.va=0)
  -q         quiet mode (disable colors, reduce output)
  -r         output in radare commands
  -s         compute text distance
  -ss        compute text distance (using levenstein algorithm)
  -S [name]  sort code diff (name, namelen, addr, size, type, dist) (only for -C or -g)
  -t [0-100] set threshold for code diff (default is 70%)
  -x         show two column hexdump diffing
  -u         unified output (---+++)
  -U         unified output using system 'diff'
  -v         show version information
  -V         be verbose (current only for -s)
  -z         diff on extracted strings
```

radiff2 是一个基于偏移的比较工具。

重要参数：

- `-s`：计算文本距离并得到相似度。
- `－AC`：这两个参数通常一起使用，从函数的角度进行比较。
- `-g`：得到给定的符号或两个偏移的图像对比。
  - 如：`radiff2 -g main a.out b.out | xdot -`（需要安装xdot）
- `-c`：计算不同点的数量。

### rafind2

```text
$ rafind2 -h
Usage: rafind2 [-mXnzZhv] [-a align] [-b sz] [-f/t from/to] [-[m|s|S|e] str] [-x hex] file ..
 -a [align] only accept aligned hits
 -b [size]  set block size
 -e [regex] search for regular expression string matches
 -f [from]  start searching from address 'from'
 -h         show this help
 -m         magic search, file-type carver
 -M [str]   set a binary mask to be applied on keywords
 -n         do not stop on read errors
 -r         print using radare commands
 -s [str]   search for a specific string (can be used multiple times)
 -S [str]   search for a specific wide string (can be used multiple times)
 -t [to]    stop search at address 'to'
 -v         print version and exit
 -x [hex]   search for hexpair string (909090) (can be used multiple times)
 -X         show hexdump of search results
 -z         search for zero-terminated strings
 -Z         show string found on each search hit
```

rafind2 用于在二进制文件中查找字符模式。

重要参数：

- `-s`：查找特定字符串。
- `-e`：使用正则匹配。
- `-z`：搜索以`\0`结束的字符串。
- `-x`：查找十六进制字符串。

### ragg2

```text
$ ragg2 -h
Usage: ragg2 [-FOLsrxhvz] [-a arch] [-b bits] [-k os] [-o file] [-I path]
             [-i sc] [-e enc] [-B hex] [-c k=v] [-C file] [-p pad] [-q off]
             [-q off] [-dDw off:hex] file|f.asm|-
 -a [arch]       select architecture (x86, mips, arm)
 -b [bits]       register size (32, 64, ..)
 -B [hexpairs]   append some hexpair bytes
 -c [k=v]        set configuration options
 -C [file]       append contents of file
 -d [off:dword]  patch dword (4 bytes) at given offset
 -D [off:qword]  patch qword (8 bytes) at given offset
 -e [encoder]    use specific encoder. see -L
 -f [format]     output format (raw, pe, elf, mach0)
 -F              output native format (osx=mach0, linux=elf, ..)
 -h              show this help
 -i [shellcode]  include shellcode plugin, uses options. see -L
 -I [path]       add include path
 -k [os]         operating system's kernel (linux,bsd,osx,w32)
 -L              list all plugins (shellcodes and encoders)
 -n [dword]      append 32bit number (4 bytes)
 -N [dword]      append 64bit number (8 bytes)
 -o [file]       output file
 -O              use default output file (filename without extension or a.out)
 -p [padding]    add padding after compilation (padding=n10s32)
                 ntas : begin nop, trap, 'a', sequence
                 NTAS : same as above, but at the end
 -P [size]       prepend debruijn pattern
 -q [fragment]   debruijn pattern offset
 -r              show raw bytes instead of hexpairs
 -s              show assembler
 -v              show version
 -w [off:hex]    patch hexpairs at given offset
 -x              execute
 -z              output in C string syntax
```

ragg2 可以将高级语言编写的简单程序编译成 x86、x86-64 或 ARM 的二进制文件。

重要参数：

- `-a`：设置体系结构。
- `-b`：设置体系结构位数(32/64)。
- `-P`：生成某种模式的字符串，常用于输入到某程序中并寻找溢出点。
- `-r`：使用原始字符而不是十六进制对。
  - ragg2 -P 50 -r`
- `-i`：生成指定的 shellcode。查看 `-L`。
  - `ragg2 -a x86 -b 32 -i exec`
- `-e`：使用指定的编码器。查看 `-L`。

### rarun2

```text
$ rarun2 -h
Usage: rarun2 -v|-t|script.rr2 [directive ..]
program=/bin/ls
arg1=/bin
# arg2=hello
# arg3="hello\nworld"
# arg4=:048490184058104849
# arg5=:!ragg2 -p n50 -d 10:0x8048123
# arg6=@arg.txt
# arg7=@300@ABCD # 300 chars filled with ABCD pattern
# system=r2 -
# aslr=no
setenv=FOO=BAR
# unsetenv=FOO
# clearenv=true
# envfile=environ.txt
timeout=3
# timeoutsig=SIGTERM # or 15
# connect=localhost:8080
# listen=8080
# pty=false
# fork=true
# bits=32
# pid=0
# pidfile=/tmp/foo.pid
# #sleep=0
# #maxfd=0
# #execve=false
# #maxproc=0
# #maxstack=0
# #core=false
# #stdio=blah.txt
# #stderr=foo.txt
# stdout=foo.txt
# stdin=input.txt # or !program to redirect input to another program
# input=input.txt
# chdir=/
# chroot=/mnt/chroot
# libpath=$PWD:/tmp/lib
# r2preload=yes
# preload=/lib/libfoo.so
# setuid=2000
# seteuid=2000
# setgid=2001
# setegid=2001
# nice=5
```

rarun2 是一个可以使用不同环境、参数、标准输入、权限和文件描述符的启动器。

常用的参数设置：

- `program`
- `arg1`, `arg2`,...
- `setenv`
- `stdin`, `stdout`

例子：

- `rarun2 program=a.out arg1=$(ragg2 -P 300 -r)`
- `rarun2 program=a.out stdin=$(python a.py)`

### rax2

```text
$ rax2 -h
Usage: rax2 [options] [expr ...]
  =[base]                 ;  rax2 =10 0x46 -> output in base 10
  int   ->  hex           ;  rax2 10
  hex   ->  int           ;  rax2 0xa
  -int  ->  hex           ;  rax2 -77
  -hex  ->  int           ;  rax2 0xffffffb3
  int   ->  bin           ;  rax2 b30
  int   ->  ternary       ;  rax2 t42
  bin   ->  int           ;  rax2 1010d
  float ->  hex           ;  rax2 3.33f
  hex   ->  float         ;  rax2 Fx40551ed8
  oct   ->  hex           ;  rax2 35o
  hex   ->  oct           ;  rax2 Ox12 (O is a letter)
  bin   ->  hex           ;  rax2 1100011b
  hex   ->  bin           ;  rax2 Bx63
  hex   ->  ternary       ;  rax2 Tx23
  raw   ->  hex           ;  rax2 -S < /binfile
  hex   ->  raw           ;  rax2 -s 414141
  -b    bin -> str        ;  rax2 -b 01000101 01110110
  -B    str -> bin        ;  rax2 -B hello
  -d    force integer     ;  rax2 -d 3 -> 3 instead of 0x3
  -e    swap endianness   ;  rax2 -e 0x33
  -D    base64 decode     ;
  -E    base64 encode     ;
  -f    floating point    ;  rax2 -f 6.3+2.1
  -F    stdin slurp C hex ;  rax2 -F < shellcode.c
  -h    help              ;  rax2 -h
  -k    keep base         ;  rax2 -k 33+3 -> 36
  -K    randomart         ;  rax2 -K 0x34 1020304050
  -n    binary number     ;  rax2 -n 0x1234 # 34120000
  -N    binary number     ;  rax2 -N 0x1234 # \x34\x12\x00\x00
  -r    r2 style output   ;  rax2 -r 0x1234
  -s    hexstr -> raw     ;  rax2 -s 43 4a 50
  -S    raw -> hexstr     ;  rax2 -S < /bin/ls > ls.hex
  -t    tstamp -> str     ;  rax2 -t 1234567890
  -x    hash string       ;  rax2 -x linux osx
  -u    units             ;  rax2 -u 389289238 # 317.0M
  -w    signed word       ;  rax2 -w 16 0xffff
  -v    version           ;  rax2 -v
```

rax2 是一个格式转换工具，在二进制、八进制、十六进制数字和字符串之间进行转换。

重要参数：

- `-e`：交换字节顺序
- `-s`：十六进制->字符
- `-S`：字符->十六进制
- `-D`, `-E`：base64 解码和编码

## 交互式使用方法

当我们进入到 Radare2 的交互式界面后，就可以使用交互式命令进行操作。

输入 `?`　可以获得帮助信息，由于命令太多，我们只会重点介绍一些常用命令：

```text
[0x00000000]> ?
Usage: [.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...
Append '?' to any char command to get detailed help
Prefix with number to repeat command N times (f.ex: 3x)
|%var =valueAlias for 'env' command
| *[?] off[=[0x]value]    Pointer read/write data/values (see ?v, wx, wv)
| (macro arg0 arg1)       Manage scripting macros
| .[?] [-|(m)|f|!sh|cmd]  Define macro or load r2, cparse or rlang file
| =[?] [cmd]              Send/Listen for Remote Commands (rap://, http://, <fd>)
| /[?]                    Search for bytes, regexps, patterns, ..
| ![?] [cmd]              Run given command as in system(3)
| #[?] !lang [..]         Hashbang to run an rlang script
| a[?]                    Analysis commands
| b[?]                    Display or change the block size
| c[?] [arg]              Compare block with given data
| C[?]                    Code metadata (comments, format, hints, ..)
| d[?]                    Debugger commands
| e[?] [a[=b]]            List/get/set config evaluable vars
| f[?] [name][sz][at]     Add flag at current address
| g[?] [arg]              Generate shellcodes with r_egg
| i[?] [file]             Get info about opened file from r_bin
| k[?] [sdb-query]        Run sdb-query. see k? for help, 'k *', 'k **' ...
| L[?] [-] [plugin]       list, unload load r2 plugins
| m[?]                    Mountpoints commands
| o[?] [file] ([offset])  Open file at optional address
| p[?] [len]              Print current block with format and length
| P[?]                    Project management utilities
| q[?] [ret]              Quit program with a return value
| r[?] [len]              Resize file
| s[?] [addr]             Seek to address (also for '0x', '0x1' == 's 0x1')
| S[?]                    Io section manipulation information
| t[?]                    Types, noreturn, signatures, C parser and more
| T[?] [-] [num|msg]      Text log utility
| u[?]                    uname/undo seek/write
| V                       Enter visual mode (V! = panels, VV = fcngraph, VVV = callgraph)
| w[?] [str]              Multiple write operations
| x[?] [len]              Alias for 'px' (print hexadecimal)
| y[?] [len] [[[@]addr    Yank/paste bytes from/to memory
| z[?]                    Zignatures management
| ?[??][expr]             Help or evaluate math expression
| ?$?                     Show available '$' variables and aliases
| ?@?                     Misc help for '@' (seek), '~' (grep) (see ~??)
| ?:?                     List and manage core plugins
```

于是我们知道了 Radare2 交互命令的一般格式，如下所示：

```text
[.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...
```

如果你对 *nix shell, sed, awk 等比较熟悉的话，也可以帮助你很快掌握 radare2 命令。

- 在任意字符命令后面加上 `?`　可以获得关于该命令更多的细节。如 `a?`、`p?`、`!?`、`@?`。
- 当命令以数字开头时表示重复运行的次数。如 `3x`。
- `!` 单独使用可以显示命令使用历史记录。
- `;` 是命令分隔符，可以在一行上运行多个命令。如 `px 10; pd 20`。
- `..` 重复运行上一条命令，使用回车键也一样。
- `/` 用于在文件中进行搜索操作。
- 以 `!` 开头可以运行 shell 命令。用法：`!<cmd>`。
  - `!ls`
- `|` 是管道符。用法：`<r2command> | <program|H|>`。
  - `pd | less`
- `~` 用于文本比配（grep）。用法：`[command]~[modifier][word,word][endmodifier][[column]][:line]`。
  - `i~:0` 显示 `i` 输出的第一行
  - `pd~mov,eax` 反汇编并匹配 mov 或 eax 所在行
  - `pi~mov&eax` 匹配 mov 和 eax 都有的行
  - `i~0x400$` 匹配以 0x400 结尾的行
- `???` 可以获得以 `?` 开头的命令的细节
  - `?` 可以做各种进制和格式的快速转换。如 `? 1234`
  - `?p vaddr` 获得虚拟地址 vaddr 的物理地址
  - `?P paddr` 获得物理地址 paddr 的虚拟地址
  - `?v` 以十六进制的形式显示某数学表达式的结果。如 `?v eip-0x804800`。
  - `?l str` 获得 str 的长度，结果被临时保存，使用 `?v` 可输出结果。
- `@@` foreach 迭代器，在列出的偏移处重复执行命令。
  - `wx ff @@ 10 20 30` 在偏移 10、20、30 处写入 ff
  - `p8 4 @@ fcn.*` 打印处每个函数的头 4 个字节
- `?$?` 可以显示表达式所使用变量的帮助信息。用法：`?v [$.]`。
  - `$$` 是当前所处的虚拟地址
  - `$?` 是最后一个运算的值
  - `$s` 文件大小
  - `$b` 块大小
  - `$l` 操作码长度
  - `$j` 跳转地址。当 `$$` 处是一个类似 `jmp` 的指令时，`$j` 中保存着将要跳转到的地址
  - `$f` 跳转失败地址。即当前跳转没有生效，`$f` 中保存下一条指令的地址
  - `$m` 操作码内存引用。如：`mov eax,[0x10] => 0x10`
- `e` 用于进行配置信息的修改
  - `e asm.bytes=false` 关闭指令 raw bytes 的显示

默认情况下，执行的每条命令都有一个参考点，通常是内存中的当前位置，由命令前的十六进制数字指示。任何的打印、写入或分析命令都在当前位置执行。例如反汇编当前位置的一条指令：

```text
[0x00005060]> pd 1
            ;-- entry0:
            ;-- rip:
            0x00005060      31ed           xor ebp, ebp
```

block size 是在我们没有指定行数的时候使用的默认值，输入 `b` 即可看到，使用 `b [num]` 修改字节数，这时使用打印命令如 `pd` 时，将反汇编相应字节的指令。

```text
[0x00005060]> b
0x100
[0x00005060]> b 10
[0x00005060]> b
0xa
[0x00005060]> pd
            ;-- entry0:
            ;-- rip:
            0x00005060      31ed           xor ebp, ebp
            0x00005062      4989d1         mov r9, rdx
```

### 分析（analyze）

所有与分析有关的命令都以 `a` 开头：

```text
[0x00000000]> a?
|Usage: a[abdefFghoprxstc] [...]
| ab [hexpairs]    analyze bytes
| abb [len]        analyze N basic blocks in [len] (section.size by default)
| aa[?]            analyze all (fcns + bbs) (aa0 to avoid sub renaming)
| ac [cycles]      analyze which op could be executed in [cycles]
| ad[?]            analyze data trampoline (wip)
| ad [from] [to]   analyze data pointers to (from-to)
| ae[?] [expr]     analyze opcode eval expression (see ao)
| af[?]            analyze Functions
| aF               same as above, but using anal.depth=1
| ag[?] [options]  output Graphviz code
| ah[?]            analysis hints (force opcode size, ...)
| ai [addr]        address information (show perms, stack, heap, ...)
| ao[?] [len]      analyze Opcodes (or emulate it)
| aO               Analyze N instructions in M bytes
| ar[?]            like 'dr' but for the esil vm. (registers)
| ap               find prelude for current offset
| ax[?]            manage refs/xrefs (see also afx?)
| as[?] [num]      analyze syscall using dbg.reg
| at[?] [.]        analyze execution traces
| av[?] [.]        show vtables
```

```text
[0x00000000]> aa?
|Usage: aa[0*?] # see also 'af' and 'afna'
| aa                  alias for 'af@@ sym.*;af@entry0;afva'
| aa*                 analyze all flags starting with sym. (af @@ sym.*)
| aaa[?]              autoname functions after aa (see afna)
| aab                 aab across io.sections.text
| aac [len]           analyze function calls (af @@ `pi len~call[1]`)
| aad [len]           analyze data references to code
| aae [len] ([addr])  analyze references with ESIL (optionally to address)
| aai[j]              show info of all analysis parameters
| aar[?] [len]        analyze len bytes of instructions for references
| aan                 autoname functions that either start with fcn.* or sym.func.*
| aas [len]           analyze symbols (af @@= `isq~[0]`)
| aat [len]           analyze all consecutive functions in section
| aaT [len]           analyze code after trap-sleds
| aap                 find and analyze function preludes
| aav [sat]           find values referencing a specific section or map
| aau [len]           list mem areas (larger than len bytes) not covered by functions
```

- `afl`：列出所有函数。
- `axt [addr]`：找到对给定地址的交叉引用。
- `af [addr]`：当你发现某个地址处有一个函数，但是没有被分析出来的时候，可以使用该命令重新分析。

### Flags

flag 用于将给定的偏移与名称相关联，flag 被分为几个 flag spaces，用于存放不同的 flag。

```text
[0x00000000]> f?
|Usage: f [?] [flagname] # Manage offset-name flags
| f                        list flags (will only list flags from selected flagspaces)
| f?flagname               check if flag exists or not, See ?? and ?!
| f. [*[*]]                list local per-function flags (*) as r2 commands
| f.blah=$$+12             set local function label named 'blah'
| f*                       list flags in r commands
| f name 12 @ 33           set flag 'name' with length 12 at offset 33
| f name = 33              alias for 'f name @ 33' or 'f name 1 33'
| f name 12 33 [cmt]       same as above + optional comment
| f-.blah@fcn.foo          delete local label from function at current seek (also f.-)
| f--                      delete all flags and flagspaces (deinit)
| f+name 12 @ 33           like above but creates new one if doesnt exist
| f-name                   remove flag 'name'
| f-@addr                  remove flag at address expression
| f. fname                 list all local labels for the given function
| f= [glob]                list range bars graphics with flag offsets and sizes
| fa [name] [alias]        alias a flag to evaluate an expression
| fb [addr]                set base address for new flags
| fb [addr] [flag*]        move flags matching 'flag' to relative addr
| fc[?][name] [color]      set color for given flag
| fC [name] [cmt]          set comment for given flag
| fd addr                  return flag+delta
| fe-                      resets the enumerator counter
| fe [name]                create flag name.#num# enumerated flag. See fe?
| fi [size] | [from] [to]  show flags in current block or range
| fg                       bring visual mode to foreground
| fj                       list flags in JSON format
| fl (@[flag]) [size]      show or set flag length (size)
| fla [glob]               automatically compute the size of all flags matching glob
| fm addr                  move flag at current offset to new address
| fn                       list flags displaying the real name (demangled)
| fo                       show fortunes
| fr [old] [[new]]         rename flag (if no new flag current seek one is used)
| fR[?] [f] [t] [m]        relocate all flags matching f&~m 'f'rom, 't'o, 'm'ask
| fs[?]+-*                 manage flagspaces
| fS[on]                   sort flags by offset or name
| fV[*-] [nkey] [offset]   dump/restore visual marks (mK/'K)
| fx[d]                    show hexdump (or disasm) of flag:flagsize
| fz[?][name]              add named flag zone -name to delete. see fz?[name]
```

常见用法：

- `f flag_name @ addr`：给地址 addr 创建一个 flag，当不指定地址时则默认指定当前地址。
- `f-flag_name`：删除flag。
- `fs`：管理命名空间。

  ```text
  [0x00005060]> fs?
  |Usage: fs [*] [+-][flagspace|addr] # Manage flagspaces
  | fs            display flagspaces
  | fs*           display flagspaces as r2 commands
  | fsj           display flagspaces in JSON
  | fs *          select all flagspaces
  | fs flagspace  select flagspace or create if it doesn't exist
  | fs-flagspace  remove flagspace
  | fs-*          remove all flagspaces
  | fs+foo        push previous flagspace and set
  | fs-           pop to the previous flagspace
  | fs-.          remove the current flagspace
  | fsm [addr]    move flags at given address to the current flagspace
  | fss           display flagspaces stack
  | fss*          display flagspaces stack in r2 commands
  | fssj          display flagspaces stack in JSON
  | fsr newname   rename selected flagspace
  ```

### 定位（seeking）

使用 `s` 命令可以改变当前位置：

```text
[0x00000000]> s?
|Usage: s  # Seek commands
| s                 Print current address
| s:pad             Print current address with N padded zeros (defaults to 8)
| s addr            Seek to address
| s-                Undo seek
| s- n              Seek n bytes backward
| s--               Seek blocksize bytes backward
| s+                Redo seek
| s+ n              Seek n bytes forward
| s++               Seek blocksize bytes forward
| s[j*=!]           List undo seek history (JSON, =list, *r2, !=names, s==)
| s/ DATA           Search for next occurrence of 'DATA'
| s/x 9091          Search for next occurrence of \x90\x91
| s.hexoff          Seek honoring a base from core->offset
| sa [[+-]a] [asz]  Seek asz (or bsize) aligned to addr
| sb                Seek aligned to bb start
| sC[?] string      Seek to comment matching given string
| sf                Seek to next function (f->addr+f->size)
| sf function       Seek to address of specified function
| sg/sG             Seek begin (sg) or end (sG) of section or file
| sl[?] [+-]line    Seek to line
| sn/sp             Seek to next/prev location, as specified by scr.nkey
| so [N]            Seek to N next opcode(s)
| sr pc             Seek to register
| ss                Seek silently (without adding an entry to the seek history)
```

- `s+`,`s-`：重复或撤销。
- `s+ n`,`s- n`：定位到当前位置向前或向后 n 字节的位置。
- `s/ DATA`：定位到下一个出现 DATA 的位置。

### 信息（information）

```text
[0x00000000]> i?
|Usage: i Get info from opened file (see rabin2's manpage)
| Output mode:
| '*'                Output in radare commands
| 'j'                Output in json
| 'q'                Simple quiet output
| Actions:
| i|ij               Show info of current file (in JSON)
| iA                 List archs
| ia                 Show all info (imports, exports, sections..)
| ib                 Reload the current buffer for setting of the bin (use once only)
| ic                 List classes, methods and fields
| iC                 Show signature info (entitlements, ...)
| id[?]              Debug information (source lines)
| iD lang sym        demangle symbolname for given language
| ie                 Entrypoint
| iE                 Exports (global symbols)
| ih                 Headers (alias for iH)
| iHH                Verbose Headers in raw text
| ii                 Imports
| iI                 Binary info
| ik [query]         Key-value database from RBinObject
| il                 Libraries
| iL [plugin]        List all RBin plugins loaded or plugin details
| im                 Show info about predefined memory allocation
| iM                 Show main address
| io [file]          Load info from file (or last opened) use bin.baddr
| ir                 Relocs
| iR                 Resources
| is                 Symbols
| iS [entropy,sha1]  Sections (choose which hash algorithm to use)
| iV                 Display file version info
| iz|izj             Strings in data sections (in JSON/Base64)
| izz                Search for Strings in the whole binary
| iZ                 Guess size of binary program
```

`i` 系列命令用于获取文件的各种信息，这时配合上 `~` 命令来获得精确的输出，下面是一个类似 checksec 的输出：

```text
[0x00005060]> iI ~relro,canary,nx,pic,rpath
canary   true
nx       true
pic      true
relro    full
rpath    NONE
```

`~` 命令还有一些其他的用法，如获取某一行某一列等，另外使用 `~{}` 可以使 json 的输出更好看：

```text
[0x00005060]> ~?
|Usage: [command]~[modifier][word,word][endmodifier][[column]][:line]
modifier:
|  &            all words must match to grep the line
|  $[n]         sort numerically / alphabetically the Nth column
|  +            case insensitive grep (grep -i)
|  ^            words must be placed at the beginning of line
|  !            negate grep
|  ?            count number of matching lines
|  ?.           count number chars
|  ??           show this help message
|  :[s]-[e]     show lines s-e
|  ..           internal 'less'
|  ...          internal 'hud' (like V_)
|  {}           json indentation
|  {path}       json grep
|  {}..         less json indentation
| endmodifier:  
|  $            words must be placed at the end of line
| column:
|  [n]          show only column n
|  [n-m]        show column n to m
|  [n-]         show all columns starting from column n
|  [i,j,k]      show the columns i, j and k
| Examples:
|  i~:0         show first line of 'i' output
|  i~:-2        show first three lines of 'i' output
|  pd~mov       disasm and grep for mov
|  pi~[0]       show only opcode
|  i~0x400$     show lines ending with 0x400
```

### 打印（print） & 反汇编（disassembling）

```text
[0x00000000]> p?
|Usage: p[=68abcdDfiImrstuxz] [arg|len] [@addr]
| p=[?][bep] [blks] [len] [blk]  show entropy/printable chars/chars bars
| p2 [len]                       8x8 2bpp-tiles
| p3 [file]                      print stereogram (3D)
| p6[de] [len]                   base64 decode/encode
| p8[?][j] [len]                 8bit hexpair list of bytes
| pa[edD] [arg]                  pa:assemble  pa[dD]:disasm or pae: esil from hexpairs
| pA[n_ops]                      show n_ops address and type
| p[b|B|xb] [len] ([skip])       bindump N bits skipping M
| pb[?] [n]                      bitstream of N bits
| pB[?] [n]                      bitstream of N bytes
| pc[?][p] [len]                 output C (or python) format
| pC[d] [rows]                   print disassembly in columns (see hex.cols and pdi)
| pd[?] [sz] [a] [b]             disassemble N opcodes (pd) or N bytes (pD)
| pf[?][.nam] [fmt]              print formatted data (pf.name, pf.name $<expr>)
| ph[?][=|hash] ([len])          calculate hash for a block
| p[iI][df] [len]                print N ops/bytes (f=func) (see pi? and pdi)
| pm[?] [magic]                  print libmagic data (see pm? and /m?)
| pr[?][glx] [len]               print N raw bytes (in lines or hexblocks, 'g'unzip)
| p[kK] [len]                    print key in randomart (K is for mosaic)
| ps[?][pwz] [len]               print pascal/wide/zero-terminated strings
| pt[?][dn] [len]                print different timestamps
| pu[?][w] [len]                 print N url encoded bytes (w=wide)
| pv[?][jh] [mode]               show variable/pointer/value in memory
| p-[?][jh] [mode]               bar|json|histogram blocks (mode: e?search.in)
| px[?][owq] [len]               hexdump of N bytes (o=octal, w=32bit, q=64bit)
| pz[?] [len]                    print zoom view (see pz? for help)
| pwd                            display current working directory
```

常用参数如下：

- `px`：输出十六进制数、偏移和原始数据。后跟 `o`,`w`,`q` 时分别表示8位、32位和64位。
- `p8`：输出8位的字节流。
- `ps`：输出字符串。

radare2 中反汇编操作是隐藏在打印操作中的，即使用 `pd`：

```text
[0x00000000]> pd?
|Usage: p[dD][ajbrfils] [sz] [arch] [bits] # Print Disassembly
| NOTE: len  parameter can be negative
| NOTE:      Pressing ENTER on empty command will repeat last pd command and also seek to end of disassembled range.
| pd N       disassemble N instructions
| pd -N      disassemble N instructions backward
| pD N       disassemble N bytes
| pda        disassemble all possible opcodes (byte per byte)
| pdb        disassemble basic block
| pdc        pseudo disassembler output in C-like syntax
| pdC        show comments found in N instructions
| pdk        disassemble all methods of a class
| pdj        disassemble to json
| pdr        recursive disassemble across the function graph
| pdf        disassemble function
| pdi        like 'pi', with offset and bytes
| pdl        show instruction sizes
| pds[?]     disassemble summary (strings, calls, jumps, refs) (see pdsf and pdfs)
| pdt        disassemble the debugger traces (see atd)
```

`@addr` 表示一个相对寻址，这里的 addr 可以是地址、符号名等，这个操作和 `s` 命令不同，它不会改变当前位置，当然即使使用类似 `s @addr` 的命令也不会改变当前位置。

```text
[0x00005060]> pd 5 @ main
            ;-- main:
            ;-- section..text:
            0x00003620      4157           push r15                    ; section 13 va=0x00003620 pa=0x00003620 sz=75529 vsz=75529 rwx=--r-x .text
            0x00003622      4156           push r14
            0x00003624      4155           push r13
            0x00003626      4154           push r12
            0x00003628      55             push rbp
[0x00005060]> s @ main
0x3620
[0x00005060]> s 0x3620
[0x00003620]>
```

### 写入（write）

当你在打开 r2 时使用了参数 `-w` 时，才可以使用该命令，`w` 命令用于写入字节，它允许多种输入格式：

```text
[0x00000000]> w?
|Usage: w[x] [str] [<file] [<<EOF] [@addr]
| w[1248][+-][n]       increment/decrement byte,word..
| w foobar             write string 'foobar'
| w0 [len]             write 'len' bytes with value 0x00
| w6[de] base64/hex    write base64 [d]ecoded or [e]ncoded string
| wa[?] push ebp       write opcode, separated by ';' (use '"' around the command)
| waf file             assemble file and write bytes
| wao[?] op            modify opcode (change conditional of jump. nop, etc)
| wA[?] r 0            alter/modify opcode at current seek (see wA?)
| wb 010203            fill current block with cyclic hexpairs
| wB[-]0xVALUE         set or unset bits with given value
| wc                   list all write changes
| wc[?][ir*?]          write cache undo/commit/reset/list (io.cache)
| wd [off] [n]         duplicate N bytes from offset at current seek (memcpy) (see y?)
| we[?] [nNsxX] [arg]  extend write operations (insert instead of replace)
| wf -|file            write contents of file at current offset
| wh r2                whereis/which shell command
| wm f0ff              set binary mask hexpair to be used as cyclic write mask
| wo[?] hex            write in block with operation. 'wo?' fmi
| wp[?] -|file         apply radare patch file. See wp? fmi
| wr 10                write 10 random bytes
| ws pstring           write 1 byte for length and then the string
| wt[f][?] file [sz]   write to file (from current seek, blocksize or sz bytes)
| wts host:port [sz]   send data to remote host:port via tcp://
| ww foobar            write wide string 'f\x00o\x00o\x00b\x00a\x00r\x00'
| wx[?][fs] 9090       write two intel nops (from wxfile or wxseek)
| wv[?] eip+34         write 32-64 bit value
| wz string            write zero terminated string (like w + \x00)
```

常见用法：

- `wa`：写入操作码，如 `wa jmp 0x8048320`
- `wx`：写入十六进制数。
- `wv`：写入32或64位的值。
- `wo`：有很多子命令，用于将当前位置的值做运算后覆盖原值。

  ```text
  [0x00005060]> wo?
  |Usage: wo[asmdxoArl24] [hexpairs] @ addr[!bsize]
  | wo[24aAdlmorwx]               without hexpair values, clipboard is used
  | wo2 [val]                     2=  2 byte endian swap
  | wo4 [val]                     4=  4 byte endian swap
  | woa [val]                     +=  addition (f.ex: woa 0102)
  | woA [val]                     &=  and
  | wod [val]                     /=  divide
  | woD[algo] [key] [IV]          decrypt current block with given algo and key
  | woe [from to] [step] [wsz=1]  ..  create sequence
  | woE [algo] [key] [IV]         encrypt current block with given algo and key
  | wol [val]                     <<= shift left
  | wom [val]                     *=  multiply
  | woo [val]                     |=  or
  | wop[DO] [arg]                 De Bruijn Patterns
  | wor [val]                     >>= shift right
  | woR                           random bytes (alias for 'wr $b')
  | wos [val]                     -=  substraction
  | wow [val]                     ==  write looped value (alias for 'wb')
  | wox [val]                     ^=  xor  (f.ex: wox 0x90)
  ```

### 调试（debugging）

在开启 r2 时使用参数 `-d` 即可开启调试模式，当然如果你已经加载了程序，可以使用命令 `ood` 重新开启调试。

```text
[0x7f8363c75f30]> d?
|Usage: d # Debug commands
| db[?]                   Breakpoints commands
| dbt[?]                  Display backtrace based on dbg.btdepth and dbg.btalgo
| dc[?]                   Continue execution
| dd[?]                   File descriptors (!fd in r1)
| de[-sc] [rwx] [rm] [e]  Debug with ESIL (see de?)
| dg <file>               Generate a core-file (WIP)
| dH [handler]            Transplant process to a new handler
| di[?]                   Show debugger backend information (See dh)
| dk[?]                   List, send, get, set, signal handlers of child
| dL [handler]            List or set debugger handler
| dm[?]                   Show memory maps
| do[?]                   Open process (reload, alias for 'oo')
| doo[args]               Reopen in debugger mode with args (alias for 'ood')
| dp[?]                   List, attach to process or thread id
| dr[?]                   Cpu registers
| ds[?]                   Step, over, source line
| dt[?]                   Display instruction traces (dtr=reset)
| dw <pid>                Block prompt until pid dies
| dx[?]                   Inject and run code on target process (See gs)
```

### 视图模式

在调试时使用视图模式是十分有用的，因为你既可以查看程序当前的位置，也可以查看任何你想看的位置。输入 `V` 即可进入视图模式，按下 `p/P` 可在不同模式之间进行切换，按下 `?` 即可查看帮助，想退出时按下 `q`。

```text
Visual mode help:
?        show this help
 ??       show the user-friendly hud
 $        toggle asm.pseudo
 %        in cursor mode finds matching pair, otherwise toggle autoblocksz
 @        redraw screen every 1s (multi-user view), in cursor set position
 !        enter into the visual panels mode
 _        enter the flag/comment/functions/.. hud (same as VF_)
 =        set cmd.vprompt (top row)
 |        set cmd.cprompt (right column)
 .        seek to program counter
 "        toggle the column mode (uses pC..)
 /        in cursor mode search in current block
 :cmd     run radare command
 ;[-]cmt  add/remove comment
 0        seek to beginning of current function
 [1-9]    follow jmp/call identified by shortcut (like ;[1])
 ,file    add a link to the text file
 /*+-[]   change block size, [] = resize hex.cols
 </>      seek aligned to block size (seek cursor in cursor mode)
 a/A      (a)ssemble code, visual (A)ssembler
 b        toggle breakpoint
 B        enumerate and inspect classes
 c/C      toggle (c)ursor and (C)olors
 d[f?]    define function, data, code, ..
 D        enter visual diff mode (set diff.from/to)
 e        edit eval configuration variables
 f/F      set/unset or browse flags. f- to unset, F to browse, ..
 gG       go seek to begin and end of file (0-$s)
 hjkl     move around (or HJKL) (left-down-up-right)
 i        insert hex or string (in hexdump) use tab to toggle
 mK/'K    mark/go to Key (any key)
 M        walk the mounted filesystems
 n/N      seek next/prev function/flag/hit (scr.nkey)
 o        go/seek to given offset
 O        toggle asm.esil
 p/P      rotate print modes (hex, disasm, debug, words, buf)
 q        back to radare shell
 r        refresh screen / in cursor mode browse comments
 R        randomize color palette (ecr)
 sS       step / step over
 t        browse types
 T        enter textlog chat console (TT)
 uU       undo/redo seek
 v        visual function/vars code analysis menu
 V        (V)iew graph using cmd.graph (agv?)
 wW       seek cursor to next/prev word
 xX       show xrefs/refs of current function from/to data/code
 yY       copy and paste selection
 z        fold/unfold comments in disassembly
 Z        toggle zoom mode
 Enter    follow address of jump/call
Function Keys: (See 'e key.'), defaults to:
  F2      toggle breakpoint
  F4      run to cursor
  F7      single step
  F8      step over
  F9      continue
```

视图模式下的命令和命令行模式下的命令有很大不同，下面列出几个，更多的命令请查看帮助：

- `o`：定位到给定的偏移。
- `;`：添加注释。
- `V`：查看图形。
- `:`：运行 radare2 命令

## Web 界面使用

Radare2 的 GUI 尚在开发中，但有一个 Web 界面可以使用，如果刚开始你不习惯命令行操作，可以输入下面的命令：

```text
$ r2 -c=H [filename]
```

默认地址为 `http://localhost:9090/`，这样你就可以在 Web 中进行操作了，但是我强烈建议你强迫自己使用命令行的操作方式。

## cutter GUI

cutter 是 r2 官方的 GUI，已经在快速开发中，基本功能已经有了，喜欢界面操作的读者可以试一下（请确保 r2 已经正确安装）：

```text
$ yaourt -S qt
```

```text
$ git clone https://github.com/radareorg/cutter
$ cd cutter
$ mkdir build
$ cd build
$ qmake ../src
$ make
```

然后就可以运行了：

```text
$ ./cutter
```

## 在 CTF 中的运用

- [IOLI crackme](https://firmianay.github.io/2017/02/20/ioli_crackme_writeup.html)
- [radare2-explorations-binaries](https://github.com/monosource/radare2-explorations-binaries)

## 更多资源

- [The radare2 book](https://www.gitbook.com/book/radare/radare2book)
- [Radare2 intro](https://github.com/radare/radare2/blob/master/doc/intro.md)
- [Radare2 blog](http://radare.today/)
- [A journey into Radare 2 – Part 1: Simple crackme](https://www.megabeets.net/a-journey-into-radare-2-part-1/)
- [A journey into Radare 2 – Part 2: Exploitation](https://www.megabeets.net/a-journey-into-radare-2-part-2/)
