# pyinstaller 打包程序反编译

> 比赛中因为不熟悉pyinstaller打包方式，导致走了很多弯路。

- 寻一个文件[archive_viewer.py](https://raw.githubusercontent.com/pyinstaller/pyinstaller/develop/PyInstaller/utils/cliutils/archive_viewer.py)来分解出程序中的`pyc`文件，或者使用`pyi-archive_viewer`命令（可能需要`pip`安装`pyinstaller`）

  `python3 archive_viewer.py pwn ` 或者`pyi-archive_viewer pwn` 

  <img src="https://img.vaala.cloud/images/2021/04/02/1ad8b1c03a94f2d4219699052575ac64.png" alt="image-20210402130116102" style="zoom:50%;" />

  这里需要两个文件，一个`struct`（后续需要用到），一个`input_httpd`（我们需要反编译的`pyc`文件）。

  提取指令：

  ```shell
  U: go Up one level
  O <name>: open embedded archive name
  X <name>: extract name
  Q: quit
  ```

- 修复`input_httpd`的文件头。（Linux和Windows下修复方式不同，本文是Linux下）

  分别打开两个`pyc`，对比发现`input_httpd`缺少文件头。（实际是看了前人的帖子）

  ```shell
  vim struct.pyc
  :%!xxd
  # 修改
  :%!xxd -r
  :wq
  ```

  <img src="https://img.vaala.cloud/images/2021/04/02/7649e2d51150494e094515417b272049.png" alt="image-20210402130831724" style="zoom:50%;" />

  这是`struct.pyc`多出来的文件头，需要补充进`input_httpd.pyc`。

  <img src="https://img.vaala.cloud/images/2021/04/02/1dbb9f731f5f73c185ddf3e0a2aa5fa3.png" alt="image-20210402131015952" style="zoom:50%;" />

  这是`input_httpd.pyc`文件，做个对比。

  我并没有选择使用`vim`来修改文件，只是用它来查看需要补充的文件头，修改的时候使用的`Hex Fiend`。

- `uncompyle6`来反编译`pyc`文件为`py`源代码文件。

  ```shell
  uncompyle6 input_httpd.pyc > input_httpd.py
  ```

