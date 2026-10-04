# sealmark

sealmark 提供命令行版本查询和本地文件的 SHA-256 摘要计算。

## 构建

```sh
cmake -S . -B build
cmake --build build
```

## 用法

```text
Usage: sealmark --version
       sealmark digest <file>
```

### 查询版本

```sh
./build/sealmark --version
```

输出：

```text
sealmark 0.1.0
```

### 计算文件摘要

```sh
printf 'hello' > hello.txt
./build/sealmark digest hello.txt
```

输入对象限普通文件。摘要覆盖文件从开头到结尾的全部原始字节：文本与
二进制文件按同一规则处理，不解码文本，不去掉换行、空白或字节顺序标记，
也不把文件名、路径、大小或修改时间计入摘要。因此内容相同而名称或所在
目录不同的文件会得到相同结果，空文件也是有效输入。文件按固定大小的
缓冲区流式读取，内存占用不随文件大小增长。

成功时标准输出只写一行，摘要为 64 个小写十六进制字符，行末有换行，
退出码为 0：

```text
sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

## 退出码

- `0`：成功（版本查询，或文件全部内容读取并完成摘要计算）。
- `1`：处理失败。路径不存在、指向目录或其他非普通文件、没有读取权限、
  读取过程中出错或摘要计算失败时，向标准错误输出包含该路径的错误信息，
  标准输出保持为空。
- `2`：用法错误。缺少路径、空路径、多传参数或未知命令时，向标准错误
  输出上述用法说明。

## 第三方组件

SHA-256 计算使用 [PicoSHA2](https://github.com/okdshin/PicoSHA2)
（MIT 许可），以单头文件形式内置于 `third_party/picosha2/`，
不依赖外部命令或系统密码库。
