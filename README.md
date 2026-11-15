# Nomi Auth Neo

基于 Rust 的 QQ 群验证码认证服务，提供登录、注册、改名、皮肤和 Yggdrasil 接口，支持 SQLite 和 MySQL/MariaDB。

搭配 [Nomi Launcher](https://github.com/NomiTeam/nomi-launcher) 和 [Nomi Auth Plugin](https://github.com/NomiTeam/nomi-auth-plugin) 使用。

接口说明在 [API.md](API.md)，开发说明在 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 运行

[发布包](https://github.com/NomiTeam/nomi-auth-neo/releases)提供 Linux 和 Windows x86_64 版本，程序无需额外安装运行库。使用 MySQL/MariaDB 时，需要已有的数据库服务。

下载可执行文件后运行 `serve`。首次执行会在当前目录生成 `.env` 和随机机器人密钥，提示修改配置后退出。填写公网地址、应用 ID 和群 ID，将密钥同步到机器人配置，再次执行 `serve` 启动服务：

```shell
$ chmod +x nomi-auth-neo
$ ./nomi-auth-neo serve --host 127.0.0.1 --port 8000
```

Windows 使用 `nomi-auth-neo.exe`。配置从当前目录读取，环境变量优先。不带参数运行只显示帮助；只有 `serve` 启动服务。

`NOMI_DATABASE_BACKEND` 可设为 `sqlite`、`mysql` 或 `mariadb`，其他字段见自动生成的 `.env`。

> 替换程序前请停止服务并备份整个数据目录。数据库、`texture-signing.pem` 和 `textures/` 应一起保留，不要让多个服务进程同时写入。

公网使用时建议通过 HTTPS 接入。

## 维护

```shell
$ ./nomi-auth-neo backup backups/nomi.tar.gz
$ ./nomi-auth-neo restore backups/nomi.tar.gz restored-data
$ ./nomi-auth-neo disable Alice
$ ./nomi-auth-neo enable Alice
$ ./nomi-auth-neo delete Alice
$ ./nomi-auth-neo cleanup
```

备份包含数据库快照、皮肤和签名私钥。恢复只写入新目录，不覆盖已有数据。

`delete ID` 要求账号已通过 `disable ID` 停用，随后永久删除账号及其角色、QQ 绑定、令牌和关联认证记录，不影响其他账号或游戏内数据。
账号删除后可以重新注册同名 ID，但 UUID 会改变。共用皮肤保留，无引用的皮肤由清理任务延迟回收。

SQLite 迁往 MySQL/MariaDB 时，配置空目标库后执行：

```shell
$ ./nomi-auth-neo migrate-database restored-data/nomi-auth.sqlite3
```

导入会核对全部记录，不修改源文件，目标非空时拒绝导入。

## 管理员登录

在启动器打开登录窗口，复制登录码，然后在服务端的程序目录执行：

```shell
$ ./nomi-auth-neo login AAAA-BBBB-CCCC Alice
```

账号存在时直接批准登录，不存在时创建账号。已绑定 QQ 的账号也可登录，现有绑定和 UUID 不变；新账号不绑定 QQ。
ID 仍须符合名称规则，已领取或过期的登录码不能使用。停用账号需先用 `enable ID` 启用。
此命令只能在服务端运行，没有对应的 HTTP 接口。测试结束后可用 `disable ID` 停用账号，再用 `delete ID` 永久删除。

## 项目结构

```text
src/
├── main.rs    - 启动和维护命令
├── core/      - 配置、请求和凭证工具
├── http/      - HTTP、限流和清理
├── services/  - 账号、会话和游戏认证
└── storage/   - 数据库、备份和迁移
```
