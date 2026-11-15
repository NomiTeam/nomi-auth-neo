# Nomi Auth Neo

基于 Rust 的 QQ 群验证码认证服务，提供登录、注册、改名、皮肤和 Yggdrasil 接口，支持 SQLite 和 MariaDB。

搭配 [Nomi Launcher](https://github.com/NomiTeam/nomi-launcher) 和 [Nomi Auth Plugin](https://github.com/NomiTeam/nomi-auth-plugin) 使用。

接口说明在 [API.md](API.md)，开发说明在 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 运行

[发布包](https://github.com/NomiTeam/nomi-auth-neo/releases)提供 Linux 和 Windows x86_64 版本，程序无需额外安装运行库。使用 MariaDB 时，需要已有的数据库服务。

首次运行会在当前目录生成 `.env`，自动生成机器人密钥。填写公网地址、应用 ID 和群 ID，将该密钥同步到机器人配置后，再次启动：

```shell
$ chmod +x nomi-auth-neo
$ ./nomi-auth-neo serve --host 127.0.0.1 --port 8000
```

Windows 使用 `nomi-auth-neo.exe`。配置从当前目录读取，环境变量优先。直接运行程序使用上述默认地址。

`NOMI_DATABASE_BACKEND` 可设为 `sqlite`、`mysql` 或 `mariadb`，其他字段见 `.env.example`。

> 替换程序前请停止服务并备份整个数据目录。数据库、`texture-signing.pem` 和 `textures/` 应一起保留，不要让多个服务进程同时写入。

## Nginx

参考 [nginx.conf](deploy/nginx.conf)，修改域名、服务端证书和后端地址，再检查配置：

```shell
$ nginx -t
```

检查通过后重载。Rust 只监听本机 HTTP，Nginx 提供 HTTPS；公开接口和 `/internal/` 共用同一域名及 443 端口。内部接口校验独立机器人密钥、应用 ID 和群 ID。

将机器人服务地址设为该 HTTPS 地址，并将 `NOMI_BOT_API_TOKEN` 设置为服务端的 `NOMI_BOT_TOKEN`。密钥使用至少 32 位随机可见 ASCII 字符，仅保存在服务端和机器人配置中。

机器人默认使用系统信任链校验服务端证书和主机名。使用自签 CA 时，填写 `NOMI_TLS_CA_CERT=/path/to/server-ca.pem`。

## 维护

```shell
$ ./nomi-auth-neo backup backups/nomi.tar.gz
$ ./nomi-auth-neo restore backups/nomi.tar.gz restored-data
$ ./nomi-auth-neo disable Alice
$ ./nomi-auth-neo enable Alice
$ ./nomi-auth-neo cleanup
```

备份包含数据库快照、皮肤和签名私钥。恢复只写入新目录，不覆盖已有数据。

SQLite 迁往 MariaDB 时，配置空目标库后执行：

```shell
$ ./nomi-auth-neo migrate-database restored-data/nomi-auth.sqlite3
```

导入会核对全部记录，不修改源文件，目标非空时拒绝导入。

## 项目结构

```text
src/
├── main.rs    - 启动和维护命令
├── core/      - 配置、请求和凭证工具
├── http/      - HTTP、限流和清理
├── services/  - 账号、会话和游戏认证
└── storage/   - 数据库、备份和迁移
```
