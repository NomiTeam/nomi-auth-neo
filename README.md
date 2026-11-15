# Nomi Auth Neo

基于 Rust 的 QQ 群验证码认证服务，提供登录、注册、改名、皮肤和 Yggdrasil 接口，支持 SQLite 和 MariaDB。

搭配 [Nomi Launcher](https://github.com/NomiTeam/nomi-launcher) 和 [Nomi Auth Plugin](https://github.com/NomiTeam/nomi-auth-plugin) 使用。

接口说明在 [API.md](API.md)，开发说明在 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 运行

[发布包](https://github.com/NomiTeam/nomi-auth-neo/releases)提供 Linux 和 Windows x86_64 版本，程序无需额外安装运行库。使用 MariaDB 时，需要已有的数据库服务。

将 `.env.example` 复制为 `.env`，填写公网地址、机器人凭证、应用 ID 和群 ID，然后执行：

```shell
$ chmod +x nomi-auth-neo
$ ./nomi-auth-neo serve --host 127.0.0.1 --port 8000
```

Windows 使用 `nomi-auth-neo.exe`。配置从当前目录读取，环境变量优先。直接运行程序使用上述默认地址。

`NOMI_DATABASE_BACKEND` 可设为 `sqlite`、`mysql` 或 `mariadb`，其他字段见 `.env.example`。

> 替换程序前请停止服务并备份整个数据目录。数据库、`texture-signing.pem` 和 `textures/` 应一起保留，不要让多个服务进程同时写入。

## Nginx

参考 [nginx.conf](deploy/nginx.conf)，修改域名、服务端证书、专用客户端 CA 和后端地址，再检查配置：

```shell
$ nginx -t
```

检查通过后再重载。后端只监听本机地址，开启 `NOMI_INTERNAL_MTLS_REQUIRED=true`。

公开接口和 `/internal/` 共用同一域名及 443 端口。公开接口不需要客户端证书；内部接口必须通过证书验证，随后校验机器人凭证。配置会覆盖验证头，不接受客户端自报结果。

为机器人签发带 `clientAuth` 用途的证书，在机器人配置中填写：

```dotenv
NOMI_TLS_CLIENT_CERT=/path/to/client.pem
NOMI_TLS_CLIENT_KEY=/path/to/client-key.pem
NOMI_TLS_CA_CERT=/path/to/server-ca.pem
```

服务端证书使用公共 CA 时，最后一项可留空。客户端 CA 私钥离线保管，机器人私钥仅允许服务用户读取；证书到期前替换并重启机器人。

> 若域名使用 CDN，机器人应直连源站。可只在机器人机器的 hosts 中将该域名解析到源站 IP，仍以域名访问并校验证书。普通 CDN 无法透传客户端证书。

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
