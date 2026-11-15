# Nomi Auth Neo

这是 [Nomi Auth](https://github.com/NomiTeam/nomi-auth) 的 Rust 实现。提供群验证码登录、账号注册、改名、皮肤和 Yggdrasil 接口，保持现有启动器与机器人协议兼容。

## 运行

Linux x86_64 使用 musl 静态构建，不需要安装 Rust、Python、OpenSSL 或 SQLite 运行库。使用 MariaDB 时，仍需要已有的数据库服务。

将 `.env.example` 复制为 `.env`，填写原来的机器人服务凭证、应用 ID、群 ID 和公网地址，然后执行：

```shell
chmod +x nomi-auth-neo
./nomi-auth-neo serve --host 127.0.0.1 --port 8000
```

直接运行 `./nomi-auth-neo` 使用同样的默认地址。配置从当前目录的 `.env` 读取，环境变量优先，沿用 `NOMI_*` 名称。

公网部署机器人的内部接口时，按 [mTLS 配置](deploy/MTLS.md) 配置同域名、同端口的路径验证，并启用 `NOMI_INTERNAL_MTLS_REQUIRED=true`。示例配置已开启；缺少证书验证的内部请求会被拒绝。旧配置未设置该项时维持原行为。

接口说明见 [API.md](API.md)。健康检查为 `/health`，认证根路径为 `/api/yggdrasil/`。不提供 HTML 页面、在线文档或 OpenAPI JSON。

## 数据兼容

`NOMI_DATABASE_BACKEND` 可设为 `sqlite`、`mysql` 或 `mariadb`。SQLite 默认使用数据目录内的 `nomi-auth.sqlite3`；MySQL/MariaDB 连接字段见 `.env.example`。

从旧服务切换时，先停止旧进程并保留完整备份。新程序使用原配置与数据目录即可读取现有数据，不能让新旧服务同时写入。

数据目录中的数据库、`texture-signing.pem` 和 `textures/` 应一起保留，不能只复制数据库。UUID、群绑定、游戏令牌、刷新令牌、去重回执和重试记录均沿用原格式。改名不会改变 UUID，已有皮肤的签名密钥不会被替换。

## 维护命令

```shell
./nomi-auth-neo backup backups/nomi.tar.gz
./nomi-auth-neo restore backups/nomi.tar.gz restored-data
./nomi-auth-neo disable Alice
./nomi-auth-neo enable Alice
./nomi-auth-neo cleanup
```

完整备份与旧服务兼容，包含 SQLite 快照、当前皮肤和签名私钥。恢复只写入新目录，不覆盖已有数据。

SQLite 迁往 MariaDB 时，配置独立空库后执行：

```shell
./nomi-auth-neo migrate-database restored-data/nomi-auth.sqlite3
```

导入只读源文件，在一个事务中核对所有记录；非空目标会拒绝导入。MySQL/MariaDB 的完整备份也可恢复回 SQLite。

## 项目结构

```text
src/
├── main.rs    - 启动与维护命令
├── core/      - 配置、请求、错误和凭证工具
├── http/      - HTTP、参数解析、限流和后台清理
├── services/  - 账号、登录、会话、改名、皮肤和游戏认证
└── storage/   - 数据库、表结构升级、备份和迁移
```

账号操作在同一写事务中校验和更新。MariaDB 使用与旧服务一致的连接级写锁，防止同一码被重复领取、令牌重复轮换或备份与皮肤更新交错。建议单进程运行；分布式限流和跨机器皮肤共享不在当前范围内。

## 构建与测试

开发流程见 [CONTRIBUTING.md](CONTRIBUTING.md)。本机构建使用 `cargo build --release`。

Linux 静态交叉构建需要 musl 目标和 cargo-zigbuild：

```shell
rustup target add x86_64-unknown-linux-musl
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl
```

输出为 `target/x86_64-unknown-linux-musl/release/nomi-auth-neo`。应在 Linux 上确认 `file` 显示静态链接，`readelf` 没有动态依赖，并运行接口测试；不能只以编译成功判断兼容性。

GitHub 发布工作流支持 Linux x86_64 静态程序和 Windows x86_64 程序。`main` 历史中的 `v版本号` tag 会触发发布，tag 必须与 Cargo 包版本一致；PR 和手动运行只构建测试包。操作步骤见 [开发指南](CONTRIBUTING.md)。

`deploy/` 提供 systemd 示例，按实际目录和服务用户修改。生产环境不需要开发工具或容器。

使用示例服务前，先创建可写目录（路径和用户与服务文件保持一致）：

```shell
sudo install -d -o www-data -g www-data -m 700 /srv/nomi-auth-neo/data /srv/nomi-auth-neo/backups
```

本机 Nginx 反代时，设置 `proxy_set_header X-Forwarded-For $remote_addr;` 和 `proxy_set_header X-Forwarded-Proto $scheme;`，覆盖客户端传入的同名头。服务仅信任来自回环地址的这两个头，用于限流与跳转地址。
