# 旧接口兼容测试

这里用旧项目的 `test_service.py` 检查真实 Rust 进程。请求通过 HTTP 发送，不使用 Python 认证服务替代 Rust 实现。

先构建 Rust 程序，再在旧项目的 Python 环境中加载 `neo_bridge` 插件。`PYTHONPATH` 需要包含旧项目根目录和本目录；例如在 Linux 下，从新项目根目录执行：

```shell
cargo build
PYTHONPATH=../nomi-auth:tests/compatibility uv run --project ../nomi-auth pytest ../nomi-auth/tests/test_service.py -p neo_bridge --neo-binary target/debug/nomi-auth-neo --ref ../nomi-auth -q
```

Windows 的 `PYTHONPATH` 使用分号分隔，程序路径加 `.exe`。

测试会启动独立进程、使用测试目录及临时端口，并在每项测试后关闭所有进程。同目录重启会先关闭旧进程。测试日志保存在系统临时目录，方便排查启动失败。

旧项目的数据库帮助类只用于准备测试数据及 SQL 断言。只有 Rust 完成数据库初始化后，适配层才允许创建帮助类；清理操作调用 Rust CLI。Python 直接执行表升级的测试、依赖 monkeypatch Python 时钟的测试会明确跳过，由 Rust 原生测试覆盖。

若设置旧测试套件要求的 `NOMI_TEST_MYSQL_*`，也会运行 MariaDB 测试。测试库必须独立，不能使用生产库。
