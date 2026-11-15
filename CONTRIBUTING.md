# 开发指南

请不要将改动直接 push 到 main，而是在 dev 开发并创建 PR。

## 环境

安装 Rust stable、rustfmt、Clippy 和 C 编译器。辅助检查使用 Python 3.13 和 uv。

```shell
$ cargo build
```

编译后的程序位于 `target/debug`。

## 同步

先 commit 或 stash 本地改动，再同步 main 到当前分支：

```shell
$ git fetch origin
$ git merge origin/main
```

解决冲突后提交；放弃合并可使用 `git merge --abort`。

## 审查

提交前在项目根目录执行：

```shell
$ cargo fmt --all --check
$ cargo clippy --all-targets -- -D warnings
$ uvx ruff check scripts tests/test_release.py
$ uvx ruff format --check scripts tests/test_release.py
```

## 测试

```shell
$ cargo test --all-targets
$ python -m unittest discover -s tests -p test_release.py -v
```

配置独立的 `NOMI_TEST_MYSQL_DATABASE/USER/PASSWORD` 后，可运行 MariaDB 测试：

```shell
$ cargo test --test storage -- --ignored --test-threads=1
```

测试库名必须以 `nomi_auth_test_` 开头，其中的业务表会被清空。可选配置 `NOMI_TEST_MYSQL_HOST/PORT`。

Linux 安装 Nginx 后，可检查真实证书和机器人客户端：

```shell
$ uv run --with httpx --with cryptography --with pydantic python scripts/test_https.py --neo-binary target/release/nomi-auth-neo --plugin-reference /path/to/nomi-auth-plugin
```

脚本在随机本地端口启动独立 Nginx，退出时清理临时进程、证书和数据。

## 发布

先更新 `Cargo.toml` 中的版本，用 Cargo 更新 `Cargo.lock`，再通过 PR 合并 main。以 `0.1.0` 为例：

```shell
$ git fetch origin
$ git tag v0.1.0 origin/main
$ git push origin v0.1.0
```

工作流核对版本和 main 归属，编译并启动检查 Linux musl 与 Windows MSVC 程序。Windows 静态链接 CRT，并检查额外运行库依赖。

发布名与 tag 相同，附件为 Linux 的 tar.gz 和 Windows 的 zip。包内程序名不带版本号，包含配置示例和对应平台的许可证。两包上传完成后才公开 release，已公开版本不会自动覆盖。

PR 和手动运行生成测试包，tag 推送执行正式发布。更新依赖后，用 `python scripts/collect_licenses.py` 更新第三方声明。

---

以上检查通过后即可提交代码并创建 PR。
