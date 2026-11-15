# 开发指南

日常开发使用 `dev`。合并 `main` 必须通过 PR，检查通过后再审核合并。

## 环境

安装 Rust stable，包括 rustfmt 和 Clippy。SQLite 随程序编译，开发环境需要 C 编译器。

## 检查与测试

```shell
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

提交信息与 PR 描述都需要 `Co-authored-by` 共同作者署名。

提交使用简短英文，例如 `add login retry tests`。每次提交只处理一个独立目的，完成实现和对应测试后再提交。

代码和注释使用英文，文档使用中文。保持方法职责明确，先校验再操作；优先用结构体和组合组织业务，不为每个字段添加访问方法。

## 兼容性检查

Rust 测试不能代替旧接口兼容性测试。具体命令和适配范围见 [兼容测试说明](tests/compatibility/README.md)。

运行真实 MariaDB 测试时，设置 `NOMI_TEST_MYSQL_DATABASE`、`NOMI_TEST_MYSQL_USER`、`NOMI_TEST_MYSQL_PASSWORD`，可选 `NOMI_TEST_MYSQL_HOST/PORT`。测试库名必须以 `nomi_auth_test_` 开头，其中的业务表会被清空。

```shell
cargo test --test storage -- --ignored --test-threads=1
```

Python 只用于开发阶段与旧实现对照，服务端运行不需要 Python。

更新依赖后，运行 `python scripts/collect_licenses.py` 更新 Linux 第三方声明。发布流程用 `--target` 为两个平台分别收集许可证。

## 发布

先在 `dev` 更新 `Cargo.toml` 的包版本，并用 Cargo 更新 `Cargo.lock`，通过 PR 合并 `main`。当前版本为 `0.1.0`，对应 tag 为 `v0.1.0`。

```shell
git fetch origin
git tag v0.1.0 origin/main
git push origin v0.1.0
```

工作流会核对 tag、包版本和 `main` 归属，构建并启动检查 Linux musl 与 Windows MSVC 程序。Windows 静态链接 CRT，并检查额外运行库依赖。

发布名与 tag 相同，附件仅为 `nomi-auth-neo-linux-x86_64.tar.gz` 和 `nomi-auth-neo-windows-x86_64.zip`。包内程序名不带版本号，并包含配置示例和对应平台的第三方声明。两包上传完成后才公开 release；失败可重跑草稿，已公开版本不会被自动覆盖。

PR 和手动运行只产生测试构建，不创建 tag 或 release。
