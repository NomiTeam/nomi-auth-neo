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

提交使用简短英文，例如 `add login retry tests`。每次提交只处理一个独立目的，完成实现和对应测试后再提交。

代码和注释使用英文，文档使用中文。保持方法职责明确，先校验再操作；优先用结构体和组合组织业务，不为每个字段添加访问方法。

## 兼容性检查

Rust 测试不能代替旧接口兼容性测试。具体命令和适配范围见 [兼容测试说明](tests/compatibility/README.md)。

运行真实 MariaDB 测试时，设置 `NOMI_TEST_MYSQL_DATABASE`、`NOMI_TEST_MYSQL_USER`、`NOMI_TEST_MYSQL_PASSWORD`，可选 `NOMI_TEST_MYSQL_HOST/PORT`。测试库名必须以 `nomi_auth_test_` 开头，其中的业务表会被清空。

```shell
cargo test --test storage -- --ignored --test-threads=1
```

Python 只用于开发阶段与旧实现对照，服务端运行不需要 Python。

更新依赖后，运行 `python scripts/collect_licenses.py` 更新 Linux 构建随附的第三方声明。该脚本只用于开发和分发准备。
