# 机器人双向 TLS

公开接口和机器人接口使用两个 HTTPS 入口，后端只监听 `127.0.0.1`。机器人入口直连 NGINX，不经过 CDN；客户端证书和原有 Bearer Token 都验证通过后才能调用内部接口。

1. 为机器人准备专用客户端 CA，签发带 `clientAuth` 用途的证书。CA 私钥离线保存，不放到服务器。不要把公共 Web CA 用作客户端 CA。
2. 修改 [公开入口](nginx-public.conf) 和 [机器人入口](nginx-internal.conf) 中的域名、证书路径和后端地址，加入 NGINX 配置。服务器证书覆盖对应域名，客户端信任其签发 CA。内部入口默认使用 `8443` 端口。
3. 后端设置 `NOMI_INTERNAL_MTLS_REQUIRED=true`，监听 `127.0.0.1:8000`。执行 `nginx -t`，通过后再重载 NGINX。
4. 机器人填写 `NOMI_AUTH_BASE_URL`、`NOMI_TLS_CLIENT_CERT`、`NOMI_TLS_CLIENT_KEY`；服务器使用私有 CA 时，另填 `NOMI_TLS_CA_CERT`。仍使用原有 `NOMI_BOT_API_TOKEN`。私钥仅允许机器人服务用户读取。

公开入口禁止 `/internal`，并清除客户端传入的 `X-Nomi-Client-Verify`。内部入口强制验证证书，只转发 `/internal/`，用 NGINX 的验证结果覆盖该请求头。不要将后端端口对外开放，也不要让其他代理绕过这两份规则。

证书到期前替换客户端证书并重启机器人。需要立即撤销某个证书时，可配置 NGINX 的 `ssl_crl` 并更新吊销列表；更换专用 CA 会使该 CA 签发的全部旧证书失效。

## 本地验证

Linux 安装 NGINX 后，在开发环境运行：

```sh
python scripts/test_mtls.py --neo-binary ./nomi-auth-neo --nginx /usr/sbin/nginx
```

脚本依赖开发测试用的 `httpx` 和 `cryptography`。加上 `--plugin-reference /path/to/nomi-auth-plugin` 可验证真实机器人客户端的登录、注册、改名流程，另需 `pydantic`。它生成临时证书，在随机本地端口启动独立 NGINX 和服务端；退出时停止进程并删除临时数据，不读取或重载系统 NGINX 配置。
