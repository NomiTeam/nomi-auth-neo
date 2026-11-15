# 机器人双向 TLS

公开接口和机器人接口共用同一域名、同一 HTTPS 端口，后端只监听 `127.0.0.1`。TLS 层允许不提供客户端证书；只有 `/internal/` 要求证书验证成功，随后继续校验原有 Bearer Token。

1. 为机器人准备专用客户端 CA，签发带 `clientAuth` 用途的证书。CA 私钥离线保存，不放到服务器。不要把公共 Web CA 用作客户端 CA。
2. 修改 [Nginx 配置](nginx.conf) 中的域名、证书路径和后端地址。服务器证书须覆盖该域名；客户端信任其签发 CA。两个接口均使用 `443`，不需要另开端口或域名。
3. 后端设置 `NOMI_INTERNAL_MTLS_REQUIRED=true`，监听 `127.0.0.1:8000`。执行 `nginx -t`，通过后再重载 NGINX。
4. 机器人填写 `NOMI_AUTH_BASE_URL`、`NOMI_TLS_CLIENT_CERT`、`NOMI_TLS_CLIENT_KEY`；服务器使用私有 CA 时，另填 `NOMI_TLS_CA_CERT`。仍使用原有 `NOMI_BOT_API_TOKEN`。私钥仅允许机器人服务用户读取。

公开路径清除客户端传入的 `X-Nomi-Client-Verify`；内部路径拒绝未通过证书验证的请求，并用 Nginx 的真实验证结果覆盖该请求头。`ssl_verify_client optional` 只允许公开路径匿名连接，不会放开内部接口。不要将后端端口对外开放。

如果域名使用 CDN，机器人仍须直连源站，因为客户端证书不能经普通 CDN 透传。可以只在机器人机器上用 hosts 将相同域名解析到源站 IP；玩家的公共 DNS 不变。仍以域名作为请求地址，保留服务端证书和主机名校验，不使用 IP URL 或关闭验证。

证书到期前替换客户端证书并重启机器人。需要立即撤销某个证书时，可配置 NGINX 的 `ssl_crl` 并更新吊销列表；更换专用 CA 会使该 CA 签发的全部旧证书失效。

## 本地验证

Linux 安装 NGINX 后，在开发环境运行：

```sh
python scripts/test_mtls.py --neo-binary ./nomi-auth-neo --nginx /usr/sbin/nginx
```

脚本依赖开发测试用的 `httpx` 和 `cryptography`。加上 `--plugin-reference /path/to/nomi-auth-plugin` 可验证真实机器人客户端的登录、注册、改名流程，另需 `pydantic`。它生成临时证书，在随机本地端口启动独立 NGINX 和服务端；退出时停止进程并删除临时数据，不读取或重载系统 NGINX 配置。
