# Linux HTTPS 部署

本版本的公开地址是 https://mcpgateway.geehy.com，宿主机为 10.100.3.74。使用 HTTPS 交付目录里的 ZIP 和配套 install-gateway.sh。公司域名在部署服务器和客户端都需要解析到该宿主机。

## 安装

在堡垒机的 Linux 终端运行：

```bash
mountpoint -q /data && mkdir -p /data/mcp-gateway/incoming
```

通过堡垒机把两个交付文件上传到该目录，再运行：

```bash
cd /data/mcp-gateway/incoming && bash install-gateway.sh
```

安装脚本检查域名、证书和上传文件，并为全新机器准备 Docker。旧实例已有不同密钥或不同证书时，会保留这些文件并提示核对。

## 随包配置

- 实例配置落在 /data/mcp-gateway/config/gateway.env。证书链和私钥落在该目录下的 tls 中，由 Compose 只读挂载，私钥访问权限限于 root 和容器运行组。
- Registry 容器里的 Nginx 提供外部 443，使用容器 8443。启动时用上游 HTTPS 模板生成配置，自动加载本目录的路由片段。
- 公司公开的 CAS 路径是 /authorize、/cas/callback 和 /renew。UC 取证由 Registry 通过容器回环地址 127.0.0.1:8093 访问 shim。公网入口上的取证路径返回 404。取证接口要求内部身份校验。
- Keycloak realm／client 和 shim 的 Mongo 用户由初始化脚本设置。CAS 签发的 UC Token 仅在后端使用，沿用已加密的 Mongo 存储。

## Windows 验收

打开 https://mcpgateway.geehy.com，确认浏览器信任证书并检查登录。WorkBuddy 使用 https://mcpgateway.geehy.com/airegistry-tools/mcp。HR 的地址和员工权限由管理员在网关 UI 配置，选择 UC Provider 后再验证搜索和调用。容器启动、域名可达、CAS 登录、UC 取证和 HR 调用分别记录实测结果。
