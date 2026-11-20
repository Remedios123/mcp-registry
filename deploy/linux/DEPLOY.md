# Linux 内网试点（A 阶段）

本目录保存发布默认值和部署代码。机器密钥放在服务器的 `/data/mcp-gateway/config/gateway.env`，不要加入 Git。调用 `compose.sh` 时依次读取 `gateway.defaults.env` 和该实例文件，后者优先，已有完整 env 可直接沿用。Compose 也会读取调用进程中已导出的同名变量，因此使用干净的 sudo 环境；不要 source 私有 env。

## 需要操作员调整的项目

| 场景 | 修改位置 |
|---|---|
| 当前 10.100.3.74 无证书试点 | 仓库默认参数已指向实际入口和正式 CAS、UC。原交付包的实例 env 可直接使用。只要实例文件还显式列出默认值，它们就会优先于仓库设置。 |
| 新实例密码 | 需要 SECRET_KEY、AUTH_SERVER_NGINX_MARKER_SECRET、Mongo bootstrap 密码、Keycloak admin/初始 realm 管理员/DB/Web/M2M 密码、OPENBAO_TOKEN、SHIM_CLIENT_SECRET、SHIM_SIGNING_SECRET、SHIM_INTERNAL_TOKEN、认证后的 SHIM_MONGO_URI、metrics pepper/管理及采集 key、GRAFANA_ADMIN_PASSWORD。bootstrap 从 URI 取 shim 用户、密码和目标库；保持已有密钥。 |
| 更换 IP 或外部 origin | 更新 REGISTRY_URL、GATEWAY_ADDITIONAL_SERVER_NAMES 和 NO_PROXY；若实例文件显式指定公开 URL、回调或 MCPGW_BASE_URL，同步修改或去掉重复值，采用 Compose 派生值。 |
| CAS／UC 换环境 | 在实例文件覆盖 CAS_BASE、UC_AUTH_URL、UC_REFRESH_URL。使用公司 CA 时将受信证书链放入 config/ca，并指定 CAS_CA_BUNDLE=/etc/company-ca/文件名。 |
| WorkBuddy DCR 需要额外可信主机 | 确认实际主机名后才设置 KEYCLOAK_DCR_TRUSTED_HOSTS。使用已有 configure-cas.py 处理策略。 |
| 正式 HR 注册 | 在网关 UI 配服务地址和授权；在 B 阶段启用 UC egress 后验证员工调用。 |

## 首次启动及重复部署

通过堡垒机上传发布包，解压到 `/data/mcp-gateway/releases/<40位提交SHA>/`。先按原部署计划准备 Docker Engine、Buildx、Compose **2.24.4 或以上**，确认 Docker 和 containerd 数据落在 /data。确认私有 env 已安装，模型位于 `/data/mcp-gateway/models/bge-small-zh-v1.5` 且容器 UID 1000 可读。

进入发布根目录执行：

```bash
sudo bash deploy/linux/init-instance.sh
sudo bash deploy/linux/check-instance.sh
sudo bash deploy/linux/compose.sh ps -a
```

初始化脚本先生成本版本的 Nginx 模板，构建六个镜像，再启动 Keycloak、MongoDB、初始化任务和网关。容器内 Python 复用仓库的 realm 模板及 configure-cas.py；A 阶段使用开放 CAS 注册，工号为登录名。脚本单独创建 realm 管理员，重复运行保留已有管理员密码；Mongo 已有用户的凭据不自动重置。启动前仍需通过宿主机先检查正式 CAS、UC 的可达性。

在内网 Windows 运行 `powershell -File deploy/linux/check-browser.ps1` 检查站点和发现文档，再用浏览器测试登录、用 WorkBuddy 验证 `http://10.100.3.74:443/airegistry-tools/mcp`。Windows HTTP 探测和员工手动验收分开记录。容器从公司服务收到 HTTP 响应表示传输可达，业务鉴权另行验证。

## 入口和范围

Compose 复用 Registry 自带 Nginx，外部 443 转到 HTTP 8080。注册 MCP 后由上游生成动态路由。公司静态浏览器入口 /authorize、/cas/callback、/renew 在内部和公开模板之间隔离；shim 内部取证接口保持私有。生成的模板派生自本次发布的上游模板，源文件未改动。检查端口和 Nginx 后，再注册只读测试 MCP。默认 egress 关闭。

当前覆盖文件是 HTTP 试点。取得证书后再配置 B 阶段 TLS 监听、客户端与 broker 回调、仅内部可访问的受信 HTTPS 取证入口和 egress，然后验收真实员工 HR 链路。不要只打开 EGRESS_AUTH_ENABLED。
