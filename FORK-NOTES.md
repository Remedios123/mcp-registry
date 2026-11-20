# 企业 CAS 和 UC 迁移记录

企业迁移最初基于上游 1.37.0（886c5437）。当前升级分支已合并上游正式版
1.38.0（18851bad），保留原生 Windows 部署适配。1.37.0 分支的升级前提交为 82075685。

## 行为对照

| 旧 fork 行为 | 1.37.0 迁移位置 |
| --- | --- |
| CAS 联邦、工号、开放注册和预绑定 | Keycloak 保留原生 OIDC broker。运行 [configure-cas.py](keycloak/setup/configure-cas.py) 配置 CAS，支持 open 与 whitelist。员工工号经受保护的 Employee ID 属性进入 Keycloak 令牌。员工邮箱可空，管理员邮箱登录沿用 realm 配置。 |
| UC 换票、刷新和补授权 | [cas-shim](cas-shim/README.md) 保留定点刷新、读时刷新及闲置截止。补授权回调检查实际 CAS 员工与发起员工一致。网关在原生代理完成工具授权后获取 UC，按部署允许的目标地址注入。 |
| 单入口搜索与代调用 | 在上游 Registry Tools MCP 上保留 search_registry_tools 和 invoke_tool。两者使用当前员工的网关身份。调用经 Nginx 和 auth-server 再检查目标工具权限。搜索继续使用上游语义 API，另迁移了工具级向量和中文测试集。 |
| 传输权限和审计 | 沿用上游 scope 和签名审计身份，恢复后台的 MCP 传输和发现方法选项。受验证的 CAS 工号供员工审计显示。Windows 的搜索计数回退使用原生文件锁。 |
| 客户端兼容 | 可启用同源 Keycloak OAuth，使用上游 /realms/ 与 /resources/ 代理和按服务的发现元数据。DeerFlow 仍使用单独的 Keycloak 客户端配置。 |
| 启停、诊断、HR 和 Data MCP | 查看 [Windows 部署说明](deploy/windows/README.md)。HR 与 Data MCP 的业务适配器由各自项目提供。此仓库负责它们的注册、权限和运行接入。 |

原生 Nginx 和 auth-server 承担数据面。旧 Python MCP 代理的环境变量
MCP_PROXY_ENABLED 和员工转发令牌没有迁入。WorkBuddy 客户端持有网关令牌，
UC 令牌由服务端使用。

## 配置迁移

- 部署环境启用 UC 一次。每个服务在编辑页的
  **Egress Auth → Per-user OAuth → Enterprise credentials** 选择 UC 后保存。
  沿用上游按服务和版本解析目的地址的逻辑，凭证只发给保存时登记的目标地址。
  提升默认版本时保留当前企业凭证绑定。新目标需重新保存，历史版本不会恢复旧绑定。
  旧 `upstreams` 白名单继续生效；采用 UI 管理地址前，先在升级版保存现有服务的授权，
  再从 `gateway.env` 中移除 `upstreams` 并重启。标准 OAuth 提供方继续使用上游配置。
- Keycloak 的用户名采用工号并沿用 realm 的大小写规则。CAS 联邦 ID 和受保护
  员工声明保留签发方的原始工号。预绑定只复用工号匹配的员工账号。
  部署时登记实际 CAS/UC 地址与精确回调 URI。证书需要私有 CA 时配置 PEM。
  [setup-cas.bat](deploy/windows/setup-cas.bat) 支持 Windows 首次配置、预绑定工号和
  初始化本机 MongoDB 认证。UC 令牌加密保存。旧明文 vault 的临时迁移开关
  见 [CAS shim 操作说明](cas-shim/README.md)。
- 可选同源模式使用 MCP_OAUTH_AS_ON_GATEWAY_REALM=true。将
  KEYCLOAK_EXTERNAL_URL 和 Keycloak 的 KC_HOSTNAME 设置为与 REGISTRY_URL
  相同的公开 origin。设置 KC_PROXY_HEADERS=xforwarded，KEYCLOAK_URL 仍指向
  私有 Keycloak。使用真实地址前检查浏览器回调、DCR 和签发令牌的 issuer。
- Win64 OpenResty 必须具备 Lua、cjson 和 auth_request。用对应运行目录生成
  配置，启停命令和外部服务地址从部署配置读取。保存应用配置、运行日志和密钥
  的目录独立于 Git 工作树。

## 验证记录

- 企业凭证回归验证同一 UC 配置可绑定多个 MCP 服务、未批准的地址在读取凭证前被拒绝、
  只允许管理员保存绑定、默认版本切换保留当前授权，以及普通员工响应隐藏内部地址。
  旧部署白名单兼容，前端类型检查和 Windows 生产构建通过。
- 双击配置在全新实例和含空格、中文的路径下通过，重复运行保留密钥。
  在新的 Windows 实例中验证七个本机服务就绪、自动登记 CAS broker、
  首个工号无邮箱预绑定、MongoDB 拒绝匿名读取及正常停止。
  单独验证无认证的旧本机数据库启用认证后原数据保留。测试使用占位 CAS/UC 地址。
- 在原生 Windows、Python 3.14、Keycloak 25、MongoDB 8.2 和 OpenResty 上跑通干净
  上游。管理页和登录重定向通过，临时测试 MCP 注册、启用和原生代理调用分别
  返回 201、200 和 200。Nginx 配置检查和重载通过。
- CAS 和出站凭证回归、后台凭证选项、搜索和代调用、Windows 原生 MongoDB
  语义 API、OAuth 元数据和 Keycloak provider 均有自动回归。回归用独立测试数据。
- 在原生 Windows 重启后，MongoDB、Keycloak、CAS shim、Registry Tools、
  auth-server、Registry 和 OpenResty 均通过就绪检查。用模拟 CAS 服务票据
  走通实际 Keycloak 的 OIDC broker，验签确认员工令牌工号原样保留，员工邮箱为空。
  本机 MCP 入口通过原生代理列出搜索和调用工具，无授权组时返回 403。
  用同一个已授权工号执行中文搜索，在未注册真实 HR 服务的实例中返回无匹配。
- MCP SDK 回归验证缺 UC 时补授权链接完整传回。第二个模拟签发方的路由和
  凭证归属检查通过。第二个签发方返回 UC 凭证时拒绝使用，CD 缺凭证时仍可取 UC。
- 分支迁移回归通过 CAS 和 OAuth 602 项、WorkBuddy 和搜索评估 71 项、代理凭证处理 24 项、前端 44 项。全量 Windows 回归在最终修改前启动，共 11,734 项通过、87 项失败、57 项跳过。失败包含原生环境的 POSIX 权限位、Bash 路径和扫描器依赖测试；最终修改的凭证故障回归另行通过。全量套件尚未通过。
- 本机回环基线禁用了安全扫描，因为上游锁定的 yara-python 在 Windows
  Python 3.14 需要 MSVC 构建工具。部署默认设置沿用上游。

## 撤销 MCP 访问权限

旧 Python 代理将权限校验的 403 作为认证失败返回 401，并附 OAuth 发现提示，
客户端会据此尝试重新授权。1.37.0 原生代理将 IAM 拒绝返回为 403 和 MCP
错误响应。原生 Windows 使用同一枚测试令牌验证了授权、撤销、恢复三步，
依次得到 200、403、200。无令牌请求仍返回带 OAuth 发现提示的 401。
WorkBuddy 界面的撤销状态待使用真实客户端验收。

## 内网与后续联调

- 用两名真实员工从 WorkBuddy 全新连接，验证无邮箱员工 CAS 首登、无 HR
  工具权限员工能取得工号、中文搜索、HR 只读调用及补授权。同步验证 Data MCP、
  豆包同源 DCR 和 DeerFlow 浏览器流程。
- CD 若支持 OAuth 授权码流程，先用上游标准 OAuth 配置。需确认其授权和令牌
  端点、client 注册与回调、scope、稳定员工标识和刷新规则。
- CD 若使用私有 CAS 换票，需确认单独 CAS service、票据兑换参数、员工标识字段、
  令牌和到期响应、续期和撤销接口。登记其凭证配置后验证真实 UC/CD 并存及逐项首开。
  目前员工工号来自 UC 换票响应。若 CD 专用员工无法在 UC 取得工号，需确定可验证的 CAS 工号来源。
- Linux 镜像和 Compose 打包放到后续。
