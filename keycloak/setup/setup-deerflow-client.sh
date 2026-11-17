#!/bin/bash
# 创建/更新 deerflow 的 Keycloak client（甲方案前置，见 docs/design/deerflow-cas-integration.md §5.A）
# 幂等：可重复运行。改动点：
#   1. client "deerflow"（confidential + PKCE S256 + standard flow）
#   2. redirect_uri 指向 df 统一入口的 OIDC 回调
#   3. audience "mcp-gateway"：**不需要**在本 client 上重复声明。realm 的 `basic`
#      client-scope 已挂 mcp-gateway-audience mapper（oidc-audience-mapper，
#      included.custom.audience=mcp-gateway），client 只要分配了 basic 就自动带上。
#      2026-10-29 实测：client 级 protocol-mappers 为空时 /validate 仍返回 200。
#   4. defaultClientScopes: basic + profile + email + offline_access。
#      basic=aud/groups 来源，offline_access=离线 refresh 必需，profile/email 对应 df 请求的 scope，
#      openid 由 Keycloak 隐式处理无需分配。
#      **不要**多加 roles / web-origins：df 用不到，加上会让每次重跑都新增 scope、失掉幂等。
#      注意 PUT /admin/clients/{id} 会忽略该字段，故下方用专用子端点幂等补齐。
set -euo pipefail
cd "$(dirname "$0")/../.." || exit 1
set -a; source .env; set +a

KEYCLOAK_URL="${KEYCLOAK_ADMIN_URL:-${KEYCLOAK_URL}}"
REALM="${KEYCLOAK_REALM:-mcp-gateway}"
DF_CLIENT_ID="deerflow"
DF_ORIGIN="${DEERFLOW_ORIGIN:-http://192.168.37.132:2027}"
DF_REDIRECT="${DEERFLOW_REDIRECT_URI:-${DF_ORIGIN}/api/v1/auth/callback/mcp-gateway}"
DF_REDIRECT_LOCAL="http://127.0.0.1:2027/api/v1/auth/callback/mcp-gateway"

if [ -z "${KEYCLOAK_ADMIN:-}" ] || [ -z "${KEYCLOAK_ADMIN_PASSWORD:-}" ]; then
    echo "缺少 KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD（根 .env）" >&2
    exit 1
fi

# 管理员令牌（master realm admin-cli，与 init-keycloak.sh 相同）
TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "username=${KEYCLOAK_ADMIN}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
    -d "client_id=admin-cli" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
if [ -z "${TOKEN:-}" ]; then
    echo "获取管理员令牌失败（检查 KEYCLOAK_URL=${KEYCLOAK_URL} 与管理员凭据）" >&2
    exit 1
fi

# JSON 解析器探测：本机（Windows Git Bash）实测**没有 jq**，若硬依赖 jq 会让下面的
# scope 挂载循环全部静默跳过、脚本仍以成功状态退出。故 jq 优先，退化到 python/py。
JSON_TOOL=""
if command -v jq >/dev/null 2>&1; then
    JSON_TOOL="jq"
elif command -v python3 >/dev/null 2>&1; then
    JSON_TOOL="python3"
elif command -v python >/dev/null 2>&1; then
    JSON_TOOL="python"
else
    echo "缺少 jq 或 python，无法解析 Keycloak 的 JSON 响应" >&2
    exit 1
fi

# 从 client-scopes 列表 JSON（stdin）里按 name 取 id；找不到输出空串
scope_id_of() {
    if [ "${JSON_TOOL}" = "jq" ]; then
        jq -r --arg n "$1" '.[] | select(.name==$n) | .id'
    else
        "${JSON_TOOL}" -c 'import sys,json
d=json.load(sys.stdin)
print(next((s["id"] for s in d if s.get("name")==sys.argv[1]),""))' "$1"
    fi
}

# client secret：优先用 .env 里的 DEERFLOW_CLIENT_SECRET，否则生成并回写 .env
SECRET="${DEERFLOW_CLIENT_SECRET:-}"
if [ -z "${SECRET}" ]; then
    SECRET=$(openssl rand -hex 24)
    printf '\n# deerflow Keycloak client（甲方案，见 docs/design/deerflow-cas-integration.md）\nDEERFLOW_CLIENT_SECRET=%s\nDEERFLOW_REDIRECT_URI=%s\n' "${SECRET}" "${DF_REDIRECT}" >> .env
    echo "已生成 client secret 并写入根 .env 的 DEERFLOW_CLIENT_SECRET"
fi

CLIENT_JSON=$(cat <<EOF
{
    "clientId": "${DF_CLIENT_ID}",
    "name": "DeerFlow Agent Client",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "secret": "${SECRET}",
    "redirectUris": ["${DF_REDIRECT}", "${DF_REDIRECT_LOCAL}"],
    "webOrigins": ["${DF_ORIGIN}"],
    "attributes": {
        "post.logout.redirect.uris": "${DF_ORIGIN}/*",
        "pkce.code.challenge.method": "S256"
    },
    "protocol": "openid-connect",
    "standardFlowEnabled": true,
    "implicitFlowEnabled": false,
    "directAccessGrantsEnabled": false,
    "serviceAccountsEnabled": false,
    "publicClient": false,
    "fullScopeAllowed": false,
    "defaultClientScopes": ["basic", "profile", "email", "offline_access"]
}
EOF
)

# 幂等 upsert（与 init-keycloak.sh 相同模式；|| true 容忍"不存在"的 grep 空匹配）
existing_id=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
    "${KEYCLOAK_URL}/admin/realms/${REALM}/clients?clientId=${DF_CLIENT_ID}" \
    | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4 || true)

if [ -z "${existing_id}" ]; then
    status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/clients" \
        -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
        -d "${CLIENT_JSON}")
    if [ "${status}" = "201" ]; then
        echo "client ${DF_CLIENT_ID} created"
    else
        echo "create failed (HTTP ${status})" >&2
        exit 1
    fi
else
    status=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${existing_id}" \
        -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
        -d "${CLIENT_JSON}")
    if [ "${status}" = "204" ]; then
        echo "client ${DF_CLIENT_ID} updated"
    else
        echo "update failed (HTTP ${status})" >&2
        exit 1
    fi
fi

# POST 分支走完 existing_id 仍是空值（POST 不返回 id），而下面的 scope 挂载与
# secret 回读都要用它，故这里统一重查一次。教训：别在"新建"路径上复用"更新"路径的变量。
existing_id=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
    "${KEYCLOAK_URL}/admin/realms/${REALM}/clients?clientId=${DF_CLIENT_ID}" \
    | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4 || true)
if [ -z "${existing_id}" ]; then
    echo "upsert 后仍查不到 client！" >&2
    exit 1
fi

# PUT /admin/clients/{id} 会忽略 defaultClientScopes（Keycloak 行为，见设计文档 §9 踩坑 1），
# 已存在的 client 必须用专用子端点逐个挂载。缺 basic 会丢 aud=mcp-gateway 与 groups（→ /validate 401
# 或权限查不到）；缺 offline_access 会拿不到离线 refresh（静默续期活不过 SSO 空闲 30 分钟）。
SCOPES_JSON=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
    "${KEYCLOAK_URL}/admin/realms/${REALM}/client-scopes")
for scope_name in basic profile email offline_access; do
    scope_id=$(printf '%s' "${SCOPES_JSON}" | scope_id_of "${scope_name}" 2>/dev/null || true)
    if [ -z "${scope_id}" ] || [ "${scope_id}" = "null" ]; then
        echo "warn: realm 里没有 client-scope '${scope_name}'，跳过" >&2
        continue
    fi
    sc=$(curl -sS -o /dev/null -w "%{http_code}" -X PUT \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${existing_id}/default-client-scopes/${scope_id}" \
        -H "Authorization: Bearer ${TOKEN}")
    # 204 = 已生效（Keycloak 对"本来就挂着"的 scope 也返回 204，不是 409），天然幂等
    echo "  default scope ${scope_name} -> HTTP ${sc}"
done

# 验证：secret 回读一致（不打印 secret 本体）
got_secret=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
    "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${existing_id}/client-secret" \
    | grep -o '"value":"[^"]*' | cut -d'"' -f4 || true)
if [ "${got_secret}" = "${SECRET}" ]; then
    echo "secret 回读一致 ✓"
else
    echo "secret 回读不一致！" >&2
    exit 1
fi
echo "redirect_uri = ${DF_REDIRECT}"
echo "aud = mcp-gateway（继承自 basic scope，无需 client 级 mapper）"
echo "已挂载 defaultClientScopes 见上方逐项输出"
