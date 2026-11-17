#!/bin/bash
# 把 Keycloak 登录页改成全中文, 并把 CAS 联邦按钮文案改成"企业内部登录"。
# 用法: bash set-login-zh.sh            (幂等, 可反复执行)
#
# 做三件事:
#   1. 打开 realm 本地化, 只挂 zh-CN 并设为默认(单一语言 -> 不出现语言切换下拉)
#   2. 身份提供方 cas 的 displayName 设为"企业内部登录"(否则按钮显示别名 "cas")
#   3. 覆盖两处中文包细节: 半角问号 -> 全角; "用户名 或 电子邮箱地址" -> "用户名或邮箱"
#
# 刻意不动 realm 的 displayName: 留空时登录卡片标题回退显示 realm 名 "mcp-gateway",
# 这是期望行为。要换标题再另行设置该字段。
set -euo pipefail
cd "$(dirname "$0")/../.." || exit 1
set -a; source .env; set +a

python <<'EOF'
import base64, hashlib, html, json, os, re, urllib.parse, urllib.request, urllib.error

KC = os.environ.get("KEYCLOAK_ADMIN_URL", "http://localhost:8080").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM", "mcp-gateway")
ADMIN = os.environ.get("KEYCLOAK_ADMIN", "admin")
LOCALE = "zh-CN"
CAS_BUTTON_LABEL = "企业内部登录"
TEXTS = {
    "usernameOrEmail": "用户名或邮箱",
    "doForgotPassword": "忘记密码？",
}


def token():
    form = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": ADMIN,
        "password": os.environ["KEYCLOAK_ADMIN_PASSWORD"],
    }).encode()
    req = urllib.request.Request(
        KC + "/realms/master/protocol/openid-connect/token",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return json.loads(urllib.request.urlopen(req, timeout=15).read())["access_token"]


def api(method, path, body=None):
    req = urllib.request.Request(
        f"{KC}/admin/realms/{REALM}{path}",
        method=method,
        headers={"Authorization": "Bearer " + token(), "Content-Type": "application/json"},
        data=json.dumps(body).encode() if body is not None else None,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


# ---- 1. realm 本地化 ----
st, realm = api("GET", "")
if st != 200:
    raise SystemExit(f"读取 realm 失败: {st} {realm}")
changed = []
if not realm.get("internationalizationEnabled"):
    realm["internationalizationEnabled"] = True
    changed.append("internationalizationEnabled")
if realm.get("supportedLocales") != [LOCALE]:
    realm["supportedLocales"] = [LOCALE]
    changed.append("supportedLocales")
if realm.get("defaultLocale") != LOCALE:
    realm["defaultLocale"] = LOCALE
    changed.append("defaultLocale")
if changed:
    st, body = api("PUT", "", realm)
    print(f"realm 更新 {changed} -> {st}" + ("" if st in (200, 204) else f" {body}"))
else:
    print("realm 本地化已就绪, 无需变更。")

# ---- 2. CAS 按钮文案 ----
st, idp = api("GET", "/identity-provider/instances/cas")
if st != 200:
    print(f"跳过 CAS 按钮: 读不到身份提供方 cas ({st}); 先跑 add-cas-broker.sh。")
elif idp.get("displayName") == CAS_BUTTON_LABEL:
    print(f"CAS 按钮文案已是「{CAS_BUTTON_LABEL}」, 无需变更。")
else:
    idp["displayName"] = CAS_BUTTON_LABEL
    st, body = api("PUT", "/identity-provider/instances/cas", idp)
    print(f"CAS 按钮文案 -> 「{CAS_BUTTON_LABEL}」 ({st})" + ("" if st in (200, 204) else f" {body}"))

# ---- 3. 中文包细节覆盖(批量写入用 POST, 单 key 才用 PUT) ----
req = urllib.request.Request(
    f"{KC}/admin/realms/{REALM}/localization/{LOCALE}",
    data=json.dumps(TEXTS, ensure_ascii=False).encode(),
    headers={"Authorization": "Bearer " + token(), "Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        print(f"文案覆盖 {list(TEXTS)} -> {r.status}")
except urllib.error.HTTPError as e:
    print(f"文案覆盖失败 {e.code} {e.read().decode()[:200]}")


# ---- 复查: 真发一次授权请求, 看渲染出来的字 ----
client_id = os.environ.get("DEERFLOW_CLIENT_ID", "deerflow")
redirect_uri = os.environ.get("DEERFLOW_REDIRECT_URI", "")
if not redirect_uri:
    st, c = api("GET", f"/clients?clientId={client_id}")
    if st == 200 and c:
        uris = c[0].get("redirectUris") or []
        redirect_uri = uris[0] if uris else ""
if not redirect_uri:
    print("复查跳过: 找不到 redirect_uri。")
    raise SystemExit(0)

verifier = base64.urlsafe_b64encode(os.urandom(48)).decode().rstrip("=")
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
q = urllib.parse.urlencode({
    "client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
    "scope": "openid profile email", "state": "zh-check", "nonce": "zh-check",
    "code_challenge": challenge, "code_challenge_method": "S256",
})
try:
    page = urllib.request.urlopen(
        urllib.request.Request(f"{KC}/realms/{REALM}/protocol/openid-connect/auth?{q}",
                               headers={"User-Agent": "Mozilla/5.0"}),
        timeout=15,
    ).read().decode("utf-8", "replace")
except Exception as e:  # 复查只是辅助, 失败不影响配置
    print(f"复查跳过: 取登录页失败 ({e})")
    raise SystemExit(0)

stripped = re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>", " ", page)
stripped = re.sub(r"<[^>]+>", "\n", stripped)
seen, labels = set(), []
for raw in stripped.split("\n"):
    t = html.unescape(raw).strip()
    if t and len(t) < 120 and t not in seen:
        seen.add(t)
        labels.append(t)
lang = re.search(r'<html[^>]*lang="([^"]+)"', page)
print("复查 lang =", lang.group(1) if lang else "?")
print("复查可见文案 =", " / ".join(labels[:12]))
EOF
