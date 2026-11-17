"""CAS-Shim 端到端自测:模拟 Keycloak 的视角完整走一遍 OIDC 授权码 + PKCE 流程。

前提: shim 以 CAS_SHIM_MOCK=true 启动(不依赖真实 CAS 网络)。
"""
import base64
import hashlib
import json
import os
import secrets
import sys

import httpx
import jwt

BASE = os.environ.get("SHIM_BASE_URL", "http://localhost:8085")
CLIENT_ID = "mcp-gateway-keycloak"
CLIENT_SECRET = "test-secret"
REDIRECT_URI = "https://keycloak.local/broker/cas/endpoint"

verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
state, nonce = secrets.token_urlsafe(8), secrets.token_urlsafe(8)

c = httpx.Client(base_url=BASE, timeout=10, follow_redirects=False)

# 1. discovery
d = c.get("/.well-known/openid-configuration").json()
assert d["issuer"] == BASE and d["token_endpoint"].endswith("/token"), "discovery 异常"
print("① discovery OK:", d["authorization_endpoint"])

# 2. /authorize → 302 到 CAS,且种下会话 cookie
r = c.get("/authorize", params={
    "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "state": state, "nonce": nonce,
    "scope": "openid", "code_challenge": challenge, "code_challenge_method": "S256",
})
assert r.status_code == 302 and "/login?service=" in r.headers["location"], f"authorize 跳转异常: {r.status_code}"
assert "shim_ctx" in r.cookies, "会话 cookie 未种下"
print("② authorize OK →", r.headers["location"][:80], "...")

# 3. 模拟 CAS 带 ST 回调(mock 模式下 ticket 随便填) → 302 回 Keycloak 带 code
r = c.get("/cas/callback", params={"ticket": "ST-1000-mock"})
assert r.status_code == 302 and "code=" in r.headers["location"], f"回调异常: {r.status_code} {r.text[:120]}"
loc = r.headers["location"]
code = loc.split("code=")[1].split("&")[0]
back_state = loc.split("state=")[1]
assert back_state == state, "state 回传不一致"
print("③ CAS 回调 OK, code 已发回 Keycloak")

# 4. POST /token(PKCE 校验 + client 认证)→ id_token
r = c.post("/token", data={"grant_type": "authorization_code", "code": code,
                           "redirect_uri": REDIRECT_URI, "client_id": CLIENT_ID,
                           "client_secret": CLIENT_SECRET, "code_verifier": verifier})
assert r.status_code == 200, f"token 换取失败: {r.status_code} {r.text[:200]}"
tokens = r.json()
print("④ token OK, id_token 前 40 字符:", tokens["id_token"][:40], "...")

# 4b. 错误 code_verifier 必须被拒
code2 = None
r = c.get("/authorize", params={"client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
                                "state": state, "nonce": nonce, "scope": "openid",
                                "code_challenge": challenge, "code_challenge_method": "S256"})
r = c.get("/cas/callback", params={"ticket": "ST-1001-mock"})
code2 = r.headers["location"].split("code=")[1].split("&")[0]
r = c.post("/token", data={"grant_type": "authorization_code", "code": code2,
                           "redirect_uri": REDIRECT_URI, "client_id": CLIENT_ID,
                           "client_secret": CLIENT_SECRET, "code_verifier": "wrong"})
assert r.status_code == 400, "错误 PKCE verifier 未被拒绝"
print("④b PKCE 负向用例 OK(verifier 错误被拒)")

# 5. id_token 验签 + claims
jwks = c.get("/jwks.json").json()["keys"][0]
pub = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks))
claims = jwt.decode(tokens["id_token"], pub, algorithms=["RS256"], audience=CLIENT_ID)
assert claims["nonce"] == nonce and claims["sub"] == "MOCK001", "id_token claims 异常"
assert claims["employee_id"] == "MOCK001" and claims["name"], "身份字段缺失"
print("⑤ id_token 验签 OK: sub =", claims["sub"], "| name =", claims["name"])

# 6. userinfo
r = c.get("/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"})
assert r.status_code == 200 and r.json()["sub"] == "MOCK001", "userinfo 异常"
print("⑥ userinfo OK:", r.json())

# 7. vault 内部接口(网关 egress broker 未来从这里取业务令牌)
r = c.get("/internal/business-token/MOCK001", headers={"X-Internal-Token": "test-internal"})
assert r.status_code == 200 and r.json()["token"].startswith("mock-biz-token-"), "vault 接口异常"
body = r.json()
print("⑦ vault OK: 业务令牌 =", body["token"][:26], "... 过期时间戳 =", body["expires_at"])

# 8. code 单次性
r = c.post("/token", data={"grant_type": "authorization_code", "code": code,
                           "redirect_uri": REDIRECT_URI, "client_id": CLIENT_ID,
                           "client_secret": CLIENT_SECRET})
assert r.status_code == 400, "code 重放未被拒绝"
print("⑧ code 重放被拒 OK")

print("\n全部 8 项自测通过 ✅")
