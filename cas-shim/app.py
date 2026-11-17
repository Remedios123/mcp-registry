"""CAS-Shim: 把公司 CAS 登录(ST 直换业务令牌)包装成标准 OIDC IdP。

供 Keycloak Identity Brokering 对接(协议角色: 我们是 IdP,Keycloak 是 RP)。

登录链路(与 hr-mcp server.py 已验证流程一致,无 PGT 代理):
  1. Keycloak 把浏览器带到 GET /authorize(state/nonce/PKCE 由 Keycloak 生成)
  2. Shim 记下上下文 → 302 到 CAS_BASE/login?service=<SHIM_BASE_URL>/cas/callback
  3. 用户在 CAS 登录(已有 SSO 会话则静默) → CAS 带 ticket=ST 回调 /cas/callback
  4. Shim 调 UC_AUTH_URL 兑换业务令牌(service 须与登录时逐字一致)
  5. 业务令牌入 per-user vault(Mongo) → Shim 给 Keycloak 发 code
  6. Keycloak POST /token 换 id_token(RS256) → 用户会话成立 → 后续 MCP token 正常签发

CAS 完全不动;本服务与 vault 是唯一新增组件。
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import ssl
import time
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pymongo import MongoClient, ReturnDocument
from cryptography.fernet import Fernet, InvalidToken

# ── 配置(环境变量,参考 .env.example) ──────────────────────────────
CAS_BASE = os.environ.get("CAS_BASE", "").rstrip("/")
UC_AUTH_URL = os.environ.get("UC_AUTH_URL", "")
SHIM_BASE_URL = os.environ.get("SHIM_BASE_URL", "http://localhost:8085").rstrip("/")
SHIM_PUBLIC_URL = os.environ.get("SHIM_PUBLIC_URL", SHIM_BASE_URL).rstrip("/")
CALLBACK_URL = os.environ.get("SHIM_CALLBACK_URL", f"{SHIM_BASE_URL}/cas/callback")
SHIM_CLIENT_ID = os.environ.get("SHIM_CLIENT_ID", "mcp-gateway-keycloak")
SHIM_CLIENT_SECRET = os.environ.get("SHIM_CLIENT_SECRET", "")
ALLOWED_REDIRECT_URIS = frozenset(
    uri.strip()
    for uri in os.environ.get(
        "SHIM_ALLOWED_REDIRECT_URIS",
        "http://127.0.0.1:8080/realms/mcp-gateway/broker/cas/endpoint",
    ).split(",")
    if uri.strip()
)
SIGNING_SECRET = os.environ.get("SHIM_SIGNING_SECRET", "")  # cookie 签名,必填
INTERNAL_TOKEN = os.environ.get("SHIM_INTERNAL_TOKEN", "")  # vault 内部接口凭据
CA_BUNDLE = os.environ.get("CAS_CA_BUNDLE")
TLS_VERIFY = (
    ssl.create_default_context(cafile=CA_BUNDLE)
    if CA_BUNDLE else os.environ.get("CAS_TLS_VERIFY", "true").lower() == "true"
)
MOCK_MODE = os.environ.get("CAS_SHIM_MOCK", "false").lower() == "true"
CODE_TTL = 60
ACCESS_TTL = 600
BUSINESS_TTL_DEFAULT = 86400
# breakout 页 iframe 那条回调要挂住的时长(浏览器跳走后连接即断, 这里只是上限)。
IFRAME_HOLD_SECONDS = 30.0

# ── 业务令牌滑动续期(设计: .scratchpad/design-business-token-sliding-renewal.md) ──
# 活跃 = 登录写 vault 或网关工具调用读 vault; 静默超闲时窗即 fail-closed。
IDLE_LIMIT_SECONDS = int(
    float(os.environ.get("BUSINESS_TOKEN_IDLE_LIMIT_HOURS", "72")) * 3600
)
# UC 刷新接口(旧 token 放 Authorization 头换新 24h token); URL 留空 = 功能惰性关闭。
UC_REFRESH_URL = os.environ.get("UC_REFRESH_URL", "")
# 用户 2026-11-09 确认 UC 刷新接口为 GET。
UC_REFRESH_METHOD = os.environ.get("UC_REFRESH_METHOD", "get").lower()
# 剩余寿命低于该阈值时, 读取/批量才触发续期(令牌 24h, 阈值 12h → 稳态余量 12h)。
REFRESH_MARGIN_SECONDS = int(
    float(os.environ.get("REFRESH_MARGIN_HOURS", "12")) * 3600
)
# 每 12h 的定点批量续期时刻(本地时区), 与分片限速。
REFRESH_BATCH_CRON = os.environ.get("REFRESH_BATCH_CRON", "03:00,15:00")
REFRESH_BATCH_RATE_PER_MINUTE = int(os.environ.get("REFRESH_BATCH_RATE_PER_MINUTE", "100"))

_log = logging.getLogger("uvicorn.error")
# httpx logs complete request URLs, including the CAS ticket query.
logging.getLogger("httpx").setLevel(logging.WARNING)

# 业务令牌续期(独立于 OIDC 登录): 浏览器直连本服务跳一次 CAS, 只刷新 vault。
RENEW_COOKIE = "shim_renew"

BASE = Path(__file__).resolve().parent
# 测试可用 SHIM_SIGNING_KEY_PATH 指到临时文件, 避免碰真实签名密钥。
KEY_PATH = Path(
    os.environ.get("SHIM_SIGNING_KEY_PATH") or (BASE / "keys" / "signing_key.pem")
)

# ── vault 存储.Mongo(生产化: 与现有部署共用 Mongo 实例, 独立库名) ──
# 与旧 sqlite 版语义一致: 每工号一行业务令牌, 24h 过期由 UC 决定, 这里只是缓存。
MONGO_URI = os.environ.get("SHIM_MONGO_URI", "mongodb://127.0.0.1:27017")
MONGO_DB = os.environ.get("SHIM_MONGO_DB", "cas_shim")
MONGO_COLLECTION = os.environ.get("SHIM_MONGO_COLLECTION", "business_tokens")
_mongo_client: MongoClient | None = None
_vault_ready = False


def _vault_collection():
    """业务令牌集合(懒连接; 首次访问建唯一索引, Mongo 不可达时抛原异常)。"""
    global _mongo_client, _vault_ready
    if _mongo_client is None:
        _mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    coll = _mongo_client[MONGO_DB][MONGO_COLLECTION]
    if not _vault_ready:
        if not MOCK_MODE:
            connection = _mongo_client.admin.command("connectionStatus")
            if not connection.get("authInfo", {}).get("authenticatedUsers"):
                raise RuntimeError("UC credential storage requires authenticated MongoDB")
        coll.create_index("account", unique=True)
        _vault_ready = True
    return coll

if len(SIGNING_SECRET) < 32:
    raise SystemExit("SHIM_SIGNING_SECRET 未设置(用于 cookie 防篡改,必填)")

# ── 签名密钥(RS256,首次生成后持久化,重启 id_token 仍可验) ─────────
_ACCOUNT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}")
_RENEW_TTL = 600
_RENEW_SEAL = Fernet(base64.urlsafe_b64encode(
    hashlib.sha256(b"uc-renew-v1:" + SIGNING_SECRET.encode()).digest()
))


_VAULT_SEAL = Fernet(base64.urlsafe_b64encode(
    hashlib.sha256(b"uc-vault-v1:" + SIGNING_SECRET.encode()).digest()
))
_VAULT_PREFIX = "fernet:v1:"
ALLOW_LEGACY_VAULT = os.environ.get("SHIM_ALLOW_LEGACY_VAULT", "false").lower() == "true"


def _seal_vault_token(account: str, token: str, expires_at: int) -> str:
    payload = {"account": account, "profile": "uc", "token": token, "expires_at": expires_at}
    return _VAULT_PREFIX + _VAULT_SEAL.encrypt(json.dumps(payload).encode()).decode("ascii")


def _verified_account(data: dict) -> str | None:
    """Use only the issuer's dedicated employee account field."""
    account = data.get("account")
    if not isinstance(account, (str, int)) or isinstance(account, bool):
        return None
    value = str(account)
    return value if _ACCOUNT.fullmatch(value) else None


def _authorization_url(account: str, profile: str) -> str:
    sealed = _RENEW_SEAL.encrypt(json.dumps({"account": account, "profile": profile}).encode())
    return f"{SHIM_PUBLIC_URL}/renew?{urlencode({'intent': sealed.decode('ascii')})}"


def _read_renew_intent(sealed: str) -> dict | None:
    try:
        payload = json.loads(_RENEW_SEAL.decrypt(sealed.encode("ascii"), ttl=_RENEW_TTL))
    except (InvalidToken, UnicodeError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("profile") != "uc":
        return None
    account = payload.get("account")
    return payload if isinstance(account, str) and _ACCOUNT.fullmatch(account) else None


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

if KEY_PATH.exists():
    _priv = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
else:
    _priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        _priv = serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
    else:
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(_priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
_KID = hashlib.sha256(
    _priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
).hexdigest()[:12]


def _jwks() -> dict:
    pub = _priv.public_key().public_numbers()
    n = base64.urlsafe_b64encode(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")).rstrip(b"=")
    e = base64.urlsafe_b64encode(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")).rstrip(b"=")
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": _KID,
                      "n": n.decode(), "e": e.decode()}]}


# ── vault: per-user 业务令牌(Mongo) ────────────────────────────────
def vault_put(account: str, name: str, uc_user_id: str, token: str, expires_at: int) -> None:
    _vault_collection().update_one(
        {"account": account},
        {"$set": {
            "account": account, "name": name, "uc_user_id": uc_user_id,
            "token": _seal_vault_token(account, token, expires_at),
            "expires_at": expires_at, "updated_at": int(time.time()),
            # 登录即活跃(spec §1 写点二): CAS 兑换成功 = 该账号刚在场。
            "last_used_at": int(time.time()),
        }},
        upsert=True,
    )


def vault_get(account: str) -> dict | None:
    doc = _vault_collection().find_one({"account": account}, {"_id": 0})
    if not doc or not isinstance(token := doc.get("token"), str) or not token:
        return None
    if not token.startswith(_VAULT_PREFIX):
        return dict(doc) if ALLOW_LEGACY_VAULT else None
    try:
        payload = json.loads(_VAULT_SEAL.decrypt(token.removeprefix(_VAULT_PREFIX).encode("ascii")))
    except (InvalidToken, UnicodeError, ValueError):
        return None
    if (
        not isinstance(payload, dict)
        or payload.get("account") != account
        or payload.get("profile") != "uc"
        or payload.get("expires_at") != doc.get("expires_at")
        or not isinstance(payload.get("token"), str)
        or not payload["token"]
    ):
        return None
    return {**doc, "token": payload["token"]}


def _effective_last_used(doc: dict) -> int:
    """最近活跃时刻: 存量行缺 last_used_at 时回落 updated_at(再回落 0)。"""
    return int(doc.get("last_used_at") or doc.get("updated_at") or 0)


def _is_idle_expired(doc: dict, now: float) -> bool:
    """静默超过闲时窗(默认 72h)即失效, 读路径与批量调度共用同一判定。"""
    return now - _effective_last_used(doc) > IDLE_LIMIT_SECONDS


_account_locks: dict[str, asyncio.Lock] = {}


def _account_lock(account: str) -> asyncio.Lock:
    """账号级锁: 串行化同一账号的续期(读时兜底与批量共用)。"""
    lock = _account_locks.get(account)
    if lock is None:
        lock = asyncio.Lock()
        _account_locks[account] = lock
    return lock


def vault_update_token(
    account: str, token: str, expires_at: int, expect_expires_at: int, activity: int
) -> bool:
    """条件写回: 仅当库中 expires_at 仍为 expect_expires_at 才更新。

    防跨进程覆盖(锁是进程内的, 条件写才是最终防线); 只碰 token 与
    expires_at/updated_at, 身份字段(name/uc_user_id)保持原行。
    activity: 该账号的真实活跃时刻(续期前的回落值), 固化进 last_used_at
    以免 updated_at 被续期顶高、把活跃时钟越续越新(终审 C1)。
    """
    res = _vault_collection().update_one(
        {"account": account, "expires_at": expect_expires_at},
        {"$set": {"token": _seal_vault_token(account, token, expires_at),
                  "expires_at": expires_at, "updated_at": int(time.time()),
                  "last_used_at": activity}},
    )
    return bool(getattr(res, "modified_count", 0))


async def _renew_account(account: str) -> bool:
    """按"锁内重读"协议为单个账号续期(读时兜底与批量共用同一实现)。

    UC 侧刷新即替换旧 token: 锁内发现令牌已被并发续期时直接采用库值,
    绝不再对已作废的旧 token 发第二次刷新; 条件写失败视为被抢先, 返回 False。
    UC 调用经 to_thread 下放线程, 不阻塞事件循环(终审 I2)。
    """
    pre = vault_get(account)
    if not pre:
        return False
    async with _account_lock(account):
        doc = vault_get(account)
        if not doc:
            return False
        if doc.get("expires_at") != pre.get("expires_at"):
            return True
        got = await asyncio.to_thread(
            _call_uc_refresh, doc.get("token") or "", account
        )
        if got is None:
            return False
        return vault_update_token(
            account, got[0], got[1], int(doc["expires_at"]),
            int(_effective_last_used(doc)),
        )


# ── 授权码与 oauth 上下文(内存,进程级;重启则要求用户重新走一遍登录) ──
_codes: dict[str, dict] = {}
_code_used: set[str] = set()


def _cookie_sign(value: str) -> str:
    sig = hmac.new(SIGNING_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{value}.{sig}"


def _cookie_verify(cookie: str) -> str | None:
    value, _, sig = cookie.rpartition(".")
    if not value or not hmac.compare_digest(sig, _cookie_sign(value).rpartition(".")[2]):
        return None
    return value


def _require_verified_issuer(url: str) -> None:
    endpoint = urlsplit(url)
    if endpoint.scheme != "https" or not endpoint.hostname or TLS_VERIFY is False:
        raise ValueError("UC endpoints require HTTPS with certificate verification")


def _exchange_st(ticket: str, service: str = CALLBACK_URL) -> dict:
    """ST 兑换业务令牌 —— 与 hr-mcp _exchange_st() 逐字同参。

    ``service`` 必须与 CAS 登录时提交的那个**逐字一致**(UC 侧会校验),
    所以调用方必须把它原样传回来, 不能一律用 CALLBACK_URL。
    """
    params = {"ticket": ticket, "ssoMode": "cas", "code": ticket, "service": service}
    if MOCK_MODE:
        return {"token": f"mock-biz-token-{secrets.token_hex(8)}",
                "account": "MOCK001", "username": "模拟用户", "userId": "mock-uc-1",
                "expiration": 86400}
    _require_verified_issuer(UC_AUTH_URL)
    response = httpx.get(UC_AUTH_URL, params=params, timeout=15, verify=TLS_VERIFY)
    response.raise_for_status()
    data = response.json()
    return data if isinstance(data, dict) else {}


def _jwt_exp(token: str) -> int | None:
    """不验签解码载荷取 exp; 令牌刚由 UC 签发, 验签交给消费方业务系统。"""
    try:
        return int(jwt.decode(token, options={"verify_signature": False})["exp"])
    except Exception as exc:
        _log.info("uc/refresh: 解析新令牌 exp 失败: %s", exc)
        return None


def _call_uc_refresh(old_token: str, account: str) -> tuple[str, int] | None:
    """调 UC 刷新接口: 旧 token 放 Authorization 头, 换回新 24h 业务令牌。

    成功判定 = 响应 token 非空, 且载荷 sub 与账号一致(防 UC 异常路由把
    他人令牌写进 vault)。UC_REFRESH_URL 未配置或任何失败都返回 None:
    前者是功能惰性关闭, 后者是 fail-closed。
    """
    if not UC_REFRESH_URL:
        return None
    if MOCK_MODE:
        return (
            f"mock-biz-token-{secrets.token_hex(8)}",
            int(time.time()) + BUSINESS_TTL_DEFAULT,
        )
    try:
        _require_verified_issuer(UC_REFRESH_URL)
        request_fn = getattr(httpx, UC_REFRESH_METHOD)
        r = request_fn(
            UC_REFRESH_URL,
            headers={"Authorization": f"Bearer {old_token}"},
            timeout=15,
            verify=TLS_VERIFY,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            data = {}
    except Exception as exc:
        _log.info("uc/refresh: transport failure type=%s", type(exc).__name__)
        return None
    token = data.get("token") or ""
    if not token:
        _log.info("uc/refresh: issuer refused refresh")
        return None
    exp = _jwt_exp(token)
    if exp is None:
        return None
    try:
        payload_sub = str(
            jwt.decode(token, options={"verify_signature": False}).get("sub") or ""
        )
    except Exception:
        payload_sub = ""
    if payload_sub != account:
        _log.info(
            "uc/refresh: 新令牌 sub(%s) 与账号(%s)不符, 拒收入库", payload_sub, account
        )
        return None
    return token, exp


def _page(kind: str, title: str, sub: str) -> HTMLResponse:
    color = {"ok": "#1f9d55", "err": "#d64545", "info": "#52606d"}.get(kind, "#52606d")
    return HTMLResponse(
        f"<!doctype html><meta charset='utf-8'><body style='font-family:sans-serif;"
        f"display:flex;min-height:100vh;align-items:center;justify-content:center;background:#eef2f7'>"
        f"<div style='background:#fff;border-radius:12px;padding:40px 48px;text-align:center;"
        f"box-shadow:0 10px 40px rgba(0,0,0,.08)'>"
        f"<h2 style='color:{color};margin:0 0 12px'>{title}</h2>"
        f"<p style='color:#52606d'>{sub}</p></div>"
    )


def _store_business_token(data: dict) -> tuple[str, int]:
    """把 UC 兑换结果写入 vault, 返回 (account, expires_at)。"""
    token = data.get("token") or ""
    account = _verified_account(data)
    if account is None:
        raise ValueError("UC response did not identify an employee")
    name = str(data.get("username") or account)
    uc_user_id = str(data.get("userId") or "")
    expires_at = int(time.time()) + int(data.get("expiration") or BUSINESS_TTL_DEFAULT)
    vault_put(account, name, uc_user_id, token, expires_at)
    return account, expires_at


# ── 定点批量续期: 每 12h 给闲时窗内所有账号续期(设计 §2) ─────────────
def _parse_cron(s: str) -> list[tuple[int, int]]:
    """"03:00,15:00" → [(3, 0), (15, 0)]; 去重升序, 非法段跳过。"""
    out = []
    for part in (s or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            hh, mm = (int(x) for x in part.split(":"))
        except ValueError:
            _log.info("REFRESH_BATCH_CRON 段无效: %r", part)
            continue
        if 0 <= hh < 24 and 0 <= mm < 60:
            out.append((hh, mm))
    return sorted(set(out))


def _next_batch_time(now_ts: float, cron: str) -> float:
    """严格大于 now_ts 的下一网格时刻(epoch 秒, 本地时区)。"""
    slots = _parse_cron(cron)
    if not slots:
        return now_ts + 86400.0
    today = datetime.datetime.fromtimestamp(now_ts).date()
    candidates = []
    for day_offset in (0, 1):
        for hh, mm in slots:
            ts = datetime.datetime.combine(
                today + datetime.timedelta(days=day_offset), datetime.time(hh, mm)
            ).timestamp()
            if ts > now_ts:
                candidates.append(ts)
    return min(candidates)


async def _batch_sleep(seconds: float) -> None:
    """批量内的节流等待, 独立包装以便测试替换。"""
    await asyncio.sleep(seconds)


async def _run_batch(now: float | None = None) -> dict:
    """遍历 vault 全部账号: 闲时窗内的无条件续期, 超窗跳过(fail-closed)。

    UC_REFRESH_URL 未配置时整轮跳过(功能惰性关闭), 返回全零统计。
    """
    now = time.time() if now is None else now
    stats = {"renewed": 0, "skipped_idle": 0, "failed": 0}
    if not UC_REFRESH_URL:
        _log.info("uc/refresh: 未配置 UC_REFRESH_URL, 本轮批量跳过(功能关闭)")
        return stats
    started = time.time()
    processed = 0
    for row in _vault_collection().find({}, {"account": 1, "_id": 0}):
        account = str(row.get("account") or "")
        doc = vault_get(account) if account else None
        if not doc:
            continue
        if _is_idle_expired(doc, now):
            stats["skipped_idle"] += 1
            continue
        try:
            if await _renew_account(account):
                stats["renewed"] += 1
            else:
                stats["failed"] += 1
        except Exception as exc:
            # 单账号异常(UC 畸形报文/Mongo 抖动/坏行)不中止整批。
            stats["failed"] += 1
            _log.warning("uc/refresh: 账号 %s 续期异常, 跳过: %s", account, exc)
        processed += 1
        if (
            REFRESH_BATCH_RATE_PER_MINUTE > 0
            and processed % REFRESH_BATCH_RATE_PER_MINUTE == 0
        ):
            await _batch_sleep(60)
    _log.info(
        "uc/refresh: 批量完成 renewed=%s skipped_idle=%s failed=%s 耗时=%.1fs",
        stats["renewed"],
        stats["skipped_idle"],
        stats["failed"],
        time.time() - started,
    )
    return stats


async def _renewal_loop() -> None:
    """睡到下一网格时刻 → 批量 → 循环; 无内存调度状态, 重启即恢复。"""
    while True:
        try:
            now = time.time()
            await asyncio.sleep(
                max(0.0, _next_batch_time(now, REFRESH_BATCH_CRON) - now)
            )
            await _run_batch()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _log.warning("renewal loop 异常, 下个网格时刻继续: %s", exc)


@contextlib.asynccontextmanager
async def _lifespan(a):
    # 定点批量续期任务: 随服务起, 随服务停。
    task = asyncio.create_task(_renewal_loop())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(
    docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan
)



# ── OIDC 发现 ──────────────────────────────────────────────────────
@app.get("/.well-known/openid-configuration")
async def discovery():
    return {
        "issuer": SHIM_BASE_URL,
        "authorization_endpoint": f"{SHIM_BASE_URL}/authorize",
        "token_endpoint": f"{SHIM_BASE_URL}/token",
        "jwks_uri": f"{SHIM_BASE_URL}/jwks.json",
        "userinfo_endpoint": f"{SHIM_BASE_URL}/userinfo",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported": ["sub", "name", "preferred_username", "employee_id", "uc_user_id"],
        "code_challenge_methods_supported": ["S256"],
    }


@app.get("/jwks.json")
async def jwks():
    return _jwks()


def _service_with_ctx(ctx_token: str) -> str:
    """把 OIDC 上下文挂到 service 的 query 上 —— 这是唯一可靠的传递通道。

    Cookie 在"从 https 的 CAS 跨站回落到 http 裸 IP"这一跳会被浏览器整条
    丢掉(实测 ``cookies=[]``, 连 SameSite=lax 都不发), 而 service 参数由
    CAS 原样回填(登录页隐藏域 value 里能看到完整 query), 不受 Cookie 限制。
    """
    return f"{CALLBACK_URL}?ctx={quote(ctx_token, safe='')}"


# ── 授权入口:记住 Keycloak 的请求,跳 CAS ─────────────────────────
@app.get("/authorize")
async def authorize(request: Request):
    q = request.query_params
    ctx = {
        "client_id": q.get("client_id", ""),
        "redirect_uri": q.get("redirect_uri", ""),
        "state": q.get("state", ""),
        "nonce": q.get("nonce", ""),
        "scope": q.get("scope", "openid"),
        "code_challenge": q.get("code_challenge", ""),
        "code_challenge_method": q.get("code_challenge_method", ""),
        "ts": int(time.time()),
    }
    if (
        ctx["client_id"] != SHIM_CLIENT_ID
        or ctx["redirect_uri"] not in ALLOWED_REDIRECT_URIS
        or q.get("response_type", "code") != "code"
        or (ctx["code_challenge"] and ctx["code_challenge_method"] != "S256")
    ):
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    ctx_b64 = base64.urlsafe_b64encode(json.dumps(ctx).encode()).decode()
    ctx_token = _cookie_sign(ctx_b64)
    resp = RedirectResponse(
        f"{CAS_BASE}/login?service={quote(_service_with_ctx(ctx_token), safe='')}",
        status_code=302,
    )
    # 上下文双通道: service 的 query 为主(见 _service_with_ctx), 签名 cookie
    # 作为后备 —— 同站场景下它能让回调少一次 URL 解析, 也兼容旧的书签/链接。
    resp.set_cookie(
        "shim_ctx", ctx_token,
        max_age=600, httponly=True, samesite="lax",
    )
    return resp


async def _hold_until_disconnect(request: Request, seconds: float) -> None:
    """挂住响应直到浏览器断开(顶层链路已落网关、标签页离开)或到达时限。

    专门伺候 breakout 页 iframe 那条重复回调: 立刻响应会让 iframe onload
    提前触发, CAS 登录页随即走收尾并取消顶层的在途跳转(实测)。
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if await request.is_disconnected():
            return
        await asyncio.sleep(0.5)


# ── CAS 回调:ST 换业务令牌 → 发 code 给 Keycloak ──────────────────
@app.get("/cas/callback")
async def cas_callback(request: Request):
    import logging
    log = logging.getLogger("uvicorn.error")
    q = request.query_params
    ticket = q.get("ticket", "")
    # 上下文优先从 service 的 query 取: 跨站回跳时浏览器可能一个 cookie 都不发。
    url_ctx = q.get("ctx", "")
    raw_ctx = url_ctx or request.cookies.get("shim_ctx", "")
    ctx_b64 = _cookie_verify(raw_ctx)
    retried = request.cookies.get("shim_retry", "") == "1"
    dest = (request.headers.get("sec-fetch-dest") or "").lower()
    log.info("cas/callback: has_ticket=%s has_context=%s retried=%s",
             bool(ticket), bool(ctx_b64), retried)
    # breakout 页双发的真身(2026-11-09 抓到源码): 同一 service URL 既放在
    # <meta http-equiv="refresh"> (跳承载它的隐藏 iframe 自己), 又用
    # window.top.location.replace() (跳顶层窗口)。iframe 那条在第三方上下文
    # 里设不上会话 cookie, 却会把同一个 ST 再兑换一次冲进 KC broker 顶掉
    # 顶层刚签的 code。而 CAS 登录页要等 iframe onload 才走收尾(XHR
    # sso-agreement/status 再自己跳 /cas/login), 会取消顶层在途的跳转 ——
    # 所以既不能兑换, 也不能立刻给响应: 挂住连接直到浏览器离开(顶层链路
    # 已落网关)或超时, iframe 永远停在加载中, CAS 页收尾不会触发。
    # Sec-Fetch-Dest 可伪造: 挂住前必须先确认 ctx 签名有效, 否则伪造者可
    # 零成本占住连接(连接耗尽 DoS); 签名无效者走下方原有快速拒绝。
    if dest == "iframe" and ctx_b64:
        log.info("cas/callback: iframe 探测请求(breakout meta refresh), 挂住不响应 ua=%s",
                 (request.headers.get("user-agent") or "")[:60])
        await _hold_until_disconnect(request, IFRAME_HOLD_SECONDS)
        return HTMLResponse(
            "<!doctype html><meta charset='utf-8'><title>ok</title>",
            headers={"Cache-Control": "no-store"},
        )
    # 排障用: 区分"根本没带 Cookie"(浏览器拒收/跨站丢弃) 与"带了但验签失败"
    # (cookie 被改写或签名密钥变更)。两者都表现成 ctx=False, 处理方式不同。
    if not ctx_b64:
        log.warning(
            "cas/callback: ctx missing (raw_len=%s) cookies=%s ua=%s",
            len(raw_ctx), sorted(request.cookies.keys()),
            (request.headers.get("user-agent") or "")[:60],
        )

    if not ctx_b64:
        # 没有 OIDC 上下文: 可能是 /renew 发起的"只续业务令牌"流程。
        renew_ctx = _cookie_verify(request.cookies.get(RENEW_COOKIE, ""))
        if renew_ctx:
            return _finish_renew(renew_ctx, ticket)
        # 实测: 从 casuat.geehy.com 回跳的这一跳, 浏览器可能一个 cookie 都不发
        # (日志 cookies=[]), 于是 shim_ctx 取不到。此时页面已经落在 shim 的
        # 第一方上下文里, 原地刷新一次浏览器就会带上 cookie —— 与用户手动 F5
        # 等效(实测 F5 后同一 ST 即可成功), 但不需要用户操作。
        # `refl=1` 只重试一次, 避免 Cookie 被彻底禁用时来回刷新。
        # 注意: 这一跳没有兑换 ST, 票据仍然有效, 刷新后可正常兑换。
        if not request.cookies and q.get("refl") != "1":
            retry_url = f"{request.url}&refl=1" if q else f"{request.url}?refl=1"
            log.info("cas/callback: no cookies at all, retrying once")
            return HTMLResponse(
                "<!doctype html><meta charset='utf-8'>"
                f"<meta http-equiv='refresh' content='0;url={html.escape(retry_url, quote=True)}'>"
                "<body style='font-family:sans-serif;text-align:center;padding-top:80px'>"
                "<p>正在完成登录…</p></body>",
                headers={"Cache-Control": "no-store"},
            )
        # 上下文丢了(无 Cookie 或签名不符):无法续流程,给明确指引
        return _page("err", "会话丢失", "请回到网关重新点击 cas 登录。")
    if not ticket:
        if retried:
            return _page("err", "CAS 未返回票据",
                         "已自动重试一次仍未拿到票据,请把本页信息反馈给维护人员。")
        # 自愈:静默重走一次 CAS(有 SSO 会话时瞬间带回新票据,用户无感)
        resp = RedirectResponse(
            f"{CAS_BASE}/login?service={quote(CALLBACK_URL, safe='')}", status_code=302)
        resp.set_cookie("shim_retry", "1", max_age=120, httponly=True, samesite="lax")
        return resp
    try:
        ctx = json.loads(base64.urlsafe_b64decode(ctx_b64))
    except Exception:
        return _page("err", "会话损坏", "授权上下文无法解析,请重新发起登录。")
    if time.time() - ctx.get("ts", 0) > 600:
        return _page("err", "会话过期", "请回身份网关重新发起登录。")

    try:
        # service 必须与登录时提交的逐字一致: 从 URL 带回来的 ctx 重建,
        # 从 cookie 回来的老路径则仍是裸 CALLBACK_URL。
        service_used = _service_with_ctx(raw_ctx) if url_ctx else CALLBACK_URL
        data = _exchange_st(ticket, service_used)
    except Exception as e:  # UC 不可达 / 证书 / 超时
        log.info("cas/callback: UC 兑换异常 type=%s", type(e).__name__)
        return _page("err", "兑换异常", "暂时无法连接到 UC，请稍后重试。")

    if not isinstance(data, dict) or not data.get("token") or not _verified_account(data):
        return _page("err", "兑换失败", "UC 未返回有效的员工身份和令牌")
    try:
        account, _ = _store_business_token(data)
    except (TypeError, ValueError):
        return _page("err", "兑换失败", "UC 返回了无效的令牌有效期")
    name = str(data.get("username") or account)
    uc_user_id = str(data.get("userId") or "")

    code = secrets.token_urlsafe(32)
    _codes[code] = {"ctx": ctx, "account": account, "name": name,
                    "uc_user_id": uc_user_id, "ts": time.time()}

    if ctx["redirect_uri"]:
        sep = "&" if "?" in ctx["redirect_uri"] else "?"
        target = f"{ctx['redirect_uri']}{sep}code={quote(code)}&state={quote(ctx['state'])}"
        resp = RedirectResponse(target, status_code=302)
    else:  # 联邦调试用:无 redirect_uri 时给回执页
        resp = _page("ok", "CAS 登录成功",
                     f"用户 {name}(工号 {account})业务令牌已入 vault,有效期至 "
                     f"{time.strftime('%H:%M', time.localtime(expires_at))}")
    resp.delete_cookie("shim_ctx")
    resp.delete_cookie("shim_retry")
    return resp


def uq(s: str) -> str:
    return (s or "")[:150].replace("<", "&lt;")


# ── 业务令牌续期: 浏览器直连, 只跑 CAS 一跳, 不动 Keycloak 会话 ──────
@app.get("/renew")
async def renew(request: Request):
    """入口: 302 到 CAS 登录, 回跳 /cas/callback 走续期分支。

    service 必须与登录时逐字一致(UC 侧会校验), 所以复用 CALLBACK_URL;
    续期意图放在签名 cookie 里, 由 /cas/callback 的 no-ctx 分支识别。
    """
    intent = request.query_params.get("intent", "")
    if _read_renew_intent(intent) is None:
        return _page("err", "授权链接失效", "请返回 WorkBuddy 重新获取授权链接。")
    resp = RedirectResponse(
        f"{CAS_BASE}/login?service={quote(CALLBACK_URL, safe='')}", status_code=302)
    resp.set_cookie(RENEW_COOKIE, _cookie_sign(intent),
                    max_age=600, httponly=True, samesite="lax")
    return resp


def _finish_renew(renew_ctx: str, ticket: str):
    """续期分支: 兑换 ST → 覆盖 vault → 回跳或给结果页。"""
    ctx = _read_renew_intent(renew_ctx)
    if ctx is None:
        return _page("err", "会话过期", "请返回 WorkBuddy 重新获取授权链接。")
    if not ticket:
        # 与登录流程一致: 静默重走一次 CAS, 有 SSO 会话时用户无感
        resp = RedirectResponse(
            f"{CAS_BASE}/login?service={quote(CALLBACK_URL, safe='')}", status_code=302)
        return resp

    try:
        data = _exchange_st(ticket)
    except Exception as e:  # UC 不可达 / 证书 / 超时
        return _page("err", "兑换异常", "暂时无法连接到 UC，请稍后重试。")

    if not isinstance(data, dict) or not data.get("token"):
        return _page("err", "兑换失败", "UC 未返回有效凭证。")
    if _verified_account(data) != ctx["account"]:
        return _page("err", "员工账号不匹配", "请用发起授权的员工账号登录 CAS。")

    try:
        _store_business_token(data)
    except (TypeError, ValueError):
        return _page("err", "兑换失败", "UC 返回了无效的令牌有效期。")
    resp = _page("ok", "业务令牌已续期", "请回到 WorkBuddy 重试刚才的操作。")
    resp.delete_cookie(RENEW_COOKIE)
    return resp


# ── token 端点:Keycloak 用 code 换 id_token ───────────────────────
def _client_auth_ok(request: Request, form: dict) -> bool:
    given = form.get("client_id", ""), form.get("client_secret", "")
    if not given[0]:  # basic
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                raw = base64.b64decode(auth[6:], validate=True).decode()
                given = tuple(raw.split(":", 1))
            except (ValueError, UnicodeError):
                return False
            if len(given) != 2:
                return False
    return hmac.compare_digest(given[0], SHIM_CLIENT_ID) and \
        bool(SHIM_CLIENT_SECRET) and hmac.compare_digest(given[1] or "", SHIM_CLIENT_SECRET)


@app.post("/token")
async def token(request: Request):
    form = dict((await request.form()).multi_items())
    if not _client_auth_ok(request, form):
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    code = form.get("code", "")
    rec = _codes.get(code)
    if not rec or code in _code_used or time.time() - rec["ts"] > CODE_TTL:
        return JSONResponse({"error": "invalid_grant", "error_description": "code 无效/已用/过期"},
                            status_code=400)
    if form.get("redirect_uri") and rec["ctx"].get("redirect_uri") and \
            form["redirect_uri"] != rec["ctx"]["redirect_uri"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri 不匹配"},
                            status_code=400)
    challenge = rec["ctx"].get("code_challenge", "")
    if challenge:  # Keycloak 发起 PKCE 时校验(S256)
        verifier = form.get("code_verifier", "")
        digest = hashlib.sha256(verifier.encode()).digest()
        ok = bool(verifier) and challenge == base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if not ok:
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE 校验失败"},
                                status_code=400)
    _code_used.add(code)
    _codes.pop(code, None)
    now = int(time.time())
    claims = {"iss": SHIM_BASE_URL, "sub": rec["account"], "aud": rec["ctx"]["client_id"],
              "iat": now, "exp": now + ACCESS_TTL, "preferred_username": rec["account"],
              "name": rec["name"], "employee_id": rec["account"], "uc_user_id": rec["uc_user_id"]}
    if rec["ctx"].get("nonce"):
        claims["nonce"] = rec["ctx"]["nonce"]
    id_token = jwt.encode(claims, _priv, algorithm="RS256", headers={"kid": _KID})
    at_claims = dict(claims, token_use="access")
    access_token = jwt.encode(at_claims, _priv, algorithm="RS256", headers={"kid": _KID})
    return {"access_token": access_token, "id_token": id_token, "token_type": "Bearer",
            "expires_in": ACCESS_TTL, "scope": rec["ctx"].get("scope", "openid")}


# ── userinfo(调试/联邦映射用) ─────────────────────────────────────
@app.get("/userinfo")
async def userinfo(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return JSONResponse({"error": "invalid_token"}, status_code=401)
    try:
        claims = jwt.decode(auth[7:], _priv.public_key(), algorithms=["RS256"],
                            options={"verify_aud": False})
    except jwt.PyJWTError as e:
        return JSONResponse({"error": "invalid_token", "error_description": str(e)[:120]},
                            status_code=401)
    return {"sub": claims["sub"], "name": claims.get("name"),
            "preferred_username": claims.get("preferred_username"),
            "employee_id": claims.get("employee_id"), "uc_user_id": claims.get("uc_user_id")}


# ── vault 内部接口:后续网关 egress broker 取业务令牌用 ─────────────
@app.get("/internal/business-token/{account}")
async def internal_business_token(account: str, request: Request, profile: str | None = None):
    supplied = request.headers.get("X-Internal-Token", "")
    if not INTERNAL_TOKEN or not hmac.compare_digest(supplied, INTERNAL_TOKEN):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    if not _ACCOUNT.fullmatch(account) or profile not in (None, "uc"):
        return JSONResponse({"error": "unknown_credential"}, status_code=404)
    row = vault_get(account)
    if not row:
        payload = {"error": "not_found"}
        if profile:
            payload.update(account=account, profile=profile, authorization_url=_authorization_url(account, profile))
        return JSONResponse(payload, status_code=404)
    now = time.time()
    if _is_idle_expired(row, now):
        # 3 天硬闸: 静默超限的账号不再服务, 也不触碰活跃时间(fail-closed)。
        payload = {"error": "idle_expired"}
        if profile:
            payload.update(account=account, profile=profile, authorization_url=_authorization_url(account, profile))
        return JSONResponse(payload, status_code=403)
    # 每次读取即一次活跃(登录与网关工具调用都汇到这里), 供闲时窗判定。
    _vault_collection().update_one(
        {"account": account},
        {"$set": {"last_used_at": int(now)}},
    )
    # 读时兜底: 剩余寿命不足一个续期阈值时, 这次调用顺手续期(批量空档自愈);
    # 续期失败(含功能关闭)不阻塞本次读取, 令牌真过期时走既有 expired 文案。
    if row["expires_at"] - now < REFRESH_MARGIN_SECONDS and await _renew_account(account):
        row = vault_get(account) or row
    expired = row["expires_at"] <= time.time()
    if profile and expired:
        return JSONResponse({
            "account": account, "profile": profile, "expired": True,
            "authorization_url": _authorization_url(account, profile),
        })
    return JSONResponse(
        {"account": row["account"], "name": row["name"], "uc_user_id": row["uc_user_id"],
         "token": row["token"], "expires_at": row["expires_at"], "expired": expired,
         **({"profile": profile} if profile else {})}
    )
