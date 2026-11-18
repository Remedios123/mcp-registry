"""Operator-configured adapters for company-specific egress credentials."""

import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, StringConstraints, TypeAdapter, ValidationError
from typing import Annotated

from registry.utils.url_guard import (
    EGRESS_UPSTREAM_PROFILE,
    UrlValidationError,
    shared_guarded_async_client,
)


PROVIDER_PREFIX = "enterprise/"
_ACCOUNT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}")
_ID = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,31}$")]


class EnterpriseCredentialDenied(Exception):
    """No credential is allowed for the configured user or target."""


class EnterpriseCredentialUnavailable(Exception):
    """The trusted credential adapter could not return a valid response."""


class CredentialProfile(BaseModel):
    id: _ID
    label: str
    issuer: _ID
    upstreams: list[str] | None = None


@dataclass(frozen=True)
class Credential:
    token: str | None = None
    authorization_url: str | None = None


def credential_profiles() -> dict[str, CredentialProfile]:
    """Read operator configuration and expose stable provider keys."""
    raw = os.getenv("ENTERPRISE_CREDENTIAL_PROFILES", "[]")
    try:
        profiles = TypeAdapter(list[CredentialProfile]).validate_json(raw)
    except ValidationError as exc:
        raise EnterpriseCredentialUnavailable("invalid enterprise credential profiles") from exc
    by_id = {PROVIDER_PREFIX + profile.id: profile for profile in profiles}
    if len(by_id) != len(profiles):
        raise EnterpriseCredentialUnavailable("duplicate enterprise credential profile ID")
    return by_id


def _has_enterprise_binding(server: dict) -> bool:
    provider = (server.get("egress_oauth") or {}).get("provider") or ""
    return server.get("egress_auth_mode") == "oauth_user" and provider.startswith(PROVIDER_PREFIX)


def preserve_service_binding_on_promotion(promoted: dict, former: dict) -> None:
    """Keep the service's current enterprise binding with its active version."""
    fields = ("egress_auth_mode", "egress_oauth", "egress_list_tools_before_consent")
    if _has_enterprise_binding(former):
        for field in fields:
            promoted.pop(field, None)
            if field in former:
                promoted[field] = former.pop(field)
    elif _has_enterprise_binding(promoted):
        # A legacy inactive record can still carry a superseded binding.
        for field in fields:
            promoted.pop(field, None)


def _base_origin(name: str) -> str:
    origin = os.getenv(name, "").rstrip("/")
    try:
        parts = urlsplit(origin)
        https = parts.scheme == "https"
        loopback = parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")
        if not (https or loopback) or not parts.hostname or parts.username is not None:
            raise ValueError
        if parts.path or parts.query or parts.fragment:
            raise ValueError
        _ = parts.port
    except ValueError as exc:
        raise EnterpriseCredentialUnavailable(f"invalid {name}") from exc
    return origin


def _authorization_link(body: dict) -> str:
    url = body.get("authorization_url")
    expected = urlsplit(_base_origin("ENTERPRISE_CREDENTIAL_SHIM_PUBLIC_URL"))
    try:
        parts = urlsplit(url) if isinstance(url, str) else None
        if parts and (parts.scheme, parts.netloc, parts.path) == (
            expected.scheme, expected.netloc, "/renew"
        ) and parts.query.startswith("intent=") and not parts.fragment:
            return url
    except ValueError:
        pass
    raise EnterpriseCredentialUnavailable("invalid business authorization link")


async def vend(
    provider: str,
    employee_id: str,
    upstream: str,
    *,
    approved_upstreams: list[str] | None = None,
) -> Credential:
    """Return a profile credential or a link for a verified employee and approved target."""
    profile = credential_profiles().get(provider)
    if (
        profile is None
        or not _ACCOUNT.fullmatch(employee_id)
        # Existing bindings may rely on their deployment allowlist.
        or (approved_upstreams is None and profile.upstreams is None)
        or (
            approved_upstreams is not None
            and (not isinstance(approved_upstreams, list) or upstream not in approved_upstreams)
        )
        or (profile.upstreams is not None and upstream not in profile.upstreams)
    ):
        raise EnterpriseCredentialDenied("employee or upstream is outside the credential profile")
    base = _base_origin("ENTERPRISE_CREDENTIAL_SHIM_URL")
    secret = os.getenv("SHIM_INTERNAL_TOKEN", "")
    if len(secret) < 32:
        raise EnterpriseCredentialUnavailable("enterprise credential adapter is not configured")
    try:
        client = shared_guarded_async_client(profile=EGRESS_UPSTREAM_PROFILE)
        reply = await client.get(
            f"{base}/internal/business-token/{employee_id}",
            params={"profile": profile.id},
            headers={"X-Internal-Token": secret},
            timeout=15.0,
        )
        body = reply.json()
    except (httpx.HTTPError, UrlValidationError, ValueError) as exc:
        raise EnterpriseCredentialUnavailable("enterprise credential adapter is unavailable") from exc
    if (
        not isinstance(body, dict)
        or body.get("account") != employee_id
        or body.get("profile") != profile.id
    ):
        raise EnterpriseCredentialUnavailable("credential response does not match the requested identity and profile")
    if reply.status_code == 200:
        token = body.get("token")
        if isinstance(token, str) and token and not body.get("expired"):
            return Credential(token=token)
    if reply.status_code in (403, 404) or (
        reply.status_code == 200 and body.get("expired")
    ):
        return Credential(authorization_url=_authorization_link(body))
    raise EnterpriseCredentialUnavailable("credential adapter refused the request")
