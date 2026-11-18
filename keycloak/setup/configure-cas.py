#!/usr/bin/env python3
"""Bind the CAS employee account to a protected Keycloak token claim."""

import argparse
import json
import os
import re
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


CLAIM = "employee_id"
SCOPE = "cas-employee"


class AdminAPI:
    def __init__(self) -> None:
        self.origin = os.environ.get("KEYCLOAK_ADMIN_URL", "http://127.0.0.1:8080").rstrip("/")
        realm = quote(os.environ.get("KEYCLOAK_REALM", "mcp-gateway"), safe="")
        self.realm_api = f"{self.origin}/admin/realms/{realm}"
        target = f"{self.origin}/realms/master/protocol/openid-connect/token"
        form = urlencode({
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": os.environ.get("KEYCLOAK_ADMIN", "admin"),
            "password": os.environ["KEYCLOAK_ADMIN_PASSWORD"],
        }).encode()
        with urlopen(target, data=form, timeout=15) as response:
            self.token = json.load(response)["access_token"]

    def call(self, method: str, path: str, body: dict | None = None):
        request = Request(
            self.realm_api + path,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=15) as response:
                contents = response.read()
        except HTTPError as exc:
            raise RuntimeError(f"Keycloak {method} {path} returned {exc.code}") from exc
        return json.loads(contents) if contents else None


def upsert_mapper(api: AdminAPI, endpoint: str, payload: dict) -> None:
    current = next((x for x in api.call("GET", endpoint) if x["name"] == payload["name"]), None)
    if current:
        api.call("PUT", f"{endpoint}/{current['id']}", {**current, **payload})
    else:
        api.call("POST", endpoint, payload)


def _configure_login_flow(api: AdminAPI, signup_mode: str) -> str:
    alias = f"cas-{signup_mode}"
    flows = api.call("GET", "/authentication/flows")
    if not any(flow["alias"] == alias for flow in flows):
        api.call("POST", "/authentication/flows", {
            "alias": alias, "providerId": "basic-flow", "topLevel": True, "builtIn": False,
        })
    provider = "idp-create-user-if-unique" if signup_mode == "open" else "deny-access-authenticator"
    endpoint = f"/authentication/flows/{alias}/executions"
    executions = api.call("GET", endpoint)
    if not any(item.get("providerId") == provider for item in executions):
        api.call("POST", endpoint + "/execution", {"provider": provider})
    for item in api.call("GET", endpoint):
        if item.get("providerId") == provider and item.get("requirement") != "REQUIRED":
            api.call("PUT", endpoint, {**item, "requirement": "REQUIRED"})
    return alias


def _configure_broker(api: AdminAPI, signup_mode: str) -> None:
    shim = os.environ.get("SHIM_BASE_URL", "http://127.0.0.1:8085").rstrip("/")
    browser = os.environ.get("SHIM_PUBLIC_URL", shim).rstrip("/")
    flow = _configure_login_flow(api, signup_mode)
    payload = {
        "alias": "cas",
        "displayName": "企业内部登录",
        "providerId": "oidc",
        "enabled": True,
        "trustEmail": False,
        "storeToken": False,
        "firstBrokerLoginFlowAlias": flow,
        "config": {
            "clientId": os.environ.get("SHIM_CLIENT_ID", "mcp-gateway-keycloak"),
            "clientSecret": os.environ["SHIM_CLIENT_SECRET"],
            "authorizationUrl": f"{browser}/authorize",
            "tokenUrl": f"{shim}/token",
            "userinfoUrl": f"{shim}/userinfo",
            "jwksUrl": f"{shim}/jwks.json",
            "validateSignature": "true",
            "useJwksUrl": "true",
            "issuer": shim,
            "defaultScope": "openid profile",
            "clientAuthMethod": "client_secret_post",
            "pkceEnabled": "true",
            "pkceMethod": "S256",
            "syncMode": "IMPORT",
        },
    }
    endpoint = "/identity-provider/instances"
    instances = api.call("GET", endpoint)
    if any(instance["alias"] == "cas" for instance in instances):
        current = api.call("GET", endpoint + "/cas")
        api.call("PUT", endpoint + "/cas", {**current, **payload})
    else:
        api.call("POST", endpoint, payload)


def bind_employee(api: AdminAPI, employee_id: str, display_name: str) -> None:
    """Pre-create an employee account without requiring an email address."""
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", employee_id):
        raise ValueError("invalid employee ID")
    query = urlencode({"username": employee_id, "exact": "true"})
    endpoint = f"/users?{query}"
    users = api.call("GET", endpoint)
    if not users:
        api.call("POST", "/users", {
            "username": employee_id, "firstName": display_name, "enabled": True,
            "attributes": {CLAIM: [employee_id]},
        })
        users = api.call("GET", endpoint)
    # Keycloak canonicalizes realm usernames to lowercase. Preserve the
    # exact issuer account in both the CAS link and the employee claim.
    user = next(
        (candidate for candidate in users if candidate["username"].casefold() == employee_id.casefold()),
        None,
    )
    if user is None:
        raise RuntimeError("Keycloak could not retrieve the employee account")
    identity_endpoint = f"/users/{user['id']}/federated-identity"
    existing = next((link for link in api.call("GET", identity_endpoint)
                     if link["identityProvider"] == "cas"), None)
    if existing:
        if existing["userId"] != employee_id:
            raise ValueError("the existing CAS account binding does not match the employee ID")
    else:
        current = api.call("GET", f"/users/{user['id']}")
        if (current.get("attributes") or {}).get(CLAIM) != [employee_id]:
            raise ValueError("the existing realm account has no matching protected employee ID")
        api.call("POST", identity_endpoint + "/cas", {
            "identityProvider": "cas", "userId": employee_id, "userName": employee_id,
        })


def _configure_realm_defaults(api: AdminAPI) -> None:
    realm = api.call("GET", "")
    callbacks = dict(realm.get("attributes") or {})
    supported_locales = set(realm.get("supportedLocales") or [])
    api.call("PUT", "", {
        "internationalizationEnabled": True,
        "supportedLocales": sorted(supported_locales | {"zh-CN"}),
        "defaultLocale": "zh-CN",
        "offlineSessionIdleTimeout": int(os.environ.get("KEYCLOAK_OFFLINE_SESSION_IDLE_SECONDS", "259200")),
        "attributes": callbacks,
    })
    actions = api.call("GET", "/authentication/required-actions")
    for action in actions:
        if action["alias"] == "VERIFY_PROFILE" and action.get("enabled"):
            api.call("PUT", "/authentication/required-actions/VERIFY_PROFILE", {
                **action, "enabled": False, "defaultAction": False,
            })
    scopes = api.call("GET", "/client-scopes")
    if not any(scope["name"] == "openid" for scope in scopes):
        api.call("POST", "/client-scopes", {
            "name": "openid", "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
        })


def configure(api: AdminAPI) -> None:
    profile = api.call("GET", "/users/profile")
    attributes = profile["attributes"]
    for item in attributes:
        if item["name"] in {"email", "firstName", "lastName"}:
            item.pop("required", None)
    employee_attribute = {
        "name": CLAIM,
        "displayName": "Employee ID",
        "permissions": {"view": ["admin"], "edit": ["admin"]},
        "multivalued": False,
    }
    attributes[:] = [item for item in attributes if item["name"] != CLAIM] + [employee_attribute]
    api.call("PUT", "/users/profile", profile)

    upsert_mapper(api, "/identity-provider/instances/cas/mappers", {
        "name": "cas-employee-id",
        "identityProviderAlias": "cas",
        "identityProviderMapper": "oidc-user-attribute-idp-mapper",
        "config": {"syncMode": "FORCE", "claim": CLAIM, "user.attribute": CLAIM},
    })

    def find_scope():
        return next((s for s in api.call("GET", "/client-scopes") if s["name"] == SCOPE), None)

    scope = find_scope()
    if scope is None:
        api.call("POST", "/client-scopes", {
            "name": SCOPE,
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "false", "display.on.consent.screen": "false"},
        })
        scope = find_scope()
    if scope is None:
        raise RuntimeError("Keycloak did not register the CAS employee scope")
    scope_id = scope["id"]
    upsert_mapper(api, f"/client-scopes/{scope_id}/protocol-mappers/models", {
        "name": "cas-employee-id",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "config": {
            "user.attribute": CLAIM,
            "claim.name": CLAIM,
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
        },
    })
    defaults = "/default-default-client-scopes"
    if not any(item["id"] == scope_id for item in api.call("GET", defaults)):
        api.call("PUT", f"{defaults}/{scope_id}")
    web_client_id = os.environ.get("KEYCLOAK_CLIENT_ID", "mcp-gateway-web")
    query = urlencode({"clientId": web_client_id})
    for client in api.call("GET", f"/clients?{query}"):
        if client["clientId"] == web_client_id:
            defaults = f"/clients/{client['id']}/default-client-scopes"
            if not any(item["id"] == scope_id for item in api.call("GET", defaults)):
                api.call("PUT", f"{defaults}/{scope_id}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("configure")
    setup.add_argument("--signup-mode", choices=("open", "whitelist"), default="whitelist")
    setup.add_argument("--if-missing", action="store_true", help="Create the CAS provider only when absent.")
    bind = commands.add_parser("bind")
    bind.add_argument("employee_id")
    bind.add_argument("display_name")
    options = parser.parse_args()
    api = AdminAPI()
    if options.command == "configure":
        if options.if_missing and any(
            item["alias"] == "cas" for item in api.call("GET", "/identity-provider/instances")
        ):
            print("CAS identity provider already configured.")
            return
        _configure_broker(api, options.signup_mode)
        _configure_realm_defaults(api)
        configure(api)
        print("CAS login and employee claim configured; realm email login settings preserved.")
    else:
        bind_employee(api, options.employee_id, options.display_name)
        print("CAS employee linked.")


if __name__ == "__main__":
    main()
