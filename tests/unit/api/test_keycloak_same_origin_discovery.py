from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from registry.api import wellknown_routes

PUBLIC_ORIGIN = "https://gw.example.test"
REALM = "mcp-gateway"
ISSUER = f"{PUBLIC_ORIGIN}/realms/{REALM}"


@pytest.fixture
def same_origin_discovery(monkeypatch):
    settings = SimpleNamespace(
        auth_provider="keycloak",
        mcp_oauth_as_on_gateway_realm=True,
        keycloak_realm=REALM,
        registry_url=PUBLIC_ORIGIN,
        mcp_https_required=True,
    )
    monkeypatch.setattr(wellknown_routes, "settings", settings)
    app = FastAPI()
    app.include_router(wellknown_routes.router, prefix="/.well-known")
    return TestClient(app), settings


def test_keycloak_metadata_discovery_for_canonical_issuer(same_origin_discovery):
    client, _ = same_origin_discovery
    endpoint = f"{ISSUER}/protocol/openid-connect"
    metadata = {
        "issuer": ISSUER,
        "authorization_endpoint": f"{endpoint}/auth",
        "token_endpoint": f"{endpoint}/token",
        "jwks_uri": f"{endpoint}/certs",
        "registration_endpoint": f"{ISSUER}/clients-registrations/openid-connect",
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    }

    with patch.object(wellknown_routes, "_get_active_auth_provider") as factory:
        factory.return_value.native_authorization_server_metadata.return_value = metadata
        for path in (
            "/.well-known/oauth-authorization-server",
            f"/.well-known/oauth-authorization-server/realms/{REALM}",
            f"/.well-known/openid-configuration/realms/{REALM}",
        ):
            response = client.get(path)
            assert response.status_code == 200
            assert response.json() == {
                **metadata,
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
            }
            assert response.headers["cache-control"] == "no-store"

        assert client.get("/.well-known/oauth-authorization-server/realms/master").status_code == 404


def test_keycloak_metadata_rejects_a_mismatched_issuer(same_origin_discovery):
    client, _ = same_origin_discovery
    with patch.object(wellknown_routes, "_get_active_auth_provider") as factory:
        factory.return_value.native_authorization_server_metadata.return_value = {
            "issuer": "https://idp.example.test/realms/mcp-gateway",
        }
        assert client.get("/.well-known/oauth-authorization-server").status_code == 502


def test_same_origin_serves_path_aware_prm_for_plain_server(same_origin_discovery):
    client, _ = same_origin_discovery
    resource = f"{PUBLIC_ORIGIN}/tools/mcp"
    metadata = {"resource": resource, "authorization_servers": [ISSUER]}
    with (
        patch.object(wellknown_routes, "_get_active_auth_provider") as factory,
        patch.object(wellknown_routes, "derive_supported_scopes", AsyncMock(return_value=["openid"])),
        patch.object(wellknown_routes, "build_resource_documentation_url", return_value=None),
        patch.object(
            wellknown_routes.server_service,
            "get_server_info",
            AsyncMock(return_value={"egress_auth_mode": "none"}),
        ),
    ):
        factory.return_value.protected_resource_metadata.return_value = metadata
        response = client.get("/.well-known/oauth-protected-resource/tools/mcp")
        assert response.status_code == 200
        assert response.json() == metadata


def test_same_origin_path_discovery_disabled_by_default(same_origin_discovery):
    client, settings = same_origin_discovery
    settings.mcp_oauth_as_on_gateway_realm = False
    assert (
        client.get(f"/.well-known/oauth-authorization-server/realms/{REALM}").status_code == 404
    )



def test_path_aware_challenge_for_a_server_ending_in_mcp():
    from registry.auth.oauth_metadata import build_per_server_prm_url

    assert build_per_server_prm_url(PUBLIC_ORIGIN, "/example-mcp") == (
        f"{PUBLIC_ORIGIN}/.well-known/oauth-protected-resource/example-mcp/mcp"
    )
