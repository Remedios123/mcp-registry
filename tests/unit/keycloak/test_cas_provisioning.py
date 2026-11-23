"""Regression tests for CAS provisioning of WorkBuddy DCR clients."""

import runpy
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock, call, patch

import pytest


SCRIPT = Path(__file__).resolve().parents[3] / "keycloak/setup/configure-cas.py"
CONFIG = runpy.run_path(str(SCRIPT))


def test_existing_broker_still_repairs_employee_and_registration_settings():
    main = CONFIG["main"]
    api = Mock()
    api.call.return_value = [{"alias": "cas"}]
    with (
        patch("sys.argv", ["configure-cas", "configure", "--if-missing"]),
        patch.dict(main.__globals__, AdminAPI=lambda: api, configure=Mock(), _configure_dcr=Mock(),
                   _configure_broker=Mock(), _configure_realm_defaults=Mock()),
    ):
        main()
        main.__globals__["configure"].assert_called_once_with(api)
        main.__globals__["_configure_dcr"].assert_called_once_with(api)
        main.__globals__["_configure_broker"].assert_not_called()
        main.__globals__["_configure_realm_defaults"].assert_not_called()


def test_partial_scope_import_preserves_keycloak_builtin_mappers():
    api = Mock()
    basic = {"id": "master-basic", "name": "basic", "protocol": "openid-connect",
             "protocolMappers": [{"id": "master-sub", "name": "sub", "protocolMapper": "oidc-sub-mapper"}]}
    api.standard_scopes.return_value = [basic]
    scopes = {name: {"name": name, "id": name} for name in ("profile", "email", "offline_access")}
    writes = []

    def request(method, path, body=None):
        if path == "/client-scopes":
            if method == "GET":
                return list(scopes.values())
            writes.append(body["name"])
            scopes[body["name"]] = {**body, "id": body["name"]}
            return
        assert path == "/client-scopes/offline_access/scope-mappings/realm"
        return [{"name": "offline_access"}]

    api.call.side_effect = request
    CONFIG["_ensure_dcr_scopes"](api)
    CONFIG["_ensure_dcr_scopes"](api)
    assert writes == ["basic", "openid"]
    assert scopes["basic"]["protocolMappers"] == [{"name": "sub", "protocolMapper": "oidc-sub-mapper"}]
    assert basic["protocolMappers"][0]["id"] == "master-sub"


@pytest.mark.parametrize("profile_was_optional", [False, True])
def test_dcr_repairs_realm_email_and_profile_defaults(profile_was_optional):
    api = Mock()
    scopes = {name: f"id-{name}" for name in CONFIG["DCR_SCOPES"]}
    default_path = "/default-default-client-scopes"
    optional_path = "/default-optional-client-scopes"
    defaults = {scopes["basic"], "id-custom-default"}
    optional = {scopes["offline_access"]}
    if profile_was_optional:
        optional.add(scopes["profile"])
    writes = []

    def request(method, path):
        if method == "GET" and path in (default_path, optional_path):
            assigned = defaults if path == default_path else optional
            return [{"id": scope_id} for scope_id in assigned]
        collection, scope_id = path.rsplit("/", 1)
        if method == "DELETE" and collection == optional_path:
            optional.remove(scope_id)
        else:
            assert method == "PUT" and collection == default_path
            assert scope_id not in optional
            defaults.add(scope_id)
        writes.append((method, collection, scope_id))

    api.call.side_effect = request
    configure = CONFIG["_configure_dcr"]
    with patch.dict(configure.__globals__, _ensure_dcr_scopes=Mock(return_value=scopes),
                    upsert_mapper=Mock(), _configure_registration=Mock()):
        configure(api)
        configure(api)

    expected = [("PUT", default_path, scopes["email"])]
    if profile_was_optional:
        expected.append(("DELETE", optional_path, scopes["profile"]))
    expected.append(("PUT", default_path, scopes["profile"]))
    assert writes == expected
    assert defaults == {scopes["basic"], scopes["email"], scopes["profile"], "id-custom-default"}
    assert optional == {scopes["offline_access"]}


@pytest.mark.parametrize("hosts", ["", "new.example"])
def test_anonymous_policies_preserve_existing_restrictions(monkeypatch, hosts):
    monkeypatch.setenv("KEYCLOAK_DCR_TRUSTED_HOSTS", hosts)
    policies = {
        "trusted": {"id": "trusted", "providerId": "trusted-hosts", "subType": "anonymous",
                    "config": {"trusted-hosts": ["old.example"],
                               "host-sending-registration-request-must-match": ["true"],
                               "client-uris-must-match": ["true"]}},
        "allowed": {"id": "allowed", "providerId": "allowed-client-templates", "subType": "anonymous",
                    "config": {"allowed-client-scopes": ["existing"]}},
        "auth": {"id": "auth", "providerId": "allowed-client-templates", "subType": "authenticated",
                 "config": {"allowed-client-scopes": ["custom"]}},
    }
    old = deepcopy(policies)
    writes = []

    def request(method, path, body=None):
        if path == "":
            return {"id": "test-realm"}
        if method == "GET":
            assert path.startswith("/components?")
            return list(policies.values())
        assert method == "PUT"
        policies[body["id"]] = body
        writes.append(body["id"])

    api = Mock()
    api.call.side_effect = request
    CONFIG["_configure_registration"](api)
    CONFIG["_configure_registration"](api)
    assert writes == (["allowed", "trusted"] if hosts else ["allowed"])
    assert policies["auth"] == old["auth"]
    expected = old["trusted"]["config"]
    if hosts:
        expected["trusted-hosts"].append(hosts)
    assert policies["trusted"]["config"] == expected
    assert policies["allowed"]["config"]["allowed-client-scopes"] == ["existing", *CONFIG["DCR_SCOPES"]]


def test_conflicting_mapper_is_reported_without_replacing_it():
    api = Mock()
    api.call.return_value = [{"name": "groups", "id": "custom", "protocolMapper": "different"}]
    with pytest.raises(RuntimeError, match="Conflicting mapper groups"):
        CONFIG["upsert_mapper"](api, "/mappers", {
            "name": "groups", "protocolMapper": "oidc-group-membership-mapper", "config": {},
        })
    assert api.call.call_args_list == [call("GET", "/mappers")]
