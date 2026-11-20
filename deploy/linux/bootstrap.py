"""Provision a fresh Compose instance, preserving operator state on later runs."""

import json
import os
import subprocess
import sys
import runpy
from pathlib import Path
from urllib.parse import quote, unquote, urlencode, urlsplit

from pymongo import MongoClient
from pymongo.errors import OperationFailure

HERE = Path(__file__).resolve().parent
ENV = os.environ


def provision_mongo() -> None:
    database = ENV["SHIM_MONGO_DB"]
    uri = ENV["SHIM_MONGO_URI"]
    address = urlsplit(uri)
    if address.hostname != "mongodb" or not address.username or not address.password:
        raise ValueError("Expected an authenticated local mongodb service for the managed shim")
    username, password = unquote(address.username), unquote(address.password)
    with MongoClient("mongodb://mongodb:27017/?replicaSet=rs0", username=ENV["DOCUMENTDB_USERNAME"],
                     password=ENV["DOCUMENTDB_PASSWORD"], authSource="admin",
                     serverSelectionTimeoutMS=15000) as admin:
        db = admin[database]
        if not db.command("usersInfo", username)["users"]:
            try:
                db.command("createUser", username, pwd=password,
                           roles=[{"role": "readWrite", "db": database}])
            except OperationFailure as exc:
                if exc.code != 51003:  # Another bootstrap created this user first.
                    raise
    with MongoClient(uri, serverSelectionTimeoutMS=15000) as client:
        db = client[database]
        db.command("ping")
        db[ENV["SHIM_MONGO_COLLECTION"]].create_index("account", unique=True)


def desired_clients(template: dict) -> list[dict]:
    origin = ENV["REGISTRY_URL"].rstrip("/")
    web, machine = (next(c for c in template["clients"] if c["clientId"] == name)
                    for name in ("mcp-gateway-web", "mcp-gateway-m2m"))
    web.update(clientId=ENV["KEYCLOAK_CLIENT_ID"], secret=ENV["KEYCLOAK_CLIENT_SECRET"],
               rootUrl=origin, baseUrl=origin, adminUrl=origin,
               redirectUris=[origin + "/oauth2/callback/keycloak"], webOrigins=[origin])
    web.setdefault("attributes", {})["post.logout.redirect.uris"] = origin + "/*"
    machine.update(clientId=ENV["KEYCLOAK_M2M_CLIENT_ID"], secret=ENV["KEYCLOAK_M2M_CLIENT_SECRET"])
    return [web, machine]


def provision_realm(module: dict) -> None:
    api = module["AdminAPI"]()
    template = json.loads((HERE / "realm.json").read_text(encoding="utf-8"))
    realm_name = ENV["KEYCLOAK_REALM"]
    template["realm"] = realm_name
    template.update(template.pop("eventsConfig", {}))
    template["clients"] = desired_clients(template)
    template.pop("users", None)
    realms_url = api.origin + "/admin/realms"
    realms = api._request("GET", realms_url, None)
    if not any(r["realm"] == realm_name for r in realms):
        api._request("POST", realms_url, template)

    for expected in template["clients"]:
        client_id = expected["clientId"]
        query = urlencode({"clientId": client_id})
        found = [c for c in api.call("GET", "/clients?" + query) if c["clientId"] == client_id]
        if not found:
            api.call("POST", "/clients", expected)
            continue
        path = "/clients/" + quote(found[0]["id"], safe="")
        current = api.call("GET", path)
        requested = {k: expected[k] for k in ("secret", "rootUrl", "baseUrl", "adminUrl",
                                              "redirectUris", "webOrigins") if k in expected}
        if client_id == ENV["KEYCLOAK_CLIENT_ID"]:
            requested["attributes"] = {**(current.get("attributes") or {}),
                "post.logout.redirect.uris": expected["attributes"]["post.logout.redirect.uris"]}
        api.call("PUT", path, {**current, **requested})

    # Only initialize the named realm admin; never rotate an existing password.
    admins = api.call("GET", "/users?username=admin&exact=true")
    if not admins:
        group = "/mcp-registry-admin"
        api.call("POST", "/users", {"username": "admin", "enabled": True,
            "groups": [group, "/mcp-servers-unrestricted"],
            "credentials": [{"type": "password", "temporary": False,
                             "value": ENV["INITIAL_ADMIN_PASSWORD"]}]})

    # The imported realm may lack standard email/profile scopes on the web client.
    module["_ensure_dcr_scopes"](api)
    client = api.call("GET", "/clients?" + urlencode({"clientId": ENV["KEYCLOAK_CLIENT_ID"]}))[0]
    path = "/clients/" + client["id"] + "/default-client-scopes"
    assigned = {s["id"] for s in api.call("GET", path)}
    for scope in api.call("GET", "/client-scopes"):
        if scope["name"] in {"email", "profile"} and scope["id"] not in assigned:
            api.call("PUT", path + "/" + scope["id"])
    # Run the shared CAS/employee/DCR provisioning entry point as shipped.
    subprocess.run([sys.executable, str(HERE / "configure-cas.py"), "configure",
                    "--signup-mode", "open"], check=True)


if __name__ == "__main__":
    provision_mongo()
    provision_realm(runpy.run_path(str(HERE / "configure-cas.py")))
    print("MongoDB shim account and Keycloak CAS configuration verified.")
