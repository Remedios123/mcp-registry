"""Start and inspect the native Windows MCP Registry gateway."""

import argparse
from contextlib import contextmanager
import json
import msvcrt
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlsplit
from urllib.request import build_opener, ProxyHandler

from dotenv import dotenv_values
import httpx
import psutil

from nginx_bridge import nginx_command, prepare_nginx


REPO = Path(__file__).resolve().parents[2]
DEFAULT_RUNTIME = REPO.with_name("mcp-registry-runtime")
STARTUP_TIMEOUT = 180
DEFAULT_PORTS = {
    "GATEWAY": 17860,
    "REGISTRY": 7860,
    "AUTH": 18888,
    "INTERNAL": 18091,
    "KEYCLOAK": 18080,
    "KEYCLOAK_MANAGEMENT": 19000,
    "MONGO": 27037,
    "SHIM": 8085,
    "MCPGW": 8003,
}


def _endpoint(port: int) -> str:
    return f"http://127.0.0.1:{port}"


def _enabled(env: dict[str, str], name: str) -> bool:
    value = env.get(name, "false").lower()
    if value not in {"true", "false"}:
        raise ValueError(f"{name} must be true or false.")
    return value == "true"


def _executable(runtime: Path, env: dict[str, str], key: str, folder: str, name: str) -> Path:
    if env.get(key):
        result = Path(env[key]).resolve()
        if result.is_file():
            return result
    else:
        results = list((runtime / folder).rglob(name))
        if len(results) == 1 and results[0].is_file():
            return results[0]
    raise ValueError(f"Set {key} to the full path to {name}.")


def _configuration(args: argparse.Namespace) -> tuple[dict[str, str], dict[str, int]]:
    config = args.config or args.instance / "gateway.env"
    if not config.is_file():
        raise ValueError(f"Copy gateway.env.example to {config} and configure it.")
    env = {**{key: value for key, value in dotenv_values(config, interpolate=False).items()
              if value is not None}, **os.environ}
    ports = {name: int(env.get(f"WINDOWS_{name}_PORT", port))
             for name, port in DEFAULT_PORTS.items()}
    if any(not 1 <= port <= 65535 for port in ports.values()) or len(set(ports.values())) != len(ports):
        raise ValueError("Windows component ports must be distinct integers between 1 and 65535.")
    gateway = env.get("REGISTRY_URL") or _endpoint(ports["GATEWAY"])
    origin = urlsplit(gateway)
    if (origin.scheme not in {"http", "https"} or not origin.hostname
            or origin.path not in {"", "/"} or origin.query or origin.fragment or origin.username):
        raise ValueError("REGISTRY_URL must be an HTTP or HTTPS origin.")
    nginx = _executable(args.runtime, env, "WINDOWS_NGINX_EXE", "openresty", "nginx.exe")
    log_dir = (args.instance / "logs").as_posix()
    # The 1.37 validator requires a leading slash. An extended drive path
    # satisfies that check and still names the correct Windows volume.
    application_logs = log_dir if log_dir.startswith("//") else f"//?/{log_dir}"
    env.update({
        **{f"WINDOWS_{name}_PORT": str(port) for name, port in ports.items()},
        "WINDOWS_NGINX_EXE": str(nginx),
        "WINDOWS_NGINX_PREFIX": str(args.instance / "nginx"),
        "PATH": str(nginx.parent) + os.pathsep + env.get("PATH", ""),
        "PYTHONPATH": str(REPO),
        "PYTHONUTF8": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "APP_LOG_DIR": application_logs,
        "CONTAINER_LOG_DIR": log_dir,
        "REGISTRY_URL": gateway.rstrip("/"),
        "AUTH_SERVER_URL": _endpoint(ports["AUTH"]),
        "AUTH_SERVER_EXTERNAL_URL": gateway.rstrip("/"),
        "EGRESS_REGISTRY_INTERNAL_URL": _endpoint(ports["INTERNAL"]),
        "NGINX_CONFIG_VALIDATION_REQUIRED": "true",
    })
    env.setdefault("NO_PROXY", "127.0.0.1,localhost")
    env.setdefault("GATEWAY_ADDITIONAL_SERVER_NAMES", f"127.0.0.1,{origin.hostname}")
    env.setdefault("AUTH_PROVIDER", "keycloak")
    return env, ports


def _require_env(env: dict[str, str], lengths: dict[str, int]) -> None:
    for name, length in lengths.items():
        if len(env.get(name, "")) < length:
            raise ValueError(f"Set {name} in gateway.env or the parent environment.")


def _keycloak_setup(args: argparse.Namespace, env: dict[str, str], port: int) -> Path:
    _require_env(env, {"KEYCLOAK_CLIENT_SECRET": 32, "KEYCLOAK_ADMIN_PASSWORD": 32})
    source = _executable(args.runtime, env, "WINDOWS_KEYCLOAK_BAT", "keycloak", "kc.bat")
    java = _executable(args.runtime, env, "WINDOWS_JAVA_EXE", "jre", "java.exe")
    home = args.instance / "keycloak"
    launcher = home / "bin/kc.bat"
    if not launcher.is_file():
        shutil.copytree(source.parent.parent, home, ignore=shutil.ignore_patterns("data", "log"),
                        dirs_exist_ok=True)
    keycloak_url = _endpoint(port)
    env.update(JAVA_HOME=str(java.parent.parent), KEYCLOAK_URL=keycloak_url,
               KEYCLOAK_EXTERNAL_URL=keycloak_url, KEYCLOAK_REALM="mcp-gateway",
               KEYCLOAK_CLIENT_ID="mcp-gateway-web")
    env.setdefault("KEYCLOAK_ADMIN", "admin")
    _prepare_realm(home, env)
    return launcher


def _prepare_realm(home: Path, env: dict[str, str]) -> None:
    target = home / "data/import/mcp-gateway-realm.json"
    realm = json.loads((REPO / "keycloak/import/realm-config.json").read_text(encoding="utf-8"))
    realm.update(realm.pop("eventsConfig", {}))
    realm.pop("users", None)
    client = next(entry for entry in realm["clients"] if entry["clientId"] == "mcp-gateway-web")
    gateway = env["REGISTRY_URL"]
    client.update(
        secret=env["KEYCLOAK_CLIENT_SECRET"], rootUrl=gateway, baseUrl=gateway, adminUrl=gateway,
        redirectUris=[f"{gateway}/oauth2/callback/keycloak"], webOrigins=[gateway],
    )
    for attribute, claim in (("id", "sub"), ("username", "preferred_username")):
        client.setdefault("protocolMappers", []).append({
            "name": f"windows-{claim}",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-property-mapper",
            "config": {
                "user.attribute": attribute,
                "claim.name": claim,
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        })
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(realm), encoding="utf-8")


def _repair_keycloak_web_scopes(env: dict[str, str]) -> None:
    """Restore the standard web scopes omitted by an old realm import."""
    realm = env["KEYCLOAK_REALM"]
    web_client = env["KEYCLOAK_CLIENT_ID"]
    token_path = "/realms/master/protocol/openid-connect/token"
    authorize_path = f"/realms/{realm}/protocol/openid-connect/auth"
    authorize_params = {
        "client_id": web_client,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": f"{env['REGISTRY_URL']}/oauth2/callback/keycloak",
        "code_challenge": "A" * 43,
        "code_challenge_method": "S256",
    }
    with httpx.Client(base_url=env["KEYCLOAK_URL"], trust_env=False, timeout=15) as client:
        probe = client.get(authorize_path, params=authorize_params)
        location = urlsplit(probe.headers.get("location", ""))
        if parse_qs(location.query).get("error") != ["invalid_scope"]:
            return
        try:
            token = client.post(token_path, data={
                "client_id": "admin-cli",
                "grant_type": "password",
                "username": env["KEYCLOAK_ADMIN"],
                "password": env["KEYCLOAK_ADMIN_PASSWORD"],
            }).raise_for_status().json()["access_token"]
            _restore_keycloak_web_scopes(client, realm, web_client, token)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Could not restore local Keycloak web scopes: {exc}") from exc
    print("Keycloak web sign-in scopes restored.")


def _restore_keycloak_web_scopes(
    client: httpx.Client,
    realm: str,
    web_client: str,
    token: str,
) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    realm_api = f"/admin/realms/{realm}"
    scopes_path = f"{realm_api}/client-scopes"
    required = {"email", "profile"}
    scopes = client.get(scopes_path, headers=headers).raise_for_status().json()
    missing = required.difference(scope["name"] for scope in scopes)
    if missing:
        defaults = client.get("/admin/realms/master/client-scopes", headers=headers).raise_for_status().json()
        for scope in defaults:
            if scope["name"] in missing:
                # Copy Keycloak's own mappers, but let the target realm assign IDs.
                scope.pop("id", None)
                for mapper in scope.get("protocolMappers", []):
                    mapper.pop("id", None)
                client.post(scopes_path, headers=headers, json=scope).raise_for_status()
        scopes = client.get(scopes_path, headers=headers).raise_for_status().json()
    selected = {scope["name"]: scope["id"] for scope in scopes if scope["name"] in required}
    if selected.keys() != required:
        raise RuntimeError("The local Keycloak master realm lacks the standard email or profile scope.")
    clients = client.get(f"{realm_api}/clients", params={"clientId": web_client}, headers=headers)
    web = next((entry for entry in clients.raise_for_status().json() if entry["clientId"] == web_client), None)
    if web is None:
        raise RuntimeError(f"Keycloak client {web_client} is missing from {realm}.")
    client_path = f"{realm_api}/clients/{web['id']}"
    default_path = f"{client_path}/default-client-scopes"
    default = client.get(default_path, headers=headers).raise_for_status().json()
    optional = client.get(f"{client_path}/optional-client-scopes", headers=headers).raise_for_status().json()
    assigned = {scope["id"] for scope in default + optional}
    for scope_id in sorted(set(selected.values()) - assigned):
        client.put(f"{default_path}/{scope_id}", headers=headers).raise_for_status()


def _uvicorn(app: str, port: int, *options: str) -> list[str]:
    return [sys.executable, "-m", "uvicorn", app, "--host", "127.0.0.1", "--port", str(port),
            *options]


def _commands(
    args: argparse.Namespace, env: dict[str, str], ports: dict[str, int],
) -> list[tuple[str, list[str] | str, str | int]]:
    commands = []
    if _enabled(env, "WINDOWS_MANAGE_MONGO"):
        mongo = _executable(args.runtime, env, "WINDOWS_MONGOD_EXE", "mongodb-portable", "mongod.exe")
        database = env.get("DOCUMENTDB_DATABASE") or "mcp_registry"
        db_path = args.instance / "mongodb"
        db_path.mkdir(exist_ok=True)
        port = ports["MONGO"]
        env.update(DOCUMENTDB_HOST="127.0.0.1", DOCUMENTDB_PORT=str(port), DOCUMENTDB_DATABASE=database,
                   DOCUMENTDB_USE_TLS="false", DOCUMENTDB_DIRECT_CONNECTION="true",
                   MONGODB_CONNECTION_STRING=f"mongodb://127.0.0.1:{port}/{database}?directConnection=true")
        commands.append(("mongodb", [str(mongo), "--dbpath", str(db_path), "--port", str(port),
                                     "--bind_ip", "127.0.0.1"], port))
        env.setdefault("SHIM_MONGO_URI", f"mongodb://127.0.0.1:{port}/?directConnection=true")
    if _enabled(env, "WINDOWS_MANAGE_KEYCLOAK"):
        port = ports["KEYCLOAK"]
        launcher = _keycloak_setup(args, env, port)
        options = ["start-dev", "--import-realm", "--db=dev-file", "--http-host=127.0.0.1",
                   f"--http-port={port}", f"--hostname={_endpoint(port)}",
                   f"--http-management-port={ports['KEYCLOAK_MANAGEMENT']}"]
        command_line = f'"{env["COMSPEC"]}" /d /s /c ""{launcher}" {" ".join(options)}"'
        commands.append(("keycloak", command_line,
                         _endpoint(port) + "/realms/mcp-gateway/.well-known/openid-configuration"))
    if _enabled(env, "WINDOWS_MANAGE_CAS_SHIM"):
        port = ports["SHIM"]
        _require_env(env, {"SHIM_CLIENT_SECRET": 32, "SHIM_SIGNING_SECRET": 32, "SHIM_INTERNAL_TOKEN": 32})
        if not _enabled(env, "CAS_SHIM_MOCK"):
            _require_env(env, {"CAS_BASE": 1, "UC_AUTH_URL": 1})
            if _enabled(env, "WINDOWS_MANAGE_MONGO"):
                raise ValueError("Real CAS and UC require authenticated MongoDB. Set WINDOWS_MANAGE_MONGO=false.")
            _require_env(env, {"SHIM_MONGO_URI": 1})
        env.setdefault("SHIM_BASE_URL", _endpoint(port))
        env.setdefault("SHIM_SIGNING_KEY_PATH", str(args.instance / "shim-signing-key.pem"))
        if _enabled(env, "WINDOWS_MANAGE_KEYCLOAK"):
            realm = f"{env['KEYCLOAK_EXTERNAL_URL']}/realms/{env['KEYCLOAK_REALM']}"
            env.setdefault("SHIM_ALLOWED_REDIRECT_URIS", f"{realm}/broker/cas/endpoint")
        env.setdefault("ENTERPRISE_CREDENTIAL_SHIM_URL", _endpoint(port))
        env.setdefault("ENTERPRISE_CREDENTIAL_SHIM_PUBLIC_URL",
                       env.get("SHIM_PUBLIC_URL") or env["SHIM_BASE_URL"])
        commands.append(("cas-shim", _uvicorn("app:app", port, "--app-dir", str(REPO / "cas-shim"),
                                              "--no-access-log"),
                         _endpoint(port) + "/.well-known/openid-configuration"))
    if _enabled(env, "WINDOWS_MANAGE_MCPGW"):
        port = ports["MCPGW"]
        if env.get("MCPGW_HTTP_ALLOWED_HOSTS", "").strip() == "*":
            raise ValueError("Use explicit MCPGW_HTTP_ALLOWED_HOSTS to keep origin protection enabled.")
        python = _executable(args.runtime, env, "REGISTRY_WINDOWS_MCPGW_PYTHON", "mcpgw-venv", "python.exe")
        commands.append(("mcpgw", [str(python), str(REPO / "servers/mcpgw/server.py")],
                         _endpoint(port) + "/health"))
    else:
        env.setdefault("DISABLE_AI_REGISTRY_TOOLS_SERVER", "true")
    bridge = str(Path(__file__).with_name("nginx_bridge.py"))
    return commands + [
        ("auth-server", [sys.executable, bridge, "auth"], _endpoint(ports["AUTH"]) + "/health"),
        ("registry", [sys.executable, bridge],
         _endpoint(ports["REGISTRY"]) + "/health"),
        ("nginx", nginx_command(Path(env["WINDOWS_NGINX_EXE"]), Path(env["WINDOWS_NGINX_PREFIX"])),
         _endpoint(ports["GATEWAY"]) + "/"),
    ]


@contextmanager
def _lock(instance: Path):
    instance.mkdir(parents=True, exist_ok=True)
    with (instance / "control.lock").open("a+b") as lock:
        if lock.tell() == 0:
            lock.write(b"\0")
            lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise RuntimeError("Another operation is controlling this instance.") from exc
        yield


def _write_state(state_path: Path, state: dict) -> None:
    pending = state_path.with_suffix(".tmp")
    pending.write_text(json.dumps(state, indent=2), encoding="utf-8")
    pending.replace(state_path)


def _live(entry: dict) -> psutil.Process | None:
    try:
        process = psutil.Process(entry["pid"])
        if process.create_time() == entry["created"]:
            return process
    except psutil.NoSuchProcess:
        pass
    return None


def _ready(target: str | int) -> bool:
    try:
        if isinstance(target, int):
            # Mongo has finished recovery when it can answer a database command.
            from pymongo import MongoClient
            from pymongo.errors import PyMongoError

            try:
                with MongoClient("127.0.0.1", target, serverSelectionTimeoutMS=800) as client:
                    return bool(client.admin.command("ping").get("ok"))
            except PyMongoError:
                return False
        with build_opener(ProxyHandler({})).open(target, timeout=2) as response:
            return response.status == 200
    except OSError:
        return False


def _wait_ready(name: str, process: subprocess.Popen, target: str | int, log: Path) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline and process.poll() is None:
        if _ready(target):
            print(f"{name} ready", flush=True)
            return
        time.sleep(0.5)
    raise RuntimeError(f"{name} failed its readiness check. See {log}.")


def _available_ports(env: dict[str, str], ports: dict[str, int]) -> None:
    managed = {"MONGO": "WINDOWS_MANAGE_MONGO", "KEYCLOAK": "WINDOWS_MANAGE_KEYCLOAK",
               "KEYCLOAK_MANAGEMENT": "WINDOWS_MANAGE_KEYCLOAK",
               "SHIM": "WINDOWS_MANAGE_CAS_SHIM", "MCPGW": "WINDOWS_MANAGE_MCPGW"}
    for name, port in ports.items():
        if name in managed and not _enabled(env, managed[name]):
            continue
        with socket.socket() as check:
            check.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                check.bind(("127.0.0.1", port))
            except OSError as exc:
                raise RuntimeError(f"Port {port} for {name} is occupied.") from exc


def _bootstrap_database(instance: Path, env: dict[str, str]) -> None:
    from pymongo import MongoClient

    pending = instance / "mongodb-bootstrap.pending"
    namespace = env.get("DOCUMENTDB_NAMESPACE", "default")
    with MongoClient(env["MONGODB_CONNECTION_STRING"], timeoutMS=5000) as client:
        scopes = client[env["DOCUMENTDB_DATABASE"]][f"mcp_scopes_{namespace}"]
        if not pending.exists() and scopes.find_one({}, {"_id": 1}) is not None:
            return
    pending.touch()
    log = instance / "logs/mongodb-init-console.log"
    with log.open("a", encoding="utf-8") as output:
        try:
            subprocess.run(
                [sys.executable, str(REPO / "scripts/init-mongodb-ce.py")],
                env=env, cwd=REPO, stdout=output, stderr=output, timeout=120, check=True,
            )
        except subprocess.SubprocessError as exc:
            raise RuntimeError(f"MongoDB initialization failed. See {log}.") from exc
    pending.unlink()


def _shutdown(name: str, entry: dict) -> None:
    process = _live(entry)
    if process is None:
        return
    children = process.children(recursive=True)
    if name == "nginx":
        try:
            subprocess.run([*entry["command"], "-s", "quit"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
    if name == "mongodb":
        from pymongo import MongoClient
        from pymongo.errors import PyMongoError

        try:
            with MongoClient("127.0.0.1", entry["target"], directConnection=True,
                             timeoutMS=3000) as client:
                client.admin.command("shutdown")
        except PyMongoError:
            pass
    if name in {"nginx", "mongodb"}:
        _, alive = psutil.wait_procs([process, *children], timeout=10)
    else:
        alive = [process, *children]
    for running in reversed(alive):
        try:
            running.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(alive, timeout=10)
    if alive:
        raise RuntimeError(f"{name} still has running processes. Check instance permissions.")


def _start(args: argparse.Namespace, state_path: Path, state: dict) -> None:
    if any(_live(entry) is not None for entry in state.values()):
        raise RuntimeError("This instance has running components. Use status or stop first.")
    env, ports = _configuration(args)
    _require_env(env, {"SECRET_KEY": 32, "AUTH_SERVER_NGINX_MARKER_SECRET": 32})
    _available_ports(env, ports)
    if not (REPO / "frontend/build/index.html").is_file():
        raise ValueError("Build the registry frontend first. See deploy/windows/README.md.")
    log_dir = args.instance / "logs"
    log_dir.mkdir(exist_ok=True)
    exe = Path(env["WINDOWS_NGINX_EXE"])
    prefix = Path(env["WINDOWS_NGINX_PREFIX"])
    prepare_nginx(REPO, exe, prefix)
    commands = _commands(args, env, ports)
    state.clear()
    _write_state(state_path, state)
    try:
        for name, command, target in commands:
            log = log_dir / f"{name}-console.log"
            if name == "nginx":
                rendered = (prefix / "gateway.conf").read_text(encoding="utf-8")
                if f"listen 127.0.0.1:{ports['GATEWAY']};" not in rendered:
                    raise RuntimeError(f"Registry did not generate an Nginx route. See {log_dir}.")
                with log.open("a", encoding="utf-8") as output:
                    subprocess.run([*command, "-t"], env=env, stdout=output, stderr=output, check=True)
            component_env = dict(env)
            if name == "auth-server":
                component_env["PYTHONPATH"] = str(REPO / "auth_server") + os.pathsep + str(REPO)
            if name == "mcpgw":
                component_env.update(
                    HOST="127.0.0.1", PORT=str(ports["MCPGW"]),
                    REGISTRY_BASE_URL=_endpoint(ports["GATEWAY"]),
                    REGISTRY_EXTERNAL_URL=env["REGISTRY_URL"],
                    MCPGW_BASE_URL=f"{env['REGISTRY_URL']}/airegistry-tools",
                )
                if env.get("KEYCLOAK_URL"):
                    component_env.setdefault("KEYCLOAK_INTERNAL_URL", env["KEYCLOAK_URL"])
            with log.open("a", encoding="utf-8") as output:
                proc = subprocess.Popen(command, cwd=REPO, env=component_env, stdin=subprocess.DEVNULL,
                                        stdout=output, stderr=subprocess.STDOUT,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
            state[name] = {"pid": proc.pid, "created": psutil.Process(proc.pid).create_time(),
                           "target": target, "command": command}
            _write_state(state_path, state)
            _wait_ready(name, proc, target, log)
            if name == "mongodb":
                _bootstrap_database(args.instance, env)
            elif name == "keycloak":
                _repair_keycloak_web_scopes(env)
    except BaseException:
        try:
            _stop(state_path, state)
        except RuntimeError as exc:
            print(f"Startup rollback: {exc}", file=sys.stderr)
        raise
    print(f"Gateway listening on {_endpoint(ports['GATEWAY'])}. Public URL {env['REGISTRY_URL']}.")


def _stop(state_path: Path, state: dict) -> None:
    failures = []
    for name, entry in reversed(list(state.items())):
        try:
            _shutdown(name, entry)
        except (OSError, RuntimeError, psutil.Error) as exc:
            failures.append(f"{name}: {exc}")
            continue
        del state[name]
        _write_state(state_path, state)
    if failures:
        raise RuntimeError("Could not stop all managed components. " + " | ".join(failures))
    print("Gateway stopped.")


def _status(instance: Path, state: dict) -> int:
    if not state:
        print("No managed components are running.")
        return 1
    unhealthy = False
    for name, entry in state.items():
        alive = _live(entry) is not None
        health = "ready" if alive and _ready(entry["target"]) else "unavailable"
        unhealthy |= health != "ready"
        print(f"{name:<12} {health:<12} PID {entry['pid']}")
    print(f"Logs: {instance / 'logs'}")
    return int(unhealthy)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["start", "status", "stop"])
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument("--instance", type=Path)
    parser.add_argument("--config", type=Path, help="Defaults to gateway.env in the instance directory.")
    args = parser.parse_args()
    args.runtime = args.runtime.resolve()
    args.instance = (args.instance or args.runtime / "gateway").resolve()
    state_path = args.instance / "processes.json"
    if not state_path.exists() and args.action != "start":
        return _status(args.instance, {}) if args.action == "status" else 0
    try:
        with _lock(args.instance):
            state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
            if args.action == "status":
                return _status(args.instance, state)
            if args.action == "start":
                _start(args, state_path, state)
            else:
                _stop(state_path, state)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, psutil.Error) as exc:
        print(f"{exc} Logs: {args.instance / 'logs'}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
