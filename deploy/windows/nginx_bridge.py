"""Run the 1.37 gateway's Linux-oriented Nginx renderer on native Windows."""

import os
from dataclasses import replace
from ipaddress import IPv4Network
from pathlib import Path
import re
import shutil
import subprocess
import sys


def nginx_command(exe: Path, prefix: Path, *args: str) -> list[str]:
    return [str(exe), "-p", prefix.as_posix() + "/", "-c", "nginx.conf", *args]


def prepare_nginx(repo: Path, exe: Path, prefix: Path) -> None:
    for folder in ("logs", "lua/virtual_mappings", "html"):
        (prefix / folder).mkdir(parents=True, exist_ok=True)
    for source in (repo / "docker/lua").glob("*.lua"):
        lua = source.read_text(encoding="utf-8").replace(
            "/etc/nginx/lua/", (prefix / "lua").as_posix() + "/"
        )
        (prefix / "lua" / source.name).write_text(lua, encoding="utf-8")
    shutil.copyfile(repo / "docker/502.html", prefix / "html/502.html")
    (prefix / "gateway.conf").write_text("", encoding="utf-8")
    (prefix / "nginx.conf").write_text(
        "worker_processes 1;\n"
        "daemon off;\n"
        "env SECRET_KEY;\n"
        "error_log logs/error.log warn;\n"
        "pid logs/nginx.pid;\n"
        "events { worker_connections 1024; }\n"
        "http {\n"
        f'  include "{(exe.parent / "conf/mime.types").as_posix()}";\n'
        f'  lua_package_path "{(exe.parent / "lualib/?.lua").as_posix()};;";\n'
        "  include gateway.conf;\n"
        "}\n",
        encoding="utf-8",
    )


def _relocate_paths(content: str, source: str, target: Path) -> str:
    # Match full Nginx arguments so drive paths containing spaces stay quoted.
    return re.sub(
        rf"(?<![\w/]){re.escape(source)}[^\s;\x22]*",
        lambda match: '"' + target.as_posix() + match[0][len(source):] + '"',
        content,
    )


def _windows_config(
    content: str,
    repo: Path,
    exe: Path,
    prefix: Path,
    registry: int,
    gateway: int,
    internal: int,
) -> str:
    replacements = {
        "listen 8080;": f"listen 127.0.0.1:{gateway};",
        "listen 8091;": f"listen 127.0.0.1:{internal};",
        "http://127.0.0.1:7860": f"http://127.0.0.1:{registry}",
        "/usr/local/lib/lua/5.1/?.so": (exe.parent / "lualib/?.dll").as_posix(),
    }
    for source, target in replacements.items():
        content = content.replace(source, target)
    for source, target in {
        "/etc/nginx/lua": prefix / "lua",
        "/var/log/containers/ai-registry": prefix / "logs",
        "/app/frontend/build": repo / "frontend/build",
        "/usr/share/nginx/html": prefix / "html",
    }.items():
        content = _relocate_paths(content, source, target)
    return content


def _configure_builtin_tools() -> None:
    if os.environ.get("WINDOWS_MANAGE_MCPGW", "").lower() != "true":
        return
    from registry.services import demo_servers_init
    from registry.utils import url_guard

    port = int(os.environ["WINDOWS_MCPGW_PORT"])
    base = f"http://127.0.0.1:{port}/"
    identities = frozenset({base, base + "mcp", base + "mcp/"})
    url_guard._BUILTIN_AIREGISTRY_TOOLS_TARGET = base
    url_guard._BUILTIN_AIREGISTRY_TOOLS_OUTBOUND_IDENTITIES = identities
    # Preserve the exact upstream entity and outbound-URL checks. Only this
    # built-in profile gains permission to reach the Windows loopback target.
    url_guard.BUILTIN_AIREGISTRY_TOOLS_PROFILE = replace(
        url_guard.BUILTIN_AIREGISTRY_TOOLS_PROFILE,
        allowed_url_identities=identities,
        allowlist_factory=lambda: url_guard._Allowlist(cidrs=(IPv4Network("127.0.0.1/32"),)),
    )
    original_load = demo_servers_init._load_server_config

    def load_config(name):
        config = original_load(name)
        if name == "cli/examples/airegistry.json":
            config["proxy_pass_url"] = base
        return config

    demo_servers_init._load_server_config = load_config


def serve_auth() -> None:
    import uvicorn

    _configure_builtin_tools()
    uvicorn.run("auth_server.server:app", host="127.0.0.1",
                port=int(os.environ["WINDOWS_AUTH_PORT"]), h11_max_incomplete_event_size=2097152)


def serve_registry() -> None:
    import uvicorn

    _configure_builtin_tools()
    from registry.core.config import Settings

    repo = Path(__file__).resolve().parents[2]
    exe = Path(os.environ["WINDOWS_NGINX_EXE"])
    prefix = Path(os.environ["WINDOWS_NGINX_PREFIX"])
    registry = int(os.environ["WINDOWS_REGISTRY_PORT"])
    gateway = int(os.environ["WINDOWS_GATEWAY_PORT"])
    internal = int(os.environ["WINDOWS_INTERNAL_PORT"])
    Settings.nginx_config_path = property(lambda _: prefix / "gateway.conf")

    from registry.core import nginx_service as service

    service.VIRTUAL_MAPPINGS_DIR = prefix / "lua/virtual_mappings"
    service.nginx_service.nginx_template_path = repo / "docker/nginx_rev_proxy_http_only.conf"
    service_class = type(service.nginx_service)
    original_render = service_class._render_config_impl
    original_run = subprocess.run

    async def render(self, servers):
        rendered = await original_render(self, servers)
        if rendered is None:
            return None
        return _windows_config(rendered, repo, exe, prefix, registry, gateway, internal)

    def run_at_prefix(args, *positional, **kwargs):
        if isinstance(args, list) and args and args[0] == "nginx":
            args = nginx_command(exe, prefix, *args[1:])
        return original_run(args, *positional, **kwargs)

    service_class._render_config_impl = render
    # The upstream validation and reload functions import subprocess locally.
    # This wrapper is installed only in the dedicated Registry process.
    subprocess.run = run_at_prefix
    uvicorn.run("registry.main:app", host="127.0.0.1", port=registry)


if __name__ == "__main__":
    if sys.argv[1:] == ["auth"]:
        serve_auth()
    else:
        serve_registry()
