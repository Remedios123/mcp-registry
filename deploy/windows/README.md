# Native Windows gateway

Run these commands from the checkout root in PowerShell. Place portable binaries and the Python
environment in a sibling `mcp-registry-runtime` directory. The launcher stores configuration,
application logs, generated Nginx files, and local data in one instance directory under that
runtime. It uses the upstream HTTP Nginx template and binds to IPv4 loopback.

## Prepare the runtime

Use the Python version declared by `pyproject.toml` and put `uv` and Node.js with npm on the current
shell's PATH. Extract these portable programs into the runtime directory. Each name must occur
once under its listed directory. An explicit executable path in the instance configuration
overrides discovery.

| Runtime folder | Executable | Configuration override |
| --- | --- | --- |
| `openresty` | `nginx.exe` with Lua and `http_auth_request` | `WINDOWS_NGINX_EXE` |
| `mongodb-portable` | `mongod.exe` for the optional local database | `WINDOWS_MONGOD_EXE` |
| `keycloak` | `kc.bat` for the optional local identity provider | `WINDOWS_KEYCLOAK_BAT` |
| `jre` | `java.exe` for the chosen Keycloak release | `WINDOWS_JAVA_EXE` |

Create the project environment and build the frontend. Run each step with network access to its
package sources or a populated local cache.

```powershell
$runtime = Join-Path (Split-Path $PWD -Parent) 'mcp-registry-runtime'
$env:UV_PROJECT_ENVIRONMENT = Join-Path $runtime 'registry-venv'
uv sync --locked --no-dev
npm.cmd --prefix frontend ci
npm.cmd --prefix frontend run build
$python = Join-Path $env:UV_PROJECT_ENVIRONMENT 'Scripts/python.exe'
$env:UV_PROJECT_ENVIRONMENT = Join-Path $runtime 'mcpgw-venv'
uv sync --project servers/mcpgw --locked --no-dev
```

The upstream lock builds `yara-python` from source when a compatible Windows wheel is unavailable.
Install the matching Visual C++ build tools to run the security scanner on this host. In a disposable
loopback test only, `uv sync --locked --no-dev --no-install-package yara-python` can be used with
the security scanner disabled.

The second environment is for the WorkBuddy tool server. Skip that environment if you set
`WINDOWS_MANAGE_MCPGW=false`. Set `REGISTRY_WINDOWS_MCPGW_PYTHON` to override its Python path.
Install or cache the configured embeddings model if the registry will run without access to the
model source. The first registration may reach the proxy timeout while the model loads.

## Configure a local instance

```powershell
$instance = Join-Path $runtime 'gateway'
New-Item -ItemType Directory -Path $instance -Force | Out-Null
Copy-Item deploy/windows/gateway.env.example (Join-Path $instance 'gateway.env')
```

Fill the secret fields with distinct random strings of at least 32 characters. You can generate a
value with `& $python -c 'import secrets; print(secrets.token_urlsafe(48))'`. Keep the configuration
directory private and retain its secrets between starts. The local Keycloak mode copies its binaries
into the instance and imports the upstream realm when the realm is absent. Sign into its
administrative console at `http://127.0.0.1:18080/admin` with the configured `KEYCLOAK_ADMIN`
username, which defaults to `admin`, and `KEYCLOAK_ADMIN_PASSWORD`. Create a realm user and place
them in `mcp-registry-admin` to administer the registry. Changing the client secret, public origin,
or initial Keycloak administrative password on an existing instance also requires updating that
setting in Keycloak.

The example uses local Keycloak development mode and loopback MongoDB. The launcher runs the
upstream MongoDB initializer for a fresh local database, including the Keycloak group-to-scope
mappings required to register servers.

The managed loopback MongoDB is for local smoke testing. For real UC, set
`WINDOWS_MANAGE_MONGO=false` and point `SHIM_MONGO_URI` at an authenticated database.

For a shared deployment,
set `WINDOWS_MANAGE_KEYCLOAK=false` and `WINDOWS_MANAGE_MONGO=false`, and configure the existing
Keycloak and authenticated MongoDB services using the settings in `.env.example`. For a fresh
external database, run `scripts/init-mongodb-ce.py` with its intended MongoDB configuration, or use
the upstream DocumentDB initialization for AWS DocumentDB. Set
`REGISTRY_URL` to the HTTPS browser origin. Terminate TLS at a front proxy that overwrites forwarded
headers, forwards to the loopback gateway port, and preserves the browser Host. Set
`SESSION_COOKIE_SECURE=true` and add the registry OAuth callback to the Keycloak web client. Use
that instance's exact host in `GATEWAY_ADDITIONAL_SERVER_NAMES` if you override the default.

## Start, inspect, and stop

```powershell
& $python -B deploy/windows/gateway.py start --runtime $runtime --instance $instance
& $python -B deploy/windows/gateway.py status --instance $instance
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:17860/
& $python -B deploy/windows/gateway.py stop --instance $instance
```

Start waits for each managed service and exits after the gateway is ready. Re-run start after stop
to restart the same instance. Distinct instances need distinct local ports and directories. A port
collision fails before starting anything. Status reports process and readiness checks and returns
exit code 1 when any managed component is unavailable. Service output is in
`<instance>/logs/*-console.log`. Nginx access and error logs are in `<instance>/nginx/logs`.
The launcher runs under the calling account. Use the same account to start and stop an instance.
Set `NGINX_DNS_RESOLVER` to your internal DNS server IPs if routes target private names.

## WorkBuddy registry tools

With `WINDOWS_MANAGE_MCPGW=true`, the launcher starts the upstream tool server on
`127.0.0.1:8003` and the registry registers it at `/airegistry-tools/`. WorkBuddy uses
`<REGISTRY_URL>/airegistry-tools/mcp`. The launcher sets the server's externally advertised
origin from `REGISTRY_URL` and gives it the local Nginx listener for its Registry API requests.
The built-in route trusts the configured loopback URL for this specific service. Custom MCP
routes continue to use the standard outbound URL policy. Keep the default host/origin checks
enabled and use explicit values if you set `MCPGW_HTTP_ALLOWED_HOSTS`.

## Company CAS and MCP adapters

Set `WINDOWS_MANAGE_CAS_SHIM=true` and review `cas-shim/.env.example`. Supply the company CAS and
user-center URLs, TLS trust, browser callback, shim client secret, signing secret, and internal
token. The launcher stores the shim's generated signing key in the instance. On a deployment with
company data, use an authenticated MongoDB deployment and set `SHIM_MONGO_URI` to the shim's
own database connection. For example, use
`mongodb://SHIM_USER:PASSWORD@mongo.company.example:27017/cas_shim?authSource=admin&tls=true`.
URL-encode credentials that contain special characters. Set the registry's authenticated
`MONGODB_CONNECTION_STRING` separately. Managed local MongoDB is for loopback development and
mock CAS tests.
The shim's access logger is disabled because CAS callbacks can carry tickets in their query
strings. Configure the front proxy's shim access logs to omit query strings as well.

From a shell with `KEYCLOAK_ADMIN_URL`, `KEYCLOAK_ADMIN_PASSWORD`, `SHIM_BASE_URL`,
`SHIM_PUBLIC_URL`, and `SHIM_CLIENT_SECRET` set, configure the Keycloak broker. Use the
same issuer and client credentials configured on the shim. With whitelist signup, bind
each employee before their first sign-in.

```powershell
& $python keycloak/setup/configure-cas.py configure --signup-mode whitelist
& $python keycloak/setup/configure-cas.py bind EMP001 'Display Name'
```

Register the Keycloak broker redirect URI in `SHIM_ALLOWED_REDIRECT_URIS` and allow
the shim's CAS callback in the CAS service configuration. Configure
`EGRESS_AUTH_ENABLED` and `ENTERPRISE_CREDENTIAL_PROFILES` for servers that use a shim-managed
business credential. The launcher defaults the registry's `ENTERPRISE_CREDENTIAL_SHIM_URL` to the
local shim listener and its browser URL to `SHIM_PUBLIC_URL` or `SHIM_BASE_URL`. Expose only the
browser and OIDC endpoints required by the CAS and Keycloak flow through the HTTPS front proxy.

The HR and data adapters are separate applications. Start them from their own project directories
using their native Windows instructions and configuration. The previous deployment used ports
`8000` and `8100` respectively. Register their actual reachable MCP URLs through the Registry UI.
For loopback HTTP adapters, the gateway requires the loopback CIDR in `SSRF_ALLOWED_CIDRS` and
`MCP_HTTPS_REQUIRED=false` in that instance. Configure the adapters' allowed origins to match
their deployment and preserve the existing origin checks.
