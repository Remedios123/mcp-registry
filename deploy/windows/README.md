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
The deployment commands use the checked-in lockfiles, which record their original dependency cutoff.

```powershell
$runtime = Join-Path (Split-Path $PWD -Parent) 'mcp-registry-runtime'
$env:UV_PROJECT_ENVIRONMENT = Join-Path $runtime 'registry-venv'
uv sync --frozen --no-dev
npm.cmd --prefix frontend ci
npm.cmd --prefix frontend run build
$python = Join-Path $env:UV_PROJECT_ENVIRONMENT 'Scripts/python.exe'
$env:UV_PROJECT_ENVIRONMENT = Join-Path $runtime 'mcpgw-venv'
uv sync --project servers/mcpgw --frozen --no-dev
```

The upstream lock builds `yara-python` from source when a compatible Windows wheel is unavailable.
Install the matching Visual C++ build tools to run the security scanner on this host. In a disposable
loopback test only, `uv sync --frozen --no-dev --no-install-package yara-python` can be used with
the security scanner disabled.

The second environment is for the WorkBuddy tool server. Skip that environment if you set
`WINDOWS_MANAGE_MCPGW=false`. Set `REGISTRY_WINDOWS_MCPGW_PYTHON` to override its Python path.
Install or cache the configured embeddings model if the registry will run without access to the
model source. The first registration may reach the proxy timeout while the model loads.

## Configure a local instance

For company CAS, use the [one-time CAS setup](#company-cas-and-mcp-adapters) below. For a
username/password-only Windows instance, configure the file manually.

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
For locally managed Keycloak, startup restores the standard email and profile scopes when
Keycloak rejects them. The realm accepts username/password sign-in with a blank email and name.

The example uses local Keycloak development mode and loopback MongoDB. The launcher runs the
upstream MongoDB initializer for a fresh local database, including the Keycloak group-to-scope
mappings required to register servers.

The CAS setup creates the credentials for the managed loopback MongoDB and enables authentication.
The data directory and credentials persist across launches.

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

After configuring `gateway.env`, double-click [start-gateway.bat](start-gateway.bat) in File Explorer
to start the default instance. Double-click [stop-gateway.bat](stop-gateway.bat) to stop it.
If either operation fails, the window stays open to show the error.

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

1. Finish [runtime preparation](#prepare-the-runtime) and double-click [setup-cas.bat](setup-cas.bat).
   Press Enter at the old file prompt to enter the current CAS base URL and UC ticket exchange
   URL yourself. Supply the UC refresh URL if available. The old file prompt also accepts a
   path to a previous shim's `.env` to prefill the endpoint settings. Enter the first employee's
   actual CAS/UC employee ID to bind that account when starting locally managed Keycloak in
   whitelist mode.
2. The installer creates or updates `mcp-registry-runtime/gateway/gateway.env` alongside the
   checkout. It generates any missing gateway, shim, and managed service secrets. Keep the file
   private and retain it with the instance data. Set `CAS_CA_BUNDLE` in this file if your CAS
   or UC HTTPS certificates require a PEM bundle trusted by the shim.
3. Ask the CAS administrator to allow the exact shim callback as a CAS service. For the default
   ports and a browser on the gateway machine, that callback is
   `http://127.0.0.1:8085/cas/callback`. For a browser on another computer, follow the
   [public HTTPS configuration](#browsers-accessing-the-gateway-from-another-computer).
4. To enable HR calls, start the HR adapter and add the following settings to `gateway.env`
   before starting the gateway. Replace the example URL in `upstreams` with the exact HR MCP
   URL you will register. For a loopback HTTP adapter, also set `SSRF_ALLOWED_CIDRS=127.0.0.1/32`
   and `MCP_HTTPS_REQUIRED=false`.

   ```dotenv
   EGRESS_AUTH_ENABLED=true
   ENTERPRISE_CREDENTIAL_PROFILES=[{"id":"uc","label":"UC","issuer":"uc","upstreams":["http://127.0.0.1:8000/mcp"]}]
   ```

5. If the gateway is already running, double-click [stop-gateway.bat](stop-gateway.bat) once,
   then double-click [start-gateway.bat](start-gateway.bat). On the default local instance open
   `http://127.0.0.1:17860/`, select **Continue with Keycloak**, then **企业内部登录**.
   The CAS account uses its employee ID without email or name.
6. In the Registry, register or edit HR, choose UC under
   **Egress Auth → Per-user OAuth → Enterprise credentials**, and grant its tools and the
   Registry Tools entry point to the relevant employee group. WorkBuddy connects to
   `http://127.0.0.1:17860/airegistry-tools/mcp` on the default local instance.

On later launches use the same `gateway.env`. Enable external MongoDB by setting
`WINDOWS_MANAGE_MONGO=false`, with authenticated `MONGODB_CONNECTION_STRING` and
`SHIM_MONGO_URI` for the Registry and shim databases. URL-encode special characters in URI
credentials. The local Keycloak administrative password is saved as `KEYCLOAK_ADMIN_PASSWORD`.
The Registry administrator is a realm user in `mcp-registry-admin` as described above.

When switching from UAT to production, update `CAS_BASE`, `UC_AUTH_URL` and `UC_REFRESH_URL`
in the instance configuration, and restart. Verify the callback registration on the new CAS
and complete UC authorization against the production issuer.

The shim's access logger is disabled because CAS callbacks can carry tickets in their query
strings. Configure the front proxy's shim access logs to omit query strings as well.

When the launcher manages both Keycloak and the shim, it registers the CAS identity provider
on first start. On the Registry login page, choose **Continue with Keycloak**, then
**企业内部登录** on the Keycloak page. Use `WINDOWS_CAS_SIGNUP_MODE=open` to allow automatic
account creation when registering a new provider. The default is `whitelist`.

For a separately managed Keycloak, configure the broker manually. From a shell with
`KEYCLOAK_ADMIN_URL`, `KEYCLOAK_ADMIN_PASSWORD`, `SHIM_BASE_URL`,
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

### Browsers accessing the gateway from another computer

Give users the gateway HTTPS URL. A loopback browser URL points at the computer running the browser.
For example, route `https://gateway.company.example` to the gateway's loopback listener on port
17860, `https://sso.company.example` to Keycloak, and `https://cas-shim.company.example` to the shim's
browser endpoints `/authorize`, `/cas/callback`, and `/renew`. Keep the shim's `/internal/` endpoints
on the private listener. The reverse proxy preserves the original Host and sets trusted HTTPS
forwarding headers.

Set `REGISTRY_URL`, `KEYCLOAK_EXTERNAL_URL`, `SHIM_PUBLIC_URL`, and `SHIM_CALLBACK_URL` to those public
origins and callback. Set `SHIM_ALLOWED_REDIRECT_URIS` to the exact public Keycloak broker callback.
On the same server, `KEYCLOAK_URL` and `SHIM_BASE_URL` can use the private loopback listeners. The
Windows-managed Keycloak uses a loopback browser hostname. For the HTTPS hostname above, set
`WINDOWS_MANAGE_KEYCLOAK=false` and run Keycloak with `KC_HOSTNAME=https://sso.company.example`,
`KC_PROXY_HEADERS=xforwarded`, and `KC_HTTP_ENABLED=true` behind a TLS-terminating proxy. Register
`https://gateway.company.example/oauth2/callback/keycloak` and
`https://gateway.company.example/logout` in the Keycloak web client. Register
`https://cas-shim.company.example/cas/callback` as the CAS service and configure the Keycloak broker.
See the [Keycloak reverse proxy documentation](https://www.keycloak.org/server/reverseproxy).

The HR and data adapters are separate applications. Start them from their own project directories
using their native Windows instructions and configuration. The previous deployment used ports
`8000` and `8100` respectively. Register their actual reachable MCP URLs through the Registry UI.
For loopback HTTP adapters, the gateway requires the loopback CIDR in `SSRF_ALLOWED_CIDRS` and
`MCP_HTTPS_REQUIRED=false` in that instance. Configure the adapters' allowed origins to match
their deployment and preserve the existing origin checks.
