#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
dc=(bash deploy/linux/compose.sh)
# Read only the three probe URLs from the final shim environment.
mapfile -t urls < <("${dc[@]}" exec -T cas-shim python -c \
  'import os; print(os.environ["CAS_BASE"].rstrip("/")+"/login",os.environ["UC_AUTH_URL"],os.environ["UC_REFRESH_URL"],sep="\n")')
[[ ${#urls[@]} == 3 ]] || { echo 'Cannot read cas-shim endpoints' >&2; exit 1; }
failed=0
for url in "${urls[@]}"; do
  curl -sS --connect-timeout 5 --max-time 15 -o /dev/null \
    -w 'host %{url_effective} remote=%{remote_ip} HTTP=%{http_code} TLS=%{ssl_verify_result}\n' "$url" || failed=1
done
"${dc[@]}" exec -T cas-shim python - <<'PY' || failed=1
import os
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, build_opener

class FirstResponse(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None

ctx = ssl.create_default_context(cafile=os.getenv("CAS_CA_BUNDLE") or None)
opener = build_opener(FirstResponse(), HTTPSHandler(context=ctx))
failed = False
for url in (os.environ["CAS_BASE"].rstrip("/")+"/login", os.environ["UC_AUTH_URL"], os.environ["UC_REFRESH_URL"]):
    try:
        with opener.open(url, timeout=15) as response:
            print("container", url, response.status)
    except HTTPError as exc:
        print("container", url, exc.code)
        exc.close()
    except (OSError, URLError) as exc:
        print("container", url, exc)
        failed = True
raise SystemExit(int(failed))
PY
"${dc[@]}" exec -T registry nginx -t || failed=1
"${dc[@]}" exec -T registry python -c \
  'from urllib.request import urlopen; print("mcpgw",urlopen("http://mcpgw-server:8003/health",timeout=8).status)' || failed=1
"${dc[@]}" ps -a
origin=$("${dc[@]}" exec -T registry printenv REGISTRY_URL)
# This request contains no employee identity or service token.
"${dc[@]}" exec -T registry python - <<'PY' || failed=1
from urllib.error import HTTPError
from urllib.request import urlopen

try:
    urlopen("http://127.0.0.1:8093/internal/business-token/probe", timeout=8)
except HTTPError as exc:
    if exc.code != 403 or exc.read() != b'{"error":"forbidden"}':
        raise
    print("Internal credential route reached shim and rejected missing authentication.")
else:
    raise SystemExit("Internal credential route did not require authentication.")
PY
curl -fsS -o /dev/null --connect-timeout 5 --max-time 20 "$origin/" || failed=1
outside=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 "$origin/internal/business-token/probe") || failed=1
if [[ $outside != 404 ]]; then
  printf 'Unexpected response on the public credential path: %s\n' "$outside" >&2
  failed=1
fi
printf 'BROWSER PENDING: on the employee Windows PC open %s, verify login and %s/airegistry-tools/mcp through WorkBuddy. Record the result separately.\n' "$origin" "$origin"
exit "$failed"
