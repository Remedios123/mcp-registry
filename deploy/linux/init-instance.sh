#!/usr/bin/env bash
# Run as root after extracting the release, model and private env on Linux.
set -euo pipefail
cd "$(dirname "$0")/../.."
dc=(bash deploy/linux/compose.sh)
base=/data/mcp-gateway
[[ $EUID == 0 ]] || { echo 'Run with sudo bash' >&2; exit 1; }
mountpoint -q /data || { echo '/data is not mounted' >&2; exit 1; }
envfile=${GATEWAY_ENV:-$base/config/gateway.env}
[[ -s "$envfile" && -s "$base/models/bge-small-zh-v1.5/model.safetensors" ]] || {
  echo 'Install the private env and BGE model first.' >&2; exit 1; }
chmod 600 "$envfile"
install -d -m 0755 "$base/config/ca"
install -d -m 0750 -o 1000 -g 1000 "$base/logs" "$base/data/servers" "$base/data/agents"
install -d -m 0700 -o 1000 -g 1000 "$base/data/shim-keys"
if [[ ! -e "$base/config/federation.json" ]]; then
  (set -o noclobber; printf '{}\n' > "$base/config/federation.json")
fi
chmod 644 "$base/config/federation.json"

# Generate from this release's upstream templates without modifying tracked files.
mkdir -p deploy/linux/.generated
for filename in nginx_rev_proxy_http_only.conf nginx_rev_proxy_http_and_https.conf; do
  target="deploy/linux/.generated/$filename"
  tmp=$(mktemp "${target}.XXXXXX")
  if ! awk -v http_only="$([[ $filename == *http_only* ]] && echo 1 || echo 0)" '
    { if (http_only && $0 ~ /^[[:space:]]*8080[[:space:]]+80;$/) {
        sub(/80;$/, "443;"); port++
      }
      print
      if ($0 ~ /server_name localhost [{][{]ADDITIONAL_SERVER_NAMES[}][}];/) {
        print "    include /etc/nginx/cas-browser.inc;"; count++
      }
    }
    END { if (count != (http_only ? 1 : 2) || (http_only && port != 1)) exit 1 }
  ' "docker/$filename" > "$tmp"; then
    rm -f -- "$tmp"; echo "Upstream template layout changed: $filename" >&2; exit 1
  fi
  chmod 644 "$tmp"
  if cmp -s "$tmp" "$target"; then rm -f -- "$tmp"; else mv -- "$tmp" "$target"; fi
done

"${dc[@]}" config --quiet
"${dc[@]}" build registry auth-server mcpgw-server metrics-service metrics-db cas-shim
"${dc[@]}" up -d --wait --wait-timeout 240 keycloak mongodb
"${dc[@]}" up -d mongodb-init
# Wait for the existing init container even when it already finished.
init_id=$("${dc[@]}" ps -aq mongodb-init)
[[ -n $init_id && $(docker wait "$init_id") == 0 ]] || { echo 'mongodb-init failed' >&2; exit 1; }
"${dc[@]}" run --rm --no-deps enterprise-init
"${dc[@]}" up -d --wait --wait-timeout 360 keycloak registry mcpgw-server cas-shim
"${dc[@]}" exec -T registry nginx -t
"${dc[@]}" ps -a
