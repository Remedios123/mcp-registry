#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
envfile=${GATEWAY_ENV:-/data/mcp-gateway/config/gateway.env}
if [[ ! -r $envfile ]]; then echo "Cannot read $envfile" >&2; exit 1; fi
if [[ -z ${BUILD_VERSION:-} ]]; then
  if [[ $(basename "$PWD") =~ ^[0-9a-f]{40}$ ]]; then BUILD_VERSION=$(basename "$PWD")
  else BUILD_VERSION=$(git rev-parse --verify HEAD); fi
fi
export BUILD_VERSION
exec docker compose -p mcp-gateway --env-file deploy/linux/gateway.defaults.env --env-file "$envfile" \
  -f docker-compose.yml -f deploy/linux/compose.override.yml "$@"
