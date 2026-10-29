#!/usr/bin/env bash
# Deploy the PUBLIC ShipCheck demo to a Nebius AI Cloud serverless endpoint.
#
# The image is built with PUBLIC_DEMO=1: the dashboard replays the recorded
# real scan in golden/, and POST /scan is disabled (a live scan runs submitted
# code and spends Nemotron/Tavily credits). No API keys go into the image or
# the endpoint, so anyone can open the URL without spending anything.
#
# Needs: a Nebius AI Cloud profile (`nebius profile create`), Docker, jq.
#   REGION_ID=eu-north1 scripts/deploy_nebius.sh
# The endpoint keeps running (and billing) until deleted:
#   nebius ai endpoint delete <id>
set -euo pipefail

NEBIUS="${NEBIUS:-nebius}"
REGION_ID="${REGION_ID:-eu-north1}"
NAME="${NAME:-shipcheck-demo}"
REGISTRY_NAME="${REGISTRY_NAME:-shipcheck}"
PLATFORM="${PLATFORM:-cpu-d3}"
PRESET="${PRESET:-4vcpu-16gb}"
TAG="${TAG:-public-$(git rev-parse --short HEAD)}"
cd "$(dirname "$0")/.."

echo "== registry"
REGISTRY_ID=$("$NEBIUS" registry list --format json | jq -r --arg n "$REGISTRY_NAME" \
  '[.items[]? | select(.metadata.name == $n) | .metadata.id][0] // empty')
if [ -z "$REGISTRY_ID" ]; then
  REGISTRY_ID=$("$NEBIUS" registry create --name "$REGISTRY_NAME" --format json | jq -r '.metadata.id')
fi
REGISTRY_PATH="${REGISTRY_ID#registry-}"
IMAGE="cr.${REGION_ID}.nebius.cloud/${REGISTRY_PATH}/shipcheck:${TAG}"
"$NEBIUS" registry configure-helper >/dev/null

echo "== build + push $IMAGE"
docker build --platform linux/amd64 --build-arg PUBLIC_DEMO=1 -t "$IMAGE" .
docker push "$IMAGE"

echo "== endpoint"
SUBNET_ID="${SUBNET_ID:-$("$NEBIUS" vpc subnet list --format json | jq -r '.items[0].metadata.id')}"
"$NEBIUS" ai endpoint create \
  --name "$NAME" \
  --image "$IMAGE" \
  --platform "$PLATFORM" \
  --preset "$PRESET" \
  --container-port 8000/http \
  --auth none \
  --subnet-id "$SUBNET_ID"

ENDPOINT_ID=$("$NEBIUS" ai endpoint get-by-name --name "$NAME" --format jsonpath='{.metadata.id}')
echo "== waiting for $ENDPOINT_ID"
for _ in $(seq 1 60); do
  URL=$("$NEBIUS" ai endpoint get "$ENDPOINT_ID" --format json \
    | jq -r '.status.public_endpoints[]? | select(startswith("https://"))' | head -1)
  if [ -n "$URL" ] && curl -sf "$URL/health" >/dev/null; then
    echo "== live: $URL"
    curl -s -o /dev/null -w "   /api/demo -> %{http_code}\n" "$URL/api/demo"
    curl -s -o /dev/null -w "   POST /scan -> %{http_code} (403 expected: public demo)\n" -X POST "$URL/scan" \
      -H 'Content-Type: application/json' -d '{"diff":""}'
    exit 0
  fi
  sleep 10
done
echo "endpoint not healthy yet; check: $NEBIUS ai endpoint get $ENDPOINT_ID" >&2
exit 1
