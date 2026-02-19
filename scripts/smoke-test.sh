#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:9292}"
EMAIL="${EMAIL:-testuser@example.com}"
PASSWORD="${PASSWORD:-Password123}"
ORG_NAME="${ORG_NAME:-Acme Labs}"
PROJECT_NAME="${PROJECT_NAME:-Petstore}"
INVITE_EMAIL="${INVITE_EMAIL:-invited@example.com}"
POLL_ATTEMPTS="${POLL_ATTEMPTS:-20}"
POLL_DELAY="${POLL_DELAY:-3}"
SCAN_TOOL="${SCAN_TOOL:-vulnapi}"
TARGET_URL="${TARGET_URL:-http://host.docker.internal:2324}"
REPORT_PATH="${REPORT_PATH:-/tmp/wapiti.json}"
REPORT_PAYLOAD='{"$schema":"https://seguridadweb.local/schemas/vulnapi-report.json","version":"0.8.10","reports":[{"id":"smoke-1","name":"Smoke Test","issues":[{"id":"SMOKE-1","name":"Test issue","status":"failed","url":"https://example.com","cvss":{"score":5.0,"vector":""},"classifications":{}}]}]}'

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for this script."
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required for this script."
  exit 1
fi

request_json() {
  local method="$1"
  local url="$2"
  local data="${3:-}"
  shift 3
  local headers=("$@")
  local header_args=()
  local header
  for header in "${headers[@]}"; do
    header_args+=(-H "$header")
  done

  if [[ -n "$data" ]]; then
    curl -sS -X "$method" "$url" "${header_args[@]}" -H "Content-Type: application/json" -d "$data"
  else
    curl -sS -X "$method" "$url" "${header_args[@]}"
  fi
}

request_status() {
  local method="$1"
  local url="$2"
  local data="${3:-}"
  shift 3
  local headers=("$@")
  local header_args=()
  local header
  for header in "${headers[@]}"; do
    header_args+=(-H "$header")
  done
  if [[ -n "$data" ]]; then
    curl -sS -o /tmp/vi_body.json -w "%{http_code}" -X "$method" "$url" "${header_args[@]}" -H "Content-Type: application/json" -d "$data"
  else
    curl -sS -o /tmp/vi_body.json -w "%{http_code}" -X "$method" "$url" "${header_args[@]}"
  fi
}

show_json() {
  if [[ -s /tmp/vi_body.json ]]; then
    jq . /tmp/vi_body.json
  else
    echo "(empty body)"
  fi
}

echo "==> Login"
STATUS="$(request_status POST "$API_BASE/auth/login" "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")"
echo "Status: $STATUS"
show_json
TOKEN="$(jq -r .access_token /tmp/vi_body.json)"

if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  echo "Failed to get token."
  exit 1
fi

AUTH_HEADER=("Authorization: Bearer $TOKEN")

echo "==> List orgs"
STATUS="$(request_status GET "$API_BASE/orgs" "" "${AUTH_HEADER[@]}")"
echo "Status: $STATUS"
show_json
ORG_ID="$(jq -r '.[0].id // empty' /tmp/vi_body.json)"

if [[ -z "$ORG_ID" ]]; then
  echo "==> Create org"
  STATUS="$(request_status POST "$API_BASE/orgs" "{\"name\":\"$ORG_NAME\"}" "${AUTH_HEADER[@]}")"
  echo "Status: $STATUS"
  show_json
  ORG_ID="$(jq -r .id /tmp/vi_body.json)"
fi

if [[ -z "$ORG_ID" ]]; then
  echo "Failed to get org id."
  exit 1
fi

echo "==> Create project"
STATUS="$(request_status POST "$API_BASE/orgs/$ORG_ID/projects" "{\"name\":\"$PROJECT_NAME\"}" "${AUTH_HEADER[@]}")"
echo "Status: $STATUS"
show_json
PROJECT_ID="$(jq -r .id /tmp/vi_body.json)"

if [[ -z "$PROJECT_ID" || "$PROJECT_ID" == "null" ]]; then
  echo "==> List projects"
  STATUS="$(request_status GET "$API_BASE/orgs/$ORG_ID/projects" "" "${AUTH_HEADER[@]}")"
  echo "Status: $STATUS"
  show_json
  PROJECT_ID="$(jq -r '.[0].id // empty' /tmp/vi_body.json)"
fi

if [[ -z "$PROJECT_ID" ]]; then
  echo "Failed to get project id."
  exit 1
fi

echo "==> Create invite"
STATUS="$(request_status POST "$API_BASE/orgs/$ORG_ID/invites" "{\"email\":\"$INVITE_EMAIL\",\"role\":\"member\"}" "${AUTH_HEADER[@]}")"
echo "Status: $STATUS"
show_json

echo "==> Create scan"
RESOLVED_TARGET_URL="$TARGET_URL"
if [[ "$RESOLVED_TARGET_URL" == http://localhost:* ]]; then
  RESOLVED_TARGET_URL="http://host.docker.internal:${RESOLVED_TARGET_URL#http://localhost:}"
elif [[ "$RESOLVED_TARGET_URL" == http://127.0.0.1:* ]]; then
  RESOLVED_TARGET_URL="http://host.docker.internal:${RESOLVED_TARGET_URL#http://127.0.0.1:}"
fi

if [[ "$SCAN_TOOL" == "vulnapi" ]]; then
  SCAN_ARGS="{\"project_id\":$PROJECT_ID,\"report\":$REPORT_PAYLOAD}"
else
  SCAN_ARGS="{\"project_id\":$PROJECT_ID,\"target_url\":\"$RESOLVED_TARGET_URL\",\"report_path\":\"$REPORT_PATH\"}"
fi

STATUS="$(request_status POST "$API_BASE/scans/run" \
  "{\"tool\":\"$SCAN_TOOL\",\"args\":$SCAN_ARGS}" \
  "${AUTH_HEADER[@]}")"
echo "Status: $STATUS"
show_json
SCAN_ID="$(jq -r .id /tmp/vi_body.json)"

if [[ -z "$SCAN_ID" || "$SCAN_ID" == "null" ]]; then
  echo "Failed to create scan."
  exit 1
fi

echo "==> List scans"
STATUS="$(request_status GET "$API_BASE/scans?project_id=$PROJECT_ID" "" "${AUTH_HEADER[@]}")"
echo "Status: $STATUS"
show_json

echo "==> Poll scan status"
SCAN_STATUS="unknown"
for ((i=1; i<=POLL_ATTEMPTS; i++)); do
  STATUS="$(request_status GET "$API_BASE/scans?project_id=$PROJECT_ID" "" "${AUTH_HEADER[@]}")"
  SCAN_STATUS="$(jq -r --arg id "$SCAN_ID" '.[] | select(.id == ($id|tonumber)) | .status' /tmp/vi_body.json)"
  echo "Attempt $i/$POLL_ATTEMPTS: scan status = ${SCAN_STATUS:-unknown}"
  if [[ "$SCAN_STATUS" == "finished" || "$SCAN_STATUS" == "failed" ]]; then
    break
  fi
  sleep "$POLL_DELAY"
done

echo "==> Scan logs"
STATUS="$(request_status GET "$API_BASE/scans/$SCAN_ID/logs" "" "${AUTH_HEADER[@]}")"
echo "Status: $STATUS"
show_json

echo "==> Findings + assets"
STATUS="$(request_status GET "$API_BASE/findings?project_id=$PROJECT_ID" "" "${AUTH_HEADER[@]}")"
echo "Status: $STATUS"
FINDINGS_COUNT="$(jq 'length' /tmp/vi_body.json 2>/dev/null || echo 0)"
echo "Findings count: $FINDINGS_COUNT"
STATUS="$(request_status GET "$API_BASE/assets?project_id=$PROJECT_ID" "" "${AUTH_HEADER[@]}")"
echo "Status: $STATUS"
ASSETS_COUNT="$(jq 'length' /tmp/vi_body.json 2>/dev/null || echo 0)"
echo "Assets count: $ASSETS_COUNT"

echo "==> Export"
curl -sS "$API_BASE/findings/export?project_id=$PROJECT_ID&format=json" \
  -H "${AUTH_HEADER[@]}" >/tmp/findings.json
curl -sS "$API_BASE/findings/export?project_id=$PROJECT_ID&format=csv" \
  -H "${AUTH_HEADER[@]}" >/tmp/findings.csv
echo "Exported: /tmp/findings.json and /tmp/findings.csv"

echo "==> Audit logs"
STATUS="$(request_status GET "$API_BASE/audit-logs" "" "${AUTH_HEADER[@]}")"
echo "Status: $STATUS"
show_json

echo "Smoke test completed."
