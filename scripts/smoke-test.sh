#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:3333}"
BASE_URL="${BASE_URL%/}"

curl_args=(-L -sS --max-time 20)
if [ -n "${SMOKE_RESOLVE:-}" ]; then
  curl_args+=(--resolve "$SMOKE_RESOLVE")
fi
if [ "${SMOKE_INSECURE:-0}" = "1" ]; then
  curl_args+=(-k)
fi

PATHS=(
  "/"
  "/malware"
  "/phishing"
  "/data-theft"
  "/cyberslacking"
  "/test-files/malware/payloads/decode-eicar-docm.json"
  "/test-files/malware/payloads/decode-eicar-docm-base32.json"
  "/test-files/malware/payloads/decrypt-eicar-txt.json"
  "/test-files/malware/payloads/decrypt-eicar-docm.json"
  "/test-files/malware/chunk-attacks/straight-split/manifest.json"
  "/test-files/malware/chunk-attacks/reverse-order/manifest.json"
  "/test-files/malware/chunk-attacks/randomized-size/manifest.json"
  "/test-files/malware/chunk-attacks/mixed-noise/manifest.json"
  "/test-files/malware/chunk-attacks/parallel-burst/manifest.json"
)

for path in "${PATHS[@]}"; do
  url="${BASE_URL}${path}"
  body="$(mktemp)"
  code="$(curl "${curl_args[@]}" -o "$body" -w '%{http_code}' "$url")"
  if [[ ! "$code" =~ ^(2|3)[0-9][0-9]$ ]]; then
    echo "Smoke test failed: $url returned HTTP $code"
    sed -n '1,40p' "$body" || true
    rm -f "$body"
    exit 1
  fi
  if [[ "$path" == *.json ]]; then
    if ! python3 -m json.tool "$body" >/dev/null; then
      echo "Smoke test failed: $url did not return valid JSON"
      sed -n '1,40p' "$body" || true
      rm -f "$body"
      exit 1
    fi
  elif ! grep -qi 'SWG Audit\|SWGAudit\|Security Web Gateway' "$body"; then
    echo "Smoke test failed: $url did not look like a SWGAudit page"
    sed -n '1,40p' "$body" || true
    rm -f "$body"
    exit 1
  fi
  rm -f "$body"
  echo "OK $code $path"
done
