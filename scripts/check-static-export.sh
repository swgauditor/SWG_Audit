#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

required_paths=(
  "index.html"
  "_next"
  "style.css"
  "swg.js"
  "images/logo.png"
  "data-theft/index.html"
  "data-theft/dns-tunneling/index.html"
  "data-theft/path-tunnel.php"
  "phishing/index.html"
  "phishing/credential-submit.php"
  "go/ms-login/index.php"
  "test-access.php"
  "test-files/malware/payloads/decode-eicar-docm.json"
  "test-files/malware/payloads/decode-eicar-docm-base32.json"
  "test-files/malware/payloads/decrypt-eicar-txt.json"
  "test-files/malware/payloads/decrypt-eicar-docm.json"
  "test-files/malware/chunk-attacks/straight-split/manifest.json"
  "test-files/malware/chunk-attacks/reverse-order/manifest.json"
  "test-files/malware/chunk-attacks/randomized-size/manifest.json"
  "test-files/malware/chunk-attacks/mixed-noise/manifest.json"
  "test-files/malware/chunk-attacks/parallel-burst/manifest.json"
)

for path in "${required_paths[@]}"; do
  [ -e "$path" ] || fail "missing required path: $path"
done

route_count="$(find . -type f -name index.html -not -path './.git/*' | wc -l | tr -d ' ')"
[ "$route_count" -ge 35 ] || fail "expected at least 35 rendered routes, found $route_count"

if find . -type f -name '*.mdx' -not -path './.git/*' | grep -q .; then
  find . -type f -name '*.mdx' -not -path './.git/*' >&2
  fail "main should contain the exported static site, not Mintlify .mdx source"
fi

[ ! -f docs.json ] || fail "docs.json belongs on the Mintlify backup branch, not static main"
if [ "${CHECK_DEPLOY_ARTIFACT:-0}" = "1" ]; then
  if find . -type f \( -name '*.bak-*' -o -name '*.mdx.bak-*' \) -not -path './.git/*' | grep -q .; then
    find . -type f \( -name '*.bak-*' -o -name '*.mdx.bak-*' \) -not -path './.git/*' >&2
    fail "backup files must not be included in the deployed static output"
  fi

  for dev_path in "Start Docs.bat" "Start Docs.command" "serve.js" "scripts/generate-pages.js" "scripts/selenium-smoke.mjs" "scripts/export-static.sh"; do
    [ ! -e "$dev_path" ] || fail "dev-only file should not be included in deployed static output: $dev_path"
  done
fi

grep -q 'name="generator" content="Mintlify"' index.html || fail "index.html does not look like the Mintlify export"
grep -q '/_next/static/' index.html || fail "index.html does not reference exported _next assets"

python3 - <<'PY'
import json
from pathlib import Path

for path in [
    "test-files/malware/payloads/decode-eicar-docm.json",
    "test-files/malware/payloads/decode-eicar-docm-base32.json",
    "test-files/malware/payloads/decrypt-eicar-txt.json",
    "test-files/malware/payloads/decrypt-eicar-docm.json",
]:
    data = json.loads(Path(path).read_text())
    required = {"mode", "filename", "mime", "payload"}
    missing = required - set(data)
    if missing:
        raise SystemExit(f"{path} missing keys: {sorted(missing)}")

for path in Path("test-files/malware/chunk-attacks").glob("*/manifest.json"):
    data = json.loads(path.read_text())
    if not data.get("chunks"):
        raise SystemExit(f"{path} has no chunks")
    for chunk in data["chunks"]:
        url = chunk.get("url", "")
        if not url.startswith("/test-files/"):
            raise SystemExit(f"{path} has invalid chunk url: {url}")
        if not Path(url.lstrip("/")).exists():
            raise SystemExit(f"{path} points to missing chunk: {url}")
PY

if command -v php >/dev/null 2>&1; then
  while IFS= read -r php_file; do
    php -l "$php_file" >/dev/null
  done < <(find . -type f -name '*.php' -not -path './.git/*' | sort)
fi

printf 'Static export check passed: %s routes\n' "$route_count"
