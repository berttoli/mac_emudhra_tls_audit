#!/bin/bash
# macOS eMudhra TLS trust assessment, 2026-10-22.
# Read-only. Does not install packages, modify trust stores, or use sudo.
# Compatible with the Bash 3.2 shipped with macOS.

set -u
export LC_ALL=C
MODE=offline
case "${1:-}" in
  ''|--offline) MODE=offline ;;
  --online) MODE=online ;;
  --probe-only) MODE=probe-only ;;
  -h|--help)
    printf 'Usage: bash %s [--offline|--online|--probe-only]\n' "$0"
    printf '%s\n' 'Offline mode checks CA files and TLS configuration. Online mode also tests affected TLS chains.'
    printf '%s\n' 'Probe-only tests curl and Python TLS without inspecting local CA files.'
    exit 0 ;;
  *) printf 'Unknown flag: %s\n' "$1" >&2; exit 64 ;;
esac

PASS=0
EXPOSED=0
BLOCKED=0
UNKNOWN=0
WARN=0
heading() { printf '\n=== %s ===\n' "$1"; }
info() { printf '[INFO] %s\n' "$1"; }
warn() { printf '[WARN] %s\n' "$1"; WARN=$((WARN + 1)); }
unknown() { printf '[UNKNOWN] %s\n' "$1"; UNKNOWN=$((UNKNOWN + 1)); }
exposed() { printf '[EXPOSED] %s\n' "$1"; EXPOSED=$((EXPOSED + 1)); }
blocked() { printf '[BLOCKED] %s\n' "$1"; BLOCKED=$((BLOCKED + 1)); }

heading 'Host and tooling'
info "Audit UTC: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
info "Mode: $MODE"
if command -v sw_vers >/dev/null 2>&1; then
  info "macOS: $(sw_vers -productVersion 2>/dev/null)"
else
  info 'Non-macOS environment (testing only).'
fi
for name in curl git python3 pip3 uv openssl brew; do
  p=$(command -v "$name" 2>/dev/null || true)
  if [ -n "$p" ]; then info "$name: $p"; fi
done

# Certificate-file checks are indicators, not equivalent to live verification.
if [ "$MODE" != probe-only ]; then
  heading 'Trust-store inventory'
  for bundle in /etc/ssl/cert.pem \
      /opt/homebrew/etc/ca-certificates/cert.pem \
      /usr/local/etc/ca-certificates/cert.pem \
      /opt/homebrew/etc/openssl@3/cert.pem \
      /usr/local/etc/openssl@3/cert.pem; do
    if [ -r "$bundle" ]; then
      count=$(grep -c '^-----BEGIN CERTIFICATE-----' "$bundle" 2>/dev/null || true)
      info "$bundle: ${count:-0} PEM certificates"
      # Apple's PEM file has these '=== /.../CN=...' separators.
      # This deliberately does not infer actual TLS acceptance from a name.
      roots=$(awk '/^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/ {print; n++} END {if (!n) print "none"}' "$bundle" 2>/dev/null)
      case "$roots" in
        none) info 'No affected-root section headings detected (not proof of safety).' ;;
        *) warn "Affected-root headings present in $bundle; verify client behavior with --online."
           printf '%s\n' "$roots" ;;
      esac
    fi
  done
  heading 'TLS configuration review'
  for key in SSL_CERT_FILE CURL_CA_BUNDLE REQUESTS_CA_BUNDLE PIP_CERT GIT_SSL_CAINFO NODE_EXTRA_CA_CERTS; do
    # Bash 3.2-compatible environment variable lookup.
    value=${!key-}
    if [ -n "$value" ]; then info "$key is configured; inspect its trust bundle locally."; fi
  done
  for key in GIT_SSL_NO_VERIFY HTTPS_PROXY HTTP_PROXY ALL_PROXY https_proxy http_proxy all_proxy; do
    value=${!key-}
    if [ -n "$value" ]; then
      if [ "$key" = GIT_SSL_NO_VERIFY ]; then warn "$key is set ($value). Check that TLS verification is not disabled.";
      else info "$key is configured (not inherently suspicious)."; fi
    fi
  done
  if command -v git >/dev/null 2>&1; then
    v=$(git config --global --get http.sslVerify 2>/dev/null || true)
    case "$v" in
      false|FALSE|0|no|NO) warn 'Git global http.sslVerify is disabled.' ;;
      '') info 'No global Git sslVerify override found.' ;;
      *) info "Git global sslVerify: $v" ;;
    esac
  fi
  if command -v brew >/dev/null 2>&1; then
    info "Homebrew CA package: $(brew list --versions ca-certificates 2>/dev/null || printf 'not installed')"
    info "Homebrew curl package: $(brew list --versions curl 2>/dev/null || printf 'not installed')"
  fi
  if command -v python3 >/dev/null 2>&1; then
    PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import ssl, sys
print('[INFO] Python:', sys.version.split()[0])
print('[INFO] Python TLS:', ssl.OPENSSL_VERSION)
print('[INFO] Python default paths:', ssl.get_default_verify_paths())
try:
    import certifi
    print('[INFO] Python certifi:', getattr(certifi, '__version__', 'unknown'), 'bundle:', certifi.where())
except ImportError:
    print('[INFO] Python certifi: not importable from this interpreter')
try:
    import pip
    print('[INFO] Python pip:', pip.__version__)
except ImportError:
    pass
PY
  fi
fi

# Test only known, publicly provided eMudhra incident endpoints.
# --noproxy '*' ensures this tests the direct TLS path; proxy-required networks
# are reported UNKNOWN, not SAFE. -q avoids ~/.curlrc overrides.
probe_curl() {
  local bin="$1" host="$2" label="$3" code rc
  code=$("$bin" -q --noproxy '*' --silent --show-error \
     --connect-timeout 6 --max-time 12 --output /dev/null \
     --write-out '%{http_code}' "https://$host/" 2>/dev/null)
  rc=$?
  if [ "$rc" -eq 0 ]; then
    exposed "$bin accepted $label (HTTP ${code:-unknown})."
  elif [ "$rc" -eq 60 ] || [ "$rc" -eq 51 ]; then
    blocked "$bin rejected $label (curl exit $rc)."
  else
    unknown "$bin $label: inconclusive (curl exit $rc; HTTP ${code:-000})."
  fi
}
