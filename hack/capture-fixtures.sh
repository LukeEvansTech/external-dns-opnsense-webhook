#!/usr/bin/env bash
# capture-fixtures.sh: fetch read-only responses from a real OPNsense firewall
# into internal/opnsense/testdata/ for the unit tests to replay.
#
# No mutating API operation is ever called. searchHostOverride is a POST so
# the sort and paging path matches production; it only reads.
#
# Required env: OPNSENSE_HOST, OPNSENSE_API_KEY, OPNSENSE_API_SECRET
# Optional:     OPNSENSE_SKIP_TLS_VERIFY=1
#
# The credentials are written to a private curl config file rather than passed
# as --user, so they never appear in the process table.
#
# REVIEW AND SANITISE every file before committing: hostnames -> example.com,
# addresses -> TEST-NET (192.0.2.0/24), uuids -> synthetic, descriptions cleared.

set -euo pipefail
: "${OPNSENSE_HOST:?}" "${OPNSENSE_API_KEY:?}" "${OPNSENSE_API_SECRET:?}"
OUT="$(cd "$(dirname "$0")/.." && pwd)/internal/opnsense/testdata"
mkdir -p "$OUT"

umask 077
CONF="$(mktemp)"
BODY="$(mktemp)"
trap 'rm -f "$CONF" "$BODY"' EXIT
# printf is a shell builtin: the secret is never an argument to another process.
printf 'user = "%s:%s"\n' "${OPNSENSE_API_KEY}" "${OPNSENSE_API_SECRET}" >"$CONF"

CURL=(curl --silent --show-error --fail --config "$CONF" --header "Accept: application/json")
if [[ "${OPNSENSE_SKIP_TLS_VERIFY:-0}" == "1" ]]; then
    CURL+=(--insecure)
fi

post() { "${CURL[@]}" --header "Content-Type: application/json" --data "$2" "${OPNSENSE_HOST}$1"; }
get() { "${CURL[@]}" "${OPNSENSE_HOST}$1"; }

post /api/unbound/settings/searchHostOverride \
    '{"current":1,"rowCount":3,"searchPhrase":"","sort":{"domain":"asc","hostname":"asc","rr":"asc","server":"asc"}}' \
    >"$OUT/search_page1.raw.json"
get /api/unbound/service/status >"$OUT/service_status.raw.json"
# Written whole and then truncated: piping curl into head closes the pipe
# early, which under `set -o pipefail` would fail the script.
post /api/unbound/diagnostics/listlocaldata '{}' >"$BODY"
head -c 4000 "$BODY" >"$OUT/listlocaldata.raw.json"
UUID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["rows"][0]["uuid"])' "$OUT/search_page1.raw.json")
get "/api/unbound/settings/getHostOverride/${UUID}" >"$OUT/get_host.raw.json"

echo "Captured to $OUT (*.raw.json). Sanitise, rename to drop .raw, and delete the raw files:"
echo "  - hostnames/domains -> example.com names; addresses -> 192.0.2.x; uuids -> 1111..., 2222...; descriptions cleared"
echo "  - keep the field set and the isAlias/_children shape exactly"
