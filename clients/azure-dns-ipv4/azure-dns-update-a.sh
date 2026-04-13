#!/bin/sh
# Update an Azure DNS A record to this host's public IPv4 address.
# Works from any Linux host behind NAT (discovers egress IP) or from pfSense.
# pfSense: no systemd/TPM cred helper — use root-only plaintext credential files; see README.md.
#
# Configuration is via command-line flags and/or environment variables.
# Flags override environment for the same setting. Nothing in this file is
# tenant-specific: use -z/-n/-d/-p (or env) instead of editing the script.
#
# Required (flags or env):
#   -z / --zone           Root DNS zone (e.g. example.com)  [AZURE_DNS_ZONE]
#   -n / --record         Relative A name (e.g. home, @)   [AZURE_DNS_RECORD_NAME]
#   -g / --resource-group Resource group of the zone       [AZURE_RESOURCE_GROUP]
#   -S / --subscription   Azure subscription ID            [AZURE_SUBSCRIPTION_ID]
#
# Service principal (one of):
#   A) -d + -p: credential directory and filename prefix:
#        $CREDENTIALS_DIRECTORY/${CREDENTIAL_FILE_PREFIX}-client-id
#        $CREDENTIALS_DIRECTORY/${CREDENTIAL_FILE_PREFIX}-client-secret
#        $CREDENTIALS_DIRECTORY/${CREDENTIAL_FILE_PREFIX}-tenant-id
#        Optional (if -g / -S not set): P-subscription-id, P-resource-group
#        Files may be plain one-line text OR systemd-creds encrypted (TPM); if
#        systemd-creds(1) is available, decrypt is tried first.
#   B) Env AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
#   C) Env AZURE_CLIENT_ID_FILE, AZURE_CLIENT_SECRET_FILE, AZURE_TENANT_ID_FILE (full paths)
#   D) Env AZURE_SUBSCRIPTION_ID_FILE, AZURE_RESOURCE_GROUP_FILE (full paths) when not using -g/-S
#
# Optional:
#   -t / --ttl            DNS TTL seconds [AZURE_DNS_TTL, default 300]
#   -D / --debug          Verbose diagnostics to stderr (set DEBUG_AZURE_DNS=1)
#   IPV4_DISCOVERY_URLS   space-separated URLs returning plain text IPv4
#
# Example:
#   ./azure-dns-update-a.sh -z example.com -n home -d /etc/mycerts -p my-dns-sp
#   (with my-dns-sp-subscription-id and my-dns-sp-resource-group next to the SP files), or:
#   ./azure-dns-update-a.sh -z example.com -n home -g my-rg -S <sub-id> -d /etc/mycerts -p my-dns-sp

set -eu

usage() {
  cat <<'EOF'
Usage: azure-dns-update-a.sh [options]

  -z, --zone ZONE           Azure DNS zone (root domain), e.g. example.com
  -n, --record NAME         Relative A record name (subdomain), or @ for apex
  -g, --resource-group RG   Resource group containing the DNS zone
  -S, --subscription ID    Azure subscription ID

  -d, --credentials-dir DIR Directory with SP credential files
  -p, --credential-prefix P File basename prefix (reads P-client-id, P-client-secret, P-tenant-id)
                            Optional: P-subscription-id, P-resource-group if -S/-g omitted

  -t, --ttl SECONDS         A record TTL (default 300)
  -D, --debug               Extra diagnostics (also: DEBUG_AZURE_DNS=1)
  -h, --help                Show this help

Environment (same names as above; flags take precedence):
  AZURE_DNS_ZONE, AZURE_DNS_RECORD_NAME, AZURE_RESOURCE_GROUP, AZURE_SUBSCRIPTION_ID
  CREDENTIALS_DIRECTORY + CREDENTIAL_FILE_PREFIX
  or AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
  or AZURE_CLIENT_ID_FILE, AZURE_CLIENT_SECRET_FILE, AZURE_TENANT_ID_FILE
  Optional files: AZURE_SUBSCRIPTION_ID_FILE, AZURE_RESOURCE_GROUP_FILE
  DEBUG_AZURE_DNS=1         Same as -D (verbose stderr; secrets stay redacted)
EOF
}

# Defaults (empty = must be supplied)
: "${AZURE_DNS_ZONE:=}"
: "${AZURE_DNS_RECORD_NAME:=}"
: "${AZURE_RESOURCE_GROUP:=}"
: "${AZURE_SUBSCRIPTION_ID:=}"
: "${CREDENTIALS_DIRECTORY:=}"
: "${CREDENTIAL_FILE_PREFIX:=}"
: "${AZURE_DNS_TTL:=300}"
: "${DEBUG_AZURE_DNS:=}"

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -D|--debug) DEBUG_AZURE_DNS=1; shift ;;
    -z)
      [ $# -ge 2 ] || {
        echo "-z requires a zone" >&2
        exit 1
      }
      AZURE_DNS_ZONE=$2
      shift 2
      ;;
    -n)
      [ $# -ge 2 ] || {
        echo "-n requires a record name" >&2
        exit 1
      }
      AZURE_DNS_RECORD_NAME=$2
      shift 2
      ;;
    -g)
      [ $# -ge 2 ] || {
        echo "-g requires a resource group" >&2
        exit 1
      }
      AZURE_RESOURCE_GROUP=$2
      shift 2
      ;;
    -S)
      [ $# -ge 2 ] || {
        echo "-S requires a subscription id" >&2
        exit 1
      }
      AZURE_SUBSCRIPTION_ID=$2
      shift 2
      ;;
    -d)
      [ $# -ge 2 ] || {
        echo "-d requires a directory" >&2
        exit 1
      }
      CREDENTIALS_DIRECTORY=$2
      shift 2
      ;;
    -p)
      [ $# -ge 2 ] || {
        echo "-p requires a credential file prefix" >&2
        exit 1
      }
      CREDENTIAL_FILE_PREFIX=$2
      shift 2
      ;;
    -t)
      [ $# -ge 2 ] || {
        echo "-t requires a ttl" >&2
        exit 1
      }
      AZURE_DNS_TTL=$2
      shift 2
      ;;
    --zone=*) AZURE_DNS_ZONE="${1#*=}"; shift ;;
    --record=*) AZURE_DNS_RECORD_NAME="${1#*=}"; shift ;;
    --resource-group=*) AZURE_RESOURCE_GROUP="${1#*=}"; shift ;;
    --subscription=*) AZURE_SUBSCRIPTION_ID="${1#*=}"; shift ;;
    --credentials-dir=*) CREDENTIALS_DIRECTORY="${1#*=}"; shift ;;
    --credential-prefix=*) CREDENTIAL_FILE_PREFIX="${1#*=}"; shift ;;
    --ttl=*) AZURE_DNS_TTL="${1#*=}"; shift ;;
    --debug) DEBUG_AZURE_DNS=1; shift ;;
    --zone|--record|--resource-group|--subscription|--credentials-dir|--credential-prefix|--ttl)
      _val=${2-}
      [ -n "$_val" ] || {
        echo "Option $1 requires a value" >&2
        exit 1
      }
      case "$1" in
        --zone) AZURE_DNS_ZONE=$_val ;;
        --record) AZURE_DNS_RECORD_NAME=$_val ;;
        --resource-group) AZURE_RESOURCE_GROUP=$_val ;;
        --subscription) AZURE_SUBSCRIPTION_ID=$_val ;;
        --credentials-dir) CREDENTIALS_DIRECTORY=$_val ;;
        --credential-prefix) CREDENTIAL_FILE_PREFIX=$_val ;;
        --ttl) AZURE_DNS_TTL=$_val ;;
      esac
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# Plain one-line files OR systemd-creds(1) encrypted blobs (same as on-disk for
# LoadCredentialEncrypted). Without decrypt, ciphertext is fed to curl and URLs break.
read_secret_line() {
  _path=$1
  if [ ! -r "$_path" ]; then
    echo "read_secret_line: not readable: $_path" >&2
    return 1
  fi
  _tmp=$(mktemp) || return 1
  if command -v systemd-creds >/dev/null 2>&1 &&
    systemd-creds decrypt "$_path" >"$_tmp" 2>/dev/null &&
    [ -s "$_tmp" ]; then
    tr -d '\r\n\t ' <"$_tmp"
    rm -f "$_tmp"
    return 0
  fi
  rm -f "$_tmp"
  tr -d '\r\n\t ' <"$_path"
}

load_sp_from_files() {
  _id_file=$1
  _sec_file=$2
  _ten_file=$3
  AZURE_CLIENT_ID=$(read_secret_line "$_id_file") || exit 1
  AZURE_CLIENT_SECRET=$(read_secret_line "$_sec_file") || exit 1
  AZURE_TENANT_ID=$(read_secret_line "$_ten_file") || exit 1
}

if [ -n "${AZURE_CLIENT_ID_FILE:-}" ] || [ -n "${AZURE_CLIENT_SECRET_FILE:-}" ] || [ -n "${AZURE_TENANT_ID_FILE:-}" ]; then
  for v in AZURE_CLIENT_ID_FILE AZURE_CLIENT_SECRET_FILE AZURE_TENANT_ID_FILE; do
    eval "_x=\${$v:-}"
    if [ -z "$_x" ]; then
      echo "When using credential files, set all of: AZURE_CLIENT_ID_FILE, AZURE_CLIENT_SECRET_FILE, AZURE_TENANT_ID_FILE" >&2
      exit 1
    fi
  done
  load_sp_from_files "$AZURE_CLIENT_ID_FILE" "$AZURE_CLIENT_SECRET_FILE" "$AZURE_TENANT_ID_FILE"
elif [ -n "${CREDENTIALS_DIRECTORY:-}" ]; then
  if [ -z "${CREDENTIAL_FILE_PREFIX:-}" ]; then
    echo "With -d / CREDENTIALS_DIRECTORY, you must set -p / CREDENTIAL_FILE_PREFIX (e.g. my-dns-sp)." >&2
    exit 1
  fi
  _dir=$CREDENTIALS_DIRECTORY
  _pfx=$CREDENTIAL_FILE_PREFIX
  load_sp_from_files "$_dir/${_pfx}-client-id" "$_dir/${_pfx}-client-secret" "$_dir/${_pfx}-tenant-id"
fi

# Subscription / resource group: optional one-line files (same dir+prefix as SP), or *_FILE env.
if [ -z "${AZURE_SUBSCRIPTION_ID:-}" ] && [ -n "${AZURE_SUBSCRIPTION_ID_FILE:-}" ]; then
  AZURE_SUBSCRIPTION_ID=$(read_secret_line "$AZURE_SUBSCRIPTION_ID_FILE") || exit 1
fi
if [ -z "${AZURE_RESOURCE_GROUP:-}" ] && [ -n "${AZURE_RESOURCE_GROUP_FILE:-}" ]; then
  AZURE_RESOURCE_GROUP=$(read_secret_line "$AZURE_RESOURCE_GROUP_FILE") || exit 1
fi
if [ -n "${CREDENTIALS_DIRECTORY:-}" ] && [ -n "${CREDENTIAL_FILE_PREFIX:-}" ]; then
  _dir=$CREDENTIALS_DIRECTORY
  _pfx=$CREDENTIAL_FILE_PREFIX
  if [ -z "${AZURE_SUBSCRIPTION_ID:-}" ] && [ -f "$_dir/${_pfx}-subscription-id" ]; then
    AZURE_SUBSCRIPTION_ID=$(read_secret_line "$_dir/${_pfx}-subscription-id") || exit 1
  fi
  if [ -z "${AZURE_RESOURCE_GROUP:-}" ] && [ -f "$_dir/${_pfx}-resource-group" ]; then
    AZURE_RESOURCE_GROUP=$(read_secret_line "$_dir/${_pfx}-resource-group") || exit 1
  fi
fi

looks_like_uuid() {
  printf '%s' "$1" | grep -E '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' >/dev/null 2>&1
}

rg_name_ok() {
  # Azure RG names: 1–90 chars, alnum, underscore, hyphen, period, parens; keep a loose check.
  _rg=$1
  [ "${#_rg}" -ge 1 ] && [ "${#_rg}" -le 90 ] || return 1
  printf '%s' "$_rg" | grep -E '^[A-Za-z0-9._()\-]+$' >/dev/null 2>&1
}

if ! looks_like_uuid "$AZURE_TENANT_ID"; then
  echo "AZURE_TENANT_ID does not look like a UUID after reading credential files." >&2
  echo "If these are systemd-creds encrypted blobs, ensure 'systemd-creds decrypt <file>' works as this user (TPM), or run from systemd with LoadCredentialEncrypted." >&2
  exit 1
fi
if ! looks_like_uuid "$AZURE_CLIENT_ID"; then
  echo "AZURE_CLIENT_ID does not look like a UUID — check credential files or decrypt." >&2
  exit 1
fi
if ! looks_like_uuid "$AZURE_SUBSCRIPTION_ID"; then
  echo "AZURE_SUBSCRIPTION_ID does not look like a UUID — use -S, PREFIX-subscription-id under -d/-p, or AZURE_SUBSCRIPTION_ID_FILE." >&2
  exit 1
fi
if ! rg_name_ok "$AZURE_RESOURCE_GROUP"; then
  echo "AZURE_RESOURCE_GROUP does not look valid — use -g, PREFIX-resource-group under -d/-p, or AZURE_RESOURCE_GROUP_FILE." >&2
  exit 1
fi

for v in AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET AZURE_SUBSCRIPTION_ID \
         AZURE_RESOURCE_GROUP AZURE_DNS_ZONE AZURE_DNS_RECORD_NAME; do
  eval "_x=\${$v:-}"
  if [ -z "$_x" ]; then
    echo "Missing required value: $v (use flag, env, or credential files — see -h)" >&2
    exit 1
  fi
done

command -v curl >/dev/null 2>&1 || {
  echo "curl is required" >&2
  exit 1
}

azure_dns_debug() {
  [ -n "${DEBUG_AZURE_DNS:-}" ] || return 0
  printf '[azure-dns] %s\n' "$*" >&2
}

# UUID-style id: show first 8 and last 4 hex chars only (no full id on stderr).
_obfuscate_uuid_like() {
  _v=$1
  _len=${#_v}
  if [ "$_len" -ge 13 ]; then
    _suf=$(printf '%s' "$_v" | sed 's/.*\(....\)$/\1/')
    printf '%.8s…%s' "$_v" "$_suf"
  else
    printf '(len=%s)' "$_len"
  fi
}

# JWT or opaque bearer: prefix + length only.
_obfuscate_bearer() {
  _t=$1
  _len=${#_t}
  _pfx=$(printf '%s' "$_t" | cut -c1-16)
  printf '%s… (length=%s)' "$_pfx" "$_len"
}

# Redact obvious token fields then truncate for safe logging.
_redact_aad_json_file() {
  _f=$1
  _max=$2
  sed -e 's/"access_token":"[^"]*"/"access_token":"<REDACTED>"/g' \
      -e 's/"refresh_token":"[^"]*"/"refresh_token":"<REDACTED>"/g' \
      -e 's/"client_secret":"[^"]*"/"client_secret":"<REDACTED>"/g' \
      "$_f" 2>/dev/null | tr '\n' ' ' | head -c "$_max"
}

_report_token_failure() {
  _http=$1
  _respfile=$2
  _url=$3
  echo "Azure AD token request failed (HTTP ${_http})." >&2
  echo "Request (no secrets): POST ${_url}" >&2
  echo "Context: tenant_id=$(_obfuscate_uuid_like "$AZURE_TENANT_ID") client_id=$(_obfuscate_uuid_like "$AZURE_CLIENT_ID") client_secret_length=${#AZURE_CLIENT_SECRET} scope=https://management.azure.com/.default" >&2
  _snap=$(_redact_aad_json_file "$_respfile" 900)
  if [ -n "$_snap" ]; then
    echo "AAD JSON (truncated/redacted): ${_snap}" >&2
  else
    echo "AAD response body was empty or unreadable." >&2
  fi
  _err=$(sed -n 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$_respfile" 2>/dev/null | head -1)
  if [ -n "$_err" ]; then
    echo "error field: ${_err}" >&2
  fi
  echo "Typical causes of 401: wrong tenant in URL, wrong client_id, expired or incorrect client_secret, or clock skew on this host." >&2
  azure_dns_debug "Full token URL: $_url"
  azure_dns_debug "AAD body (longer redacted): $(_redact_aad_json_file "$_respfile" 2400)"
}

arm_get_token() {
  _url="https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token"
  azure_dns_debug "Requesting token (client_secret length=${#AZURE_CLIENT_SECRET})"
  _resp=$(mktemp) || return 1
  _curl_ec=0
  _http=$(curl -sS -g -o "$_resp" -w '%{http_code}' -X POST "$_url" \
    --data-urlencode grant_type=client_credentials \
    --data-urlencode client_id="$AZURE_CLIENT_ID" \
    --data-urlencode client_secret="$AZURE_CLIENT_SECRET" \
    --data-urlencode scope="https://management.azure.com/.default") || _curl_ec=$?
  if [ "$_curl_ec" != 0 ]; then
    echo "curl failed (exit $_curl_ec) contacting login.microsoftonline.com." >&2
    _report_token_failure "${_http:-?}" "$_resp" "$_url"
    rm -f "$_resp"
    return 1
  fi
  if [ "$_http" != "200" ]; then
    _report_token_failure "$_http" "$_resp" "$_url"
    rm -f "$_resp"
    return 1
  fi
  _tok=$(grep -o '"access_token":"[^"]*' < "$_resp" | cut -d'"' -f4)
  if [ -z "$_tok" ]; then
    echo "Token HTTP 200 but no access_token in JSON (unexpected response)." >&2
    _report_token_failure "200" "$_resp" "$_url"
    rm -f "$_resp"
    return 1
  fi
  rm -f "$_resp"
  azure_dns_debug "Got bearer token $(_obfuscate_bearer "$_tok")"
  printf '%s' "$_tok"
}

is_ipv4() {
  printf '%s' "$1" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' >/dev/null 2>&1
}

discover_public_ipv4() {
  _default_urls="https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip"
  _urls="${IPV4_DISCOVERY_URLS:-$_default_urls}"
  for u in $_urls; do
    _ip=$(curl -fsS -4 --max-time 12 "$u" 2>/dev/null | tr -d '\r\n\t ')
    if is_ipv4 "$_ip"; then
      printf '%s' "$_ip"
      return 0
    fi
  done
  return 1
}

echo "Discovering public IPv4..."
PUBIP=$(discover_public_ipv4) || {
  echo "Could not discover a public IPv4 address from discovery URLs" >&2
  exit 1
}
echo "Using public IPv4: $PUBIP"

echo "Fetching Azure management token..."
MGMT_TOKEN=$(arm_get_token) || exit 1
if [ -z "$MGMT_TOKEN" ]; then
  echo "Failed to obtain management.azure.com access token" >&2
  exit 1
fi

TTL_RAW="$AZURE_DNS_TTL"
TTL=$(printf '%s' "$TTL_RAW" | tr -cd '0123456789')
[ -n "$TTL" ] || TTL=300

RECORD="$AZURE_DNS_RECORD_NAME"
case "$RECORD" in
  @) RECORD_AT="@" ;;
  *) RECORD_AT="$RECORD" ;;
esac

RECORD_ENC=$(printf '%s' "$RECORD_AT" | sed 's/@/%40/g')

ARM_HOST="https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${AZURE_RESOURCE_GROUP}/providers/Microsoft.Network/dnsZones/${AZURE_DNS_ZONE}/A/${RECORD_ENC}"
ARM_URL="${ARM_HOST}?api-version=2018-05-01"

# Match Microsoft DNS record-set PUT schema (2018-05-01): properties.TTL is uppercase;
# top-level "location" is not used in the official A record example and can cause 400.
BODY=$(printf '{"properties":{"TTL":%s,"ARecords":[{"ipv4Address":"%s"}]}}' "$TTL" "$PUBIP")

RESP_FILE=$(mktemp)
trap 'rm -f "$RESP_FILE"' EXIT INT TERM

echo "Upserting A record ${RECORD}.${AZURE_DNS_ZONE} -> ${PUBIP} (TTL ${TTL})..."
azure_dns_debug "PUT DNS (subscription $(_obfuscate_uuid_like "$AZURE_SUBSCRIPTION_ID") rg=${AZURE_RESOURCE_GROUP} zone=${AZURE_DNS_ZONE} record=${RECORD})"
azure_dns_debug "Authorization: Bearer $(_obfuscate_bearer "$MGMT_TOKEN")"
HTTP_CODE=$(curl -sS -o "$RESP_FILE" -w '%{http_code}' -X PUT "$ARM_URL" \
  -H "Authorization: Bearer ${MGMT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$BODY") || exit 1

if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "201" ]; then
  echo "Azure DNS PUT failed with HTTP $HTTP_CODE" >&2
  _arm_snap=$(tr '\n' ' ' <"$RESP_FILE" | head -c 1200)
  echo "ARM body (truncated): ${_arm_snap}" >&2
  azure_dns_debug "Full PUT URL: $ARM_URL"
  exit 1
fi
echo "DNS A record updated successfully."
