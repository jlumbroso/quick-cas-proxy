#!/usr/bin/env bash
set -euo pipefail

# quick-cas-proxy deploy script
# - No args: prepare ~/.quick-cas dirs & perms only
# - One arg: deploy to <CGI_BIN_DIR>/cas (copy files, set perms)
# - Flags:
#     -h | --help            : show help
#     --repair-wrappers      : overwrite validate.php and serviceValidate.php with known-good templates
#
# Examples:
#   ./deploy.sh
#   ./deploy.sh ~/public_html/cgi-bin
#   ./deploy.sh --repair-wrappers ~/public_html/cgi-bin

show_help() {
  cat <<'EOF'
Usage:
  deploy.sh [--repair-wrappers] [CGI_BIN_DIR]

Behavior:
  - With no arguments:
      Creates ~/.quick-cas/, ~/.quick-cas/tickets/, and ~/.quick-cas/server.log (secure perms).
  - With CGI_BIN_DIR (e.g., ~/public_html/cgi-bin):
      Also deploys repo files into CGI_BIN_DIR/cas/ and sets permissions,
      verifying wrapper files and warning if modified.

Flags:
  --repair-wrappers   Overwrite validate.php and serviceValidate.php in target with known-good templates.
  -h, --help          Show this help.

Notes:
  - Idempotent: safe to run repeatedly (e.g., after git pull).
  - Wrapper files are kept in the repo for legibility; this script can optionally repair them if needed.
EOF
}

REPAIR_WRAPPERS="no"
CGI_BIN_DIR=""

# -------- Parse args --------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) show_help; exit 0 ;;
    --repair-wrappers) REPAIR_WRAPPERS="yes"; shift ;;
    --) shift; break ;;
    -*)
      echo "ERROR: unknown flag: $1" >&2
      exit 2
      ;;
    *)
      if [[ -z "$CGI_BIN_DIR" ]]; then
        CGI_BIN_DIR="$1"
      else
        echo "ERROR: unexpected extra argument: $1" >&2
        exit 2
      fi
      shift || true
      ;;
  esac
done

# -------- Prepare ~/.quick-cas --------
HOME_DIR="${HOME:-$PWD}"
QC_BASE="${QUICKCAS_HOME:-${HOME_DIR}/.quick-cas}"
QC_TICKETS="${QC_BASE}/tickets"
QC_LOG="${QC_BASE}/server.log"

echo "==> Preparing Quick-CAS state at: ${QC_BASE}"
umask 077
mkdir -p "${QC_TICKETS}"
touch "${QC_LOG}" || true
chmod 700 "${QC_BASE}" "${QC_TICKETS}" || true
chmod 600 "${QC_LOG}" || true

if [[ -z "${CGI_BIN_DIR}" ]]; then
  echo "==> Local state prepared (no CGI deploy requested)."
  echo "    Base:    ${QC_BASE}"
  echo "    Tickets: ${QC_TICKETS}"
  echo "    Log:     ${QC_LOG}"
  exit 0
fi

# -------- Validate target path --------
if [[ ! -d "${CGI_BIN_DIR}" ]]; then
  echo "ERROR: not valid path: ${CGI_BIN_DIR}" >&2
  exit 2
fi

# -------- Destination dirs --------
CAS_DIR="${CGI_BIN_DIR%/}/cas"
CONF_DIR="${CAS_DIR}/quick-cas"
echo "==> Deploying to: ${CAS_DIR}"
mkdir -p "${CAS_DIR}" "${CONF_DIR}"

# -------- Helper: smart copy (idempotent) --------
smart_install() {
  # smart_install <src> <dest> <mode>
  local src="$1" dest="$2" mode="$3"
  if [[ -f "${src}" ]]; then
    if [[ -f "${dest}" ]] && cmp -s "${src}" "${dest}"; then
      :
    else
      cp -f "${src}" "${dest}"
    fi
    chmod "${mode}" "${dest}"
    echo "    + ${dest}"
  else
    echo "    - (skip) ${src} not found"
  fi
}

# -------- Copy files from repo --------
smart_install "quick-cas.php"        "${CAS_DIR}/quick-cas.php"         0644
smart_install "index.php"            "${CAS_DIR}/index.php"             0644
smart_install "validate.php"         "${CAS_DIR}/validate.php"          0644
smart_install "serviceValidate.php"  "${CAS_DIR}/serviceValidate.php"   0644
smart_install ".htaccess"            "${CAS_DIR}/.htaccess"             0644

# Config subdir (+ access_list)
chmod 711 "${CONF_DIR}" || true
smart_install "quick-cas/access_list" "${CONF_DIR}/access_list"         0644

# Directory perms
chmod 711 "${CAS_DIR}" || true

# -------- Wrapper templates (for optional repair) --------
WRAP_VALIDATE='<?php
// DO NOT EDIT: thin endpoint wrapper; logic lives in quick-cas.php
require_once __DIR__."/quick-cas.php";
run_validate();
'
WRAP_SERVICEVALIDATE='<?php
// DO NOT EDIT: thin endpoint wrapper; logic lives in quick-cas.php
require_once __DIR__."/quick-cas.php";
run_serviceValidate();
'

# -------- Verify wrappers --------
verify_wrapper() {
  # verify_wrapper <path> <expected_text_regex> <friendly_name>
  local path="$1" expect="$2" name="$3"
  if [[ ! -f "${path}" ]]; then
    echo "WARN: ${name} missing at ${path}"
    return 1
  fi
  if ! grep -q 'DO NOT EDIT: thin endpoint wrapper' "${path}"; then
    echo "WARN: ${name} at ${path} lacks sentinel comment (may be modified)."
  fi
  if ! grep -Eq "${expect}" "${path}"; then
    echo "WARN: ${name} at ${path} does not appear to call expected function."
    return 1
  fi
  return 0
}

echo "==> Verifying wrapper files"
VERIFY_FAIL=0
verify_wrapper "${CAS_DIR}/validate.php" 'run_validate\(' 'validate.php' || VERIFY_FAIL=1
verify_wrapper "${CAS_DIR}/serviceValidate.php" 'run_serviceValidate\(' 'serviceValidate.php' || VERIFY_FAIL=1

if [[ "${REPAIR_WRAPPERS}" == "yes" ]]; then
  echo "==> --repair-wrappers specified; writing known-good wrappers"
  printf "%s" "${WRAP_VALIDATE}"        > "${CAS_DIR}/validate.php"
  printf "%s" "${WRAP_SERVICEVALIDATE}" > "${CAS_DIR}/serviceValidate.php"
  chmod 0644 "${CAS_DIR}/validate.php" "${CAS_DIR}/serviceValidate.php"
  VERIFY_FAIL=0
fi

if [[ "${VERIFY_FAIL}" -ne 0 ]]; then
  echo "NOTE: To repair wrappers automatically, re-run with --repair-wrappers"
fi

# -------- Summary & tips --------
ME_USER="${USER:-$(id -un)}"
echo "==> Done."
echo
echo "Paths:"
echo "  Quick-CAS base: ${QC_BASE}"
echo "  Tickets dir:    ${QC_TICKETS}"
echo "  Log file:       ${QC_LOG}"
echo "  CAS dir:        ${CAS_DIR}"
echo "  Config dir:     ${CONF_DIR}"
if [[ -f "${CONF_DIR}/access_list" ]]; then
  echo "  Access list:    ${CONF_DIR}/access_list"
else
  echo "  Access list:    (none installed)"
fi
echo
echo "Test login (PennKey-gated):"
echo "  https://alliance.seas.upenn.edu/~${ME_USER}/cgi-bin/cas/index.php/login?service=https://example.com"
echo
echo "Test CAS 2.0 serviceValidate (should be PUBLIC, return XML error if missing params):"
echo "  https://alliance.seas.upenn.edu/~${ME_USER}/cgi-bin/cas/serviceValidate.php"
echo
echo "If serviceValidate returns a redirect to the IdP, it's still Shibboleth-gated — check .htaccess:"
echo "  <Files \"serviceValidate.php\">"
echo "    ShibRequestSetting requireSession 0"
echo "    Require all granted"
echo "  </Files>"
