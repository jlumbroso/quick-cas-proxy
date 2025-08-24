#!/usr/bin/env bash
set -euo pipefail

BASE_DEFAULT="https://alliance.seas.upenn.edu/~${USER}/cgi-bin/cas"
BASE="${1:-$BASE_DEFAULT}"

SV="${BASE%/}/serviceValidate.php"
VL="${BASE%/}/validate.php"
LG="${BASE%/}/index.php/login"

pass() { printf "✅ %s\n" "$1"; }
fail() { printf "❌ %s\n" "$1"; exit 1; }

echo "Testing base: $BASE"

# 1) serviceValidate is public + XML
hdrs="$(curl -sS -I "$SV")" || true
code="$(printf "%s" "$hdrs" | awk 'toupper($1)=="HTTP/1.1"{print $2; exit}')"
ctype="$(printf "%s" "$hdrs" | awk -F': ' 'tolower($1)=="content-type"{print tolower($2)}' | tr -d '\r')"
if [[ "$code" == "200" && "$ctype" == *"xml"* ]]; then
  pass "serviceValidate HEAD -> 200 + XML"
else
  echo "$hdrs"
  fail "serviceValidate not public or not XML (code=$code, content-type=$ctype)"
fi

# 2) serviceValidate with no params -> INVALID_REQUEST XML
body="$(curl -sS "$SV")" || true
if echo "$body" | grep -q "<cas:serviceResponse" && echo "$body" | grep -q "INVALID_REQUEST"; then
  pass "serviceValidate (no params) -> INVALID_REQUEST XML"
else
  echo "$body"
  fail "serviceValidate (no params) did not return expected XML"
fi

# 3) validate with no params -> 'no'
txt="$(curl -sS "$VL")" || true
if [[ "$(echo -n "$txt" | tr -d '\r')" == "no" ]]; then
  pass "validate (no params) -> 'no'"
else
  echo "$txt"
  fail "validate (no params) did not return 'no'"
fi

# 4) login without service -> 400
hdrs2="$(curl -sS -I "$LG" || true)"
code2="$(printf "%s" "$hdrs2" | awk 'toupper($1)=="HTTP/1.1"{print $2; exit}')"
if [[ "$code2" == "400" ]]; then
  pass "login (no service) -> 400"
else
  echo "$hdrs2"
  fail "login (no service) did not return 400 (got $code2)"
fi

echo "All tests passed."
