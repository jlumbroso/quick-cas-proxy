#!/bin/bash

# quick-cas-proxy deployer (index.php version)
# Usage:
#   ./deploy.sh ~/public_html/cgi-bin

CGI_BIN_DIR="$1"
if [[ "$1" == "-h" || "$1" == "--help" || -z "$1" ]]; then
  echo "Usage: ./deploy.sh /path/to/cgi-bin"
  echo "Deploys quick-cas.php, index.php, .htaccess into cgi-bin/cas/"
  exit 1
fi

CAS_DIR="$CGI_BIN_DIR/cas"
mkdir -p "$CAS_DIR"

echo "Deploying to: $CAS_DIR"

install -m 755 -C quick-cas.php "$CAS_DIR/quick-cas.php"
install -m 755 -C index.php "$CAS_DIR/index.php"
install -m 644 -C .htaccess "$CAS_DIR/.htaccess"

chmod 711 "$CAS_DIR"

echo "Done."
echo "Test with:"
echo "  https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas/index.php/login?service=https://example.com"
