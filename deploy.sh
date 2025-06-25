#!/bin/bash

# quick-cas-proxy deployment script
# Usage:
#   ./deploy.sh /path/to/cgi-bin        # deploys into cgi-bin/cas/
#   ./deploy.sh                         # assumes already inside cgi-bin/cas/, just re-applies permissions
#   ./deploy.sh -h                      # help

show_help() {
cat << EOF
Usage:
  ./deploy.sh /path/to/cgi-bin     Deploy quick-cas-proxy to CGI bin
  ./deploy.sh                      Re-apply permissions and fix symlinks in current folder
  ./deploy.sh -h                   Show this help message

Deployment will:
  - Copy quick-cas.php into [cgi-bin]/cas/
  - Create symlinks for login.php, validate.php, and serviceValidate.php
  - Copy .htaccess
  - Set permissions and group ownership
EOF
}

# Handle help flag
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  show_help
  exit 0
fi

# --------------------------
# Case 1: No args — reconfigure current directory
# --------------------------
if [[ -z "$1" ]]; then
  echo "No directory provided — assuming current directory is 'cgi-bin/cas/'"
  echo "Fixing permissions and symlinks..."

  ln -sf quick-cas.php login.php
  ln -sf quick-cas.php validate.php
  ln -sf quick-cas.php serviceValidate.php

  chmod 711 .
  chmod 644 *.php .htaccess

  if command -v chgrp >/dev/null 2>&1; then
    echo "Attempting to chgrp to httpd..."
    chgrp httpd . || echo "(chgrp failed — expected on non-Eniac environments)"
  fi

  echo "Done."
  exit 0
fi

# --------------------------
# Case 2: One path provided
# --------------------------
CGI_BIN_DIR="$1"

if [ ! -d "$CGI_BIN_DIR" ]; then
  echo "Error: '$CGI_BIN_DIR' is not a valid directory."
  show_help
  exit 1
fi

CAS_DIR="$CGI_BIN_DIR/cas"
mkdir -p "$CAS_DIR"

echo "Deploying to: $CAS_DIR"

cp quick-cas.php "$CAS_DIR/"
cp .htaccess "$CAS_DIR/"

ln -sf "$CAS_DIR/quick-cas.php" "$CAS_DIR/login.php"
ln -sf "$CAS_DIR/quick-cas.php" "$CAS_DIR/validate.php"
ln -sf "$CAS_DIR/quick-cas.php" "$CAS_DIR/serviceValidate.php"

chmod 711 "$CAS_DIR"
chmod 644 "$CAS_DIR"/*.php "$CAS_DIR/.htaccess"

if command -v chgrp >/dev/null 2>&1; then
  echo "Attempting to chgrp to httpd..."
  chgrp httpd "$CAS_DIR" || echo "(chgrp failed — expected on non-Eniac environments)"
fi

echo "Deployment complete. Test with: /cgi-bin/cas/login"
