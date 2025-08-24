# Quick CAS Proxy

A lightweight **CAS-compatible** login shim that sits behind **Shibboleth**. It lets you gate microservices with PennKey (or any env-integrated Shibboleth) and validate tickets via standard CAS endpoints.

- **Login:** `/index.php/login?service=...` (PennKey-gated)
- **CAS 1.0:** `/validate.php?service=...&ticket=ST-...` (public)
- **CAS 2.0:** `/serviceValidate.php?service=...&ticket=ST-...` (public, returns CAS XML + attributes)

> Works on servers such as Penn Engineering's `alliance.seas.upenn.edu` (CGI) with PennKey, but can be used anywhere your webserver exposes Shibboleth attributes to scripts and lets you add `.htaccess`.

---

## ✨ Features

- 🔐 PennKey login using Apache Shibboleth headers
- 🎓 Compatible with CAS 1.0 and CAS 2.0 protocols:
  - `/index.php/login`
  - `/index.php/validate`
  - `/index.php/serviceValidate`
- ⚙️ Configurable backend:
  - `FILE`-based (optional) with TTL support
  - `SQLITE` backend (default)
- 🪪 One-time service tickets, auto-expiring
- 🪝 URL dispatch via `index.php`, no rewrite rules required
- 📁 Deploys cleanly to its own subdirectory (`cgi-bin/cas/`)
- 📤 Automatically forwards Shibboleth attributes like `displayName`, `givenName`, `mail`, `affiliation`, etc.
- ❌ Service access control:** ALLOW/BLOCK lists using **regex** (file + in-code list)
- 🔄 Log with log rotation (size cap, keep N files)
- 🔐 Security headers (`X-Content-Type-Options`, `Referrer-Policy`)
- ▫️ Minimal, portable code (no Composer deps)


---

## 🗂 File Structure


After deployment, your `cgi-bin/cas/` folder will contain:
```

cgi-bin/cas/
.htaccess                 # Shib gate; exempts validate/serviceValidate
index.php                 # dispatcher (PATH\_INFO)
quick-cas.php             # core logic (this file)
validate.php              # thin wrapper -> run\_validate()
serviceValidate.php       # thin wrapper -> run\_serviceValidate()
quick-cas/access\_list     # OPTIONAL: regexes for service allow/block

````

**Wrappers** (kept in the repo for clarity):

```php
<?php // validate.php
// DO NOT EDIT: thin endpoint wrapper; logic lives in quick-cas.php
require_once __DIR__.'/quick-cas.php';
run_validate();
````

```php
<?php // serviceValidate.php
// DO NOT EDIT: thin endpoint wrapper; logic lives in quick-cas.php
require_once __DIR__.'/quick-cas.php';
run_serviceValidate();
```

---

## 🔐 .htaccess

Put this in `cgi-bin/cas/.htaccess`:

```apache
# Gate by default with Shibboleth
AuthType shibboleth
ShibRequestSetting requireSession 1
Require shib-session

# EXEMPT validation endpoints (server-to-server)
<Files "serviceValidate.php">
  ShibRequestSetting requireSession 0
  Require all granted
</Files>

<Files "validate.php">
  ShibRequestSetting requireSession 0
  Require all granted
</Files>

# Optional pretty URLs if allowed (commented)
# <IfModule mod_rewrite.c>
#   RewriteEngine On
#   RewriteBase /~<USER>/cgi-bin/cas/
#   RewriteRule ^login$           index.php/login [L]
#   RewriteRule ^validate$        validate.php [L]
#   RewriteRule ^serviceValidate$ serviceValidate.php [L]
# </IfModule>
```

---

## 🚀 Deploy

Use the provided `deploy.sh`:

```bash
# Prepare local state (~/.quick-cas) only
./deploy.sh

# Deploy to your CGI-BIN (creates/updates cgi-bin/cas/)
./deploy.sh ~/public_html/cgi-bin
```

The script:

* ensures `~/.quick-cas/{quickcas.db,tickets/,server.log}` (secure perms),
* copies `*.php`, `.htaccess`, wrappers to `<CGI_BIN_DIR>/cas/`,
* warns if wrappers look modified, `--repair-wrappers` can restore them.

---

## 🎛️ Configuration

Edit constants at the top of `quick-cas.php` as needed.

### Storage

* `STORAGE_TYPE`: `'SQLITE'` (default) or `'FILE'`
* `TICKET_TTL`: validity of a ticket in seconds (default `300`)
* Old tickets are lazily purged where `issued_at < (now - 24 * TICKET_TTL)`

### Logging

* `LOG_ENABLED`: enable/disable logging
* `LOG_ROTATE_MAX_SIZE`: rotate when log reaches this many bytes (default 1 MiB)
* `LOG_ROTATE_MAX_FILES`: keep this many rolled logs (e.g., `.1`, `.2`, …)

Logs live at `~/.quick-cas/server.log`.

### Attribute Passthrough

At `/login`, the proxy captures Shibboleth **environment variables**:
`givenName, sn, displayName, mail, employeeNumber, affiliation,
unscoped_affiliation, eppn, pennname`

They’re stored with the ticket and returned by `/serviceValidate` as:

```xml
<cas:authenticationSuccess>
  <cas:user>lumbroso</cas:user>
  <cas:attribute name="mail">lumbroso@cis.upenn.edu</cas:attribute>
  <cas:attribute name="affiliation">member@upenn.edu</cas:attribute>
  <cas:attribute name="affiliation">employee@upenn.edu</cas:attribute>
  <cas:attribute name="affiliation">faculty@upenn.edu</cas:attribute>
  ...
</cas:authenticationSuccess>
```

> **Multi-value attributes** (like `affiliation`) are split on `;` and emitted as multiple `<cas:attribute>` tags.

### Service Access Control (ALLOW/BLOCK)

You can restrict which `service` URLs are permitted on `/login`.

* `ACCESS_SERVICE_LIST_TYPE`: `'ALLOW'` or `'BLOCK'`
* `ACCESS_SERVICE_LIST_FILENAME`: file with **regex** rules, one per line
  (relative path is resolved against the CAS script directory)
* `ACCESS_SERVICE_LIST`: extra regex rules inline

Rules are **regular expressions**. You can use delimited form (`~...~i`) or raw (we’ll wrap it in `~...~i`).

Examples:

```txt
# quick-cas/access_list  (ALLOW mode)
^https://[^/]+\.seas\.upenn\.edu(/|$)
^https://fb9c0e11601d\.ngrok-free\.app(/|$)
```

**Behavior:**

* **ALLOW:** if *any* regex matches → allowed; empty list ⇒ allow all
* **BLOCK:** if *any* regex matches → **denied**; empty list ⇒ allow all
* `ACCESS_ENFORCE_HTTPS`: when true (default), only `https://` services allowed

---

## 🐍 Flask Integration Example (client)

Assuming `quick-cas-proxy` is deployed at `https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas` with the paths:
```
https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas/login.php
https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas/serviceValidate.php
https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas/validate.php
```

Install:
```bash
pip install flask-cas-ng
```

You will also need a way to create a tunnel to your local Flask server (e.g., [ngrok](https://ngrok.com/)).

Then:

```python
from flask import Flask, redirect, request, session, url_for
import requests, xml.etree.ElementTree as ET

app = Flask(__name__)
app.secret_key = "test-key"

CAS_BASE = "https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas"
CAS_LOGIN = f"{CAS_BASE}/index.php/login"           # gated
CAS_VALIDATE_V2 = f"{CAS_BASE}/serviceValidate.php" # public
SERVICE_URL = "https://<your-ngrok>.ngrok-free.app/verify"

@app.route("/")
def home():
    if "cas_user" in session:
        return f"✅ Logged in as: {session['cas_user']}"
    return redirect(url_for("login"))

@app.route("/login")
def login():
    return redirect(f"{CAS_LOGIN}?service={SERVICE_URL}")

@app.route("/verify")
def verify():
    ticket = request.args.get("ticket")
    if not ticket: return "Missing ticket", 400
    r = requests.get(CAS_VALIDATE_V2, params={"service": SERVICE_URL, "ticket": ticket}, allow_redirects=False, timeout=10)
    ns = {"cas": "http://www.yale.edu/tp/cas"}
    root = ET.fromstring(r.text)
    success = root.find("cas:authenticationSuccess", ns)
    if success is None: return ("Login failed\n\n"+r.text, 403)
    user = success.find("cas:user", ns).text
    attrs = {}
    for a in success.findall("cas:attribute", ns):
        attrs.setdefault(a.attrib["name"], []).append(a.text or "")
    session["cas_user"] = user
    session["cas_attrs"] = attrs
    return redirect(url_for("profile"))

@app.route("/profile")
def profile():
    return f"<h1>👤 CAS Login Successful</h1><pre>{session.get('cas_user')}\\n{session.get('cas_attrs')}</pre>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6000, debug=True)
```

> Use an **HTTPS public callback** (e.g., ngrok) as your `SERVICE_URL`. The proxy enforces HTTPS by default.

```
ngrok http 6000
```

Then update your `SERVICE_URL` to the ngrok URL:

```python
SERVICE_URL = "https://<your-ngrok>.ngrok-free.app/verify"
```

You can then visit `https://<your-ngrok>.ngrok-free.app/` to test the integration.

---

## 🧪 Sanity tests

Run the included script:

```bash
# default base = https://alliance.seas.upenn.edu/~$USER/cgi-bin/cas
./test.sh

# or specify the base explicitly
./test.sh "https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas"
```

It checks:

* `serviceValidate.php` is **public** and returns **XML**
* `serviceValidate.php` with no params returns **INVALID\_REQUEST** XML
* `validate.php` with no params returns **no**
* `index.php/login` with no `service` → **400**

---

## 🛠 Troubleshooting

* **XML looks like HTML login page:** your `/serviceValidate.php` is still Shib-gated. See `.htaccess` exemptions.
* **`no` on validation:** tickets are one-use & TTL-bound; also ensure login + validation hit **the same storage** (SQLite in home avoids `/tmp` pitfalls).
* **No attributes in CAS XML:** your `/login` didn’t see Shibboleth env vars; confirm with a gated `whoami.php` or check `~/.quick-cas/server.log` for `attrs=0`.

---

## 📜 License

Mozilla Public License V2 — simple, open, safe for internal academic use.

---

## 🙏 Acknowledgments

Built for Penn Engineering by [@jlumbroso](https://github.com/jlumbroso), inspired by practical needs for lightweight, CAS-compatible access control behind PennKey.