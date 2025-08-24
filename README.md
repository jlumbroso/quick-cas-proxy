# Quick CAS Proxy

A lightweight **CAS-compatible** login shim that sits behind **Shibboleth**. It lets you gate microservices with PennKey (or any env-integrated Shibboleth) and validate tickets via standard CAS endpoints.

* **Login:** `/login.php?service=...` (PennKey-gated)
* **CAS 1.0:** `/validate.php?service=...&ticket=ST-...` (public)
* **CAS 2.0:** `/serviceValidate.php?service=...&ticket=ST-...` (public, returns CAS XML + attributes)
* **CAS 3.0 (P3):** `/p3_serviceValidate.php?service=...&ticket=ST-...` (public, returns CAS v3 XML with `<cas:attributes>`)

> Works on servers such as Penn Engineering's `alliance.seas.upenn.edu` (CGI) with PennKey, but can be used anywhere your webserver exposes Shibboleth attributes to scripts and lets you add `.htaccess`.

---

## ✨ Features

* 🔐 PennKey login using Apache Shibboleth headers
* 🎓 Compatible with CAS 1.0, CAS 2.0 **and CAS 3.0 (P3)** protocols:

  * `/index.php/login`
  * `/index.php/validate`
  * `/index.php/serviceValidate`
  * **`/index.php/p3_serviceValidate` (and `p3_serviceValidate.php`)**
* ⚙️ Configurable backend:

  * `FILE`-based (optional) with TTL support
  * `SQLITE` backend (default)
* 🪪 One-time service tickets, auto-expiring
* 🧹 Lazy purge of stale tickets at **24 × TTL**
* 🪝 URL dispatch via `index.php`, no rewrite rules required
* 📁 Deploys cleanly to its own subdirectory (`cgi-bin/cas/`)
* 📤 Automatically forwards Shibboleth attributes like `displayName`, `givenName`, `mail`, `affiliation`, etc.
* ❌ **Service access control:** ALLOW/BLOCK lists using **regex** (file + in-code list)
* 🔄 Log with log rotation (size cap, keep N files)
* 🔐 Security headers (`X-Content-Type-Options`, `Referrer-Policy`)
* ▫️ Minimal, portable code (no Composer deps)

---

## 🗂 File Structure

After deployment, your `cgi-bin/cas/` folder will contain:

```
cgi-bin/cas/
  .htaccess                 # Shib gate; exempts validate/serviceValidate (and p3_serviceValidate)
  index.php                 # dispatcher (PATH_INFO)
  quick-cas.php             # core logic (this file)
  login.php                 # thin wrapper -> run_login()
  validate.php              # thin wrapper -> run_validate()
  serviceValidate.php       # thin wrapper -> run_serviceValidate()
  p3_serviceValidate.php    # thin wrapper -> run_p3_serviceValidate()
  quick-cas/access_list     # OPTIONAL: regexes for service allow/block
```

**Wrappers** (kept in the repo for clarity):

```php
<?php // login.php
// DO NOT EDIT: thin endpoint wrapper; logic lives in quick-cas.php
require_once __DIR__.'/quick-cas.php';
run_login();
```

```php
<?php // validate.php
// DO NOT EDIT: thin endpoint wrapper; logic lives in quick-cas.php
require_once __DIR__.'/quick-cas.php';
run_validate();
```

```php
<?php // serviceValidate.php
// DO NOT EDIT: thin endpoint wrapper; logic lives in quick-cas.php
require_once __DIR__.'/quick-cas.php';
run_serviceValidate();
```

```php
<?php // p3_serviceValidate.php
// DO NOT EDIT: thin endpoint wrapper; logic lives in quick-cas.php
require_once __DIR__.'/quick-cas.php';
run_p3_serviceValidate();
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

<Files "p3_serviceValidate.php">
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
#   RewriteRule ^login$             index.php/login [L]
#   RewriteRule ^validate$          validate.php [L]
#   RewriteRule ^serviceValidate$   serviceValidate.php [L]
#   RewriteRule ^p3_serviceValidate$ p3_serviceValidate.php [L]
# </IfModule>
```

**(Optional) Deny direct web access to the access list file**
Create a second `.htaccess` inside `cgi-bin/cas/quick-cas/` with:

```apache
Require all denied
```

This keeps `quick-cas/access_list` private while still readable by PHP.

---

## 🚀 Deploy

Use the provided `deploy.sh`:

```bash
# Prepare local state (~/.quick-cas) only
./deploy.sh

# Deploy to your CGI-BIN (creates/updates cgi-bin/cas/)
./deploy.sh ~/public_html/cgi-bin

# Repair wrappers if they were edited
./deploy.sh --repair-wrappers ~/public_html/cgi-bin
```

The script:

* ensures `~/.quick-cas/{quickcas.db,tickets/,server.log}` (secure perms),
* copies `*.php`, `.htaccess`, wrappers to `<CGI_BIN_DIR>/cas/`,
* warns if wrappers look modified, `--repair-wrappers` can restore them,
* is idempotent (safe to run after `git pull` or from a hook).

---

## 🎛️ Configuration

Edit constants at the top of `quick-cas.php` as needed.

### Storage

* `STORAGE_TYPE`: `'SQLITE'` (default) or `'FILE'`
* `TICKET_TTL`: validity of a ticket in seconds (default `300`)
* Old tickets are lazily purged where `issued_at < (now - 24 * TICKET_TTL)`

State lives under `~/.quick-cas/`:

* `quickcas.db` (SQLite)
* `tickets/` (FILE mode)
* `server.log` (rotated)

### Logging

* `LOG_ENABLED`: enable/disable logging
* `LOG_ROTATE_MAX_SIZE`: rotate when log reaches this many bytes (default 1 MiB)
* `LOG_ROTATE_MAX_FILES`: keep this many rolled logs (e.g., `.1`, `.2`, …)

Logs live at `~/.quick-cas/server.log` with timestamps and rotation.

### Attribute Passthrough

At `/login`, the proxy captures Shibboleth **environment variables**:
`givenName, sn, displayName, mail, employeeNumber, affiliation,
unscoped_affiliation, eppn, pennname`

They’re stored with the ticket and returned by validation endpoints:

**CAS 2.0 (`/serviceValidate.php`)** — repeated `<cas:attribute name="...">value</cas:attribute>`:

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

**CAS 3.0 / P3 (`/p3_serviceValidate.php`)** — attributes are inside `<cas:attributes>` as child tags:

```xml
<cas:authenticationSuccess>
  <cas:user>lumbroso</cas:user>
  <cas:attributes>
    <cas:mail>lumbroso@cis.upenn.edu</cas:mail>
    <cas:affiliation>member@upenn.edu</cas:affiliation>
    <cas:affiliation>employee@upenn.edu</cas:affiliation>
    <cas:affiliation>faculty@upenn.edu</cas:affiliation>
    ...
  </cas:attributes>
</cas:authenticationSuccess>
```

> **Multi-value attributes** (like `affiliation`) are split on `;` and emitted as multiple tags in both v2 and v3 formats.

### Service Access Control (ALLOW/BLOCK)

You can restrict which `service` URLs are permitted on `/login`.

* `ACCESS_SERVICE_LIST_TYPE`: `'ALLOW'` or `'BLOCK'`
* `ACCESS_SERVICE_LIST_FILENAME`: file with **regex** rules, one per line
  (relative path is resolved against the CAS script directory; default `quick-cas/access_list`)
* `ACCESS_SERVICE_LIST`: extra regex rules inline
* `ACCESS_ENFORCE_HTTPS`: when true (default), only `https://` services allowed

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

---

## 🐍 Flask Integration Example (manual XML, CAS 2.0)

Assuming `quick-cas-proxy` is deployed at:

```
https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas
  ├─ login.php
  ├─ serviceValidate.php
  └─ validate.php
```

Install:

```bash
pip install flask requests
```

You will also need a way to create a tunnel to your local Flask server (e.g., [ngrok](https://ngrok.com/)).

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

---

## 🐍 Flask Integration Example (library, CAS 3.0 via `python-cas`)

If you prefer a batteries-included client that parses CAS v3 attributes for you, use `python-cas` with the **p3** endpoint:

Install:

```bash
pip install flask gunicorn python-cas requests
```

```python
# app.py
import os
from flask import Flask, redirect, request, session, url_for, render_template_string
from urllib.parse import urlencode, urljoin
from cas import CASClientV3

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

# IMPORTANT: trailing slash
CAS_SERVER_ROOT = os.environ.get(
    "CAS_SERVER_ROOT",
    "https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas/"
)
SERVICE_URL = os.environ.get("SERVICE_URL")  # e.g. https://cas-flask-demo.onrender.com/callback

class CASClientV3PHP(CASClientV3):
    url_suffix = 'p3_serviceValidate.php'  # our v3 endpoint
    def get_login_url(self):
        params = {'service': self.service_url}
        return urljoin(self.server_url, 'login.php') + '?' + urlencode(params)

def external_service_url():
    if SERVICE_URL:
        return SERVICE_URL
    base = request.url_root[:-1] if request.url_root.endswith('/') else request.url_root
    return base + url_for("callback")

def cas_client(service_url: str):
    return CASClientV3PHP(
        server_url=CAS_SERVER_ROOT,
        service_url=service_url,
        verify_ssl_certificate=True,
    )

@app.route("/")
def home():
    if "user" in session:
        attrs = session.get("attrs") or {}
        return render_template_string(
            "<h1>Profile</h1>"
            "<p><b>User:</b> {{u}}</p>"
            "<h2>Attributes</h2><pre>{{a}}</pre>"
            "<p><a href='{{url_for('logout')}}'>Logout</a></p>",
            u=session["user"], a=attrs
        )
    return redirect(url_for("login"))

@app.route("/login")
def login():
    svc = external_service_url()
    return redirect(cas_client(svc).get_login_url())

@app.route("/callback")
def callback():
    ticket = request.args.get("ticket")
    if not ticket:
        return "Missing ticket", 400
    svc = external_service_url()
    user, attrs, _ = cas_client(svc).verify_ticket(ticket)
    if not user:
        return "Ticket verification failed", 403
    session["user"] = user
    session["attrs"] = attrs or {}
    return redirect(url_for("home"))

@app.route("/logout")
def logout():
    session.clear()
    return "Logged out"
```

Set env vars for production (Render, etc.):

* `CAS_SERVER_ROOT` = `https://alliance.seas.upenn.edu/~<user>/cgi-bin/cas/`
* `SERVICE_URL`     = your public callback URL (e.g., `https://cas-flask-demo.onrender.com/callback`)
* `SECRET_KEY`      = any secret

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
* `p3_serviceValidate.php` is **public** and returns **XML** (v3 format)
* `validate.php` with no params returns **no**
* `index.php/login` with no `service` → **400**

---

## 🛠 Troubleshooting

* **XML looks like HTML login page:** your validation endpoint is still Shib-gated. See `.htaccess` exemptions for `serviceValidate.php` and `p3_serviceValidate.php`.
* **`no` on validation:** tickets are one-use & TTL-bound; also ensure login + validation hit **the same storage** (SQLite in home avoids `/tmp` pitfalls).
* **No attributes in CAS XML:** your `/login` didn’t see Shibboleth env vars; confirm with a gated `whoami.php` or check `~/.quick-cas/server.log` for `attrs=0`.
* **`index.php/*` exemptions:** shared hosting may not allow selective exemptions on `index.php/…`. Use the discrete `*.php` endpoints (as above).

---

Short answer: yes. This proxy is powerful—you’re effectively minting CAS tickets based on Shibboleth—and that deserves a clear, explicit “Ethics & Appropriate Use” section. Here’s a drop-in section you can paste into the README (no style changes, matches your tone).

---

## 🧭 Ethics & Appropriate Use

This project issues CAS-style tickets by trusting a Shibboleth-protected context. That means you are *extending* your institution’s identity perimeter. Please use it responsibly.

### Why this exists

- Provide a lightweight bridge for **internal apps/microservices** that can speak CAS but live behind **Shibboleth**, so teams can prototype and ship small tools safely.
- In many institutions, two things slow harmless, low-risk use cases:
  - **Process friction:** getting an SP registered or a CAS client approved can take weeks/months—disproportionate for small experiments or class projects.
  - **Category error (misassociation):** authentication gets conflated with **content endorsement**. SSO simply proves *who* is signing in; it does **not** imply the institution is reviewing or owning *what* the app does. This proxy keeps that separation explicit: it uses the official login to **gate audience**, not to claim institutional sponsorship of the app’s content or functionality.
- This shim **does not bypass** your IdP; it relies on it. It’s intended for **internal, policy-compliant** scenarios. As a project matures or its risk increases, migrate to the **official SP/CAS registration** path.


### Guardrails & responsibilities

* **Institutional policy:** Before production use, get sign-off from your IT/Sec team (e.g., Shibboleth attribute release policy, acceptable use, data classification, incident response).
* **Scope control:** Keep the proxy limited to services you control. Use an **ALLOW list** (recommended) and require **HTTPS** to prevent open-redirect abuse or ticket leakage.
* **Data minimization:** Only capture the attributes your app needs. Tickets are one-time and short-lived; attributes are stored only with the ticket and returned once.
* **Logging:** Logs are for operability, not surveillance. Rotate them and avoid logging full attribute payloads. Consider disabling logs in production or scrubbing identifiers.
* **Transparency:** If end users interact with apps relying on this proxy, be clear that authentication is via the institution’s IdP, but ticket minting/validation is handled by this shim.
* **No third-party brokering:** Don’t let external orgs “rely” on your proxy as an IdP. If a use case grows beyond your team, migrate to the **official** CAS/SP registration path.
* **Security hygiene:** Enforce HTTPS for `service` URLs, use an **ALLOW** list, keep `.htaccess` exemptions tight, and store state under the user’s home (not shared `/tmp`).
* **Compliance:** Attributes may be personal data (e.g., FERPA/GDPR/CCPA). Set retention appropriately and document your purpose and lawful basis if applicable.

### Recommended defaults (production)

* `ACCESS_ENFORCE_HTTPS = true`
* `ACCESS_SERVICE_LIST_TYPE = 'ALLOW'` with explicit trusted hosts
* Keep `TICKET_TTL` short (e.g., 300s) and leave purge at `24 × TTL`
* Consider `LOG_ENABLED = false` (or keep it on but only log minimal metadata)
* Prefer `SQLITE` storage in `~/.quick-cas/` (avoids multi-host `/tmp` issues)

### Quick ethics checklist

* [ ] I have approval (or a green light) to run this internally.
* [ ] Only services I control are allowed (ALLOW list in place).
* [ ] HTTPS-only service URLs enforced.
* [ ] Logging minimized/rotated; no sensitive attributes retained longer than needed.
* [ ] Clear path to migrate heavy/long-term use to official CAS/SP registration.

> Bottom line: this shim is great for small, internal, policy-compliant use. If it starts looking like a general identity provider, it’s time to involve your central IAM team and move to the sanctioned path.

---

## 📜 License

Mozilla Public License V2 — simple, open, safe for internal academic use.

---

## 🙏 Acknowledgments

Built for Penn Engineering by [@jlumbroso](https://github.com/jlumbroso), inspired by practical needs for lightweight, CAS-compatible access control behind PennKey.
