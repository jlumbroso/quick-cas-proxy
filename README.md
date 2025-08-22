# Quick CAS Proxy

A lightweight CAS-compatible login proxy designed for any environment where server-side scripts (e.g. PHP) can be protected via `.htaccess`-based SSO — such as Shibboleth. This implementation is specialized for use at Penn, leveraging PennKey authentication, but the core architecture is portable to any institution with similar SSO infrastructure.

---

## ✨ Features

- 🔐 PennKey login using Apache Shibboleth headers
- 🎓 Compatible with CAS 1.0 and CAS 2.0 protocols:
  - `/index.php/login`
  - `/index.php/validate`
  - `/index.php/serviceValidate`
- ⚙️ Configurable backend:
  - `FILE`-based (default) with TTL support
  - `SQLITE` backend (optional)
- 🪪 One-time service tickets, auto-expiring
- 🪝 URL dispatch via `index.php`, no rewrite rules required
- 📁 Deploys cleanly to its own subdirectory (`cgi-bin/cas/`)
- 📤 Automatically forwards Shibboleth attributes like `displayName`, `givenName`, `mail`, `affiliation`, etc.

---

## 🗂 File Structure

After deployment, your `cgi-bin/cas/` folder will contain:

```
cgi-bin/cas/
├── quick-cas.php          ← all CAS logic, modular
├── index.php              ← dispatches to CAS logic by path
├── .htaccess              ← Shibboleth config only (no rewrite)
├── deploy.sh              ← optional deployment script
```

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/YOURNAME/quick-cas-proxy.git
cd quick-cas-proxy
```

### 2. Deploy

To deploy to your `cgi-bin` directory (e.g. `~/public_html/cgi-bin/`):

```bash
./deploy.sh ~/public_html/cgi-bin/
```

To reconfigure only (e.g. after a `git pull`), run from inside the `cas/` subdirectory:

```bash
cd ~/public_html/cgi-bin/cas/
./deploy.sh
```

---

## 🔧 Configuration

Inside `quick-cas.php`, you can configure:

```php
const STORAGE_TYPE = 'FILE'; // or 'SQLITE'
const TICKET_PREFIX = '/tmp/cas_ticket_';
const SQLITE_PATH = '/tmp/quickcas.db';
const TICKET_TTL = 300; // seconds
```

For most users, `FILE` is sufficient. Switch to `SQLITE` for concurrent or persistent usage.

---

## 🔐 Optional Rewrite Rules

If Apache `mod_rewrite` is enabled for `.htaccess`, you can use cleaner routes like `/cas/login` instead of `/cas/index.php/login`. Update `.htaccess` as follows:

```apache
# Auth remains unchanged
AuthType shibboleth
ShibRequestSetting requireSession 1
Require shib-session

# Optional rewrite block (commented out by default)
# <IfModule mod_rewrite.c>
# RewriteEngine On
# RewriteBase /~lumbroso/cgi-bin/cas/
# RewriteRule ^login$ index.php/login [L]
# RewriteRule ^validate$ index.php/validate [L]
# RewriteRule ^serviceValidate$ index.php/serviceValidate [L]
# </IfModule>
```

Test these by visiting:
```
https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas/login?service=https://example.com
```

---

## 📡 CAS Endpoints

Assuming you are not using rewrite rules, use the following full URLs:

```
https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas/index.php/login
https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas/index.php/validate
https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas/index.php/serviceValidate
```

---

## 🧪 Testing CAS Flow

To test login:

```bash
curl -i "https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas/index.php/login?service=https://example.com"
```

To test ticket validation:

```bash
curl "https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas/index.php/validate?service=https://example.com&ticket=ST-12345"
```

To test serviceValidate (CAS 2.0):

```bash
curl "https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas/index.php/serviceValidate?service=https://example.com&ticket=ST-12345"
```

---

## 🐍 Flask Integration Example

Install:
```bash
pip install flask-cas-ng
```

```python
from flask import Flask
from flask_cas_ng import CAS

app = Flask(__name__)
app.secret_key = 'super-secret-key'
cas = CAS(app, '/cas')

# Your CAS proxy configuration
app.config['CAS_SERVER'] = 'https://alliance.seas.upenn.edu/~lumbroso/cgi-bin/cas'
app.config['CAS_LOGIN_ROUTE'] = '/index.php/login'
app.config['CAS_VALIDATE_ROUTE'] = '/index.php/validate'
app.config['CAS_AFTER_LOGIN'] = 'cas_logged_in'

@app.route('/')
@cas.login
def home():
    return f"Hello, {cas.username}!"

@app.route('/cas_logged_in')
def cas_logged_in():
    return f"User {cas.username} is authenticated."
```

---

## 🛠 Git Deployment Hook

For self-healing deployments:

```bash
git pull && ./deploy.sh ~/public_html/cgi-bin/
```

Or set up a Git post-merge hook:

```bash
echo '#!/bin/sh\n./deploy.sh ~/public_html/cgi-bin/' > .git/hooks/post-merge
chmod +x .git/hooks/post-merge
```

---

## 📜 License

Mozilla Public License V2 — simple, open, safe for internal academic use.

---

## 🙏 Acknowledgments

Built for Penn Engineering by [@jlumbroso](https://github.com/jlumbroso), inspired by practical needs for lightweight, CAS-compatible access control behind PennKey.
