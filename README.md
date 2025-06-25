# Quick CAS Proxy

A lightweight CAS-compatible login proxy designed for any environment where server-side scripts (e.g. PHP) can be protected via `.htaccess`-based SSO — such as Shibboleth.

This implementation is specialized for use at Penn, leveraging PennKey authentication, but the core architecture is portable to any institution with similar SSO infrastructure.

---

## ✨ Features

- 🔐 PennKey login using Apache Shibboleth headers
- 🎓 Compatible with CAS 1.0 and CAS 2.0 protocols:
  - `/cas/login`
  - `/cas/validate`
  - `/cas/serviceValidate`
- ⚙️ Configurable backend:
  - `FILE`-based (default) with TTL support
  - `SQLITE` backend (optional)
- 🪪 One-time service tickets, auto-expiring
- 🪝 Symlink-based dispatch (`basename($_SERVER['SCRIPT_NAME'])`)
- 📁 Deploys cleanly to its own subdirectory (`cgi-bin/cas/`)

---

## 🗂 File Structure

After deployment, your `cgi-bin/cas/` folder will contain:

```

cgi-bin/cas/
├── quick-cas.php
├── login.php              ← symlink to quick-cas.php
├── validate.php           ← symlink to quick-cas.php
├── serviceValidate.php    ← symlink to quick-cas.php
└── .htaccess              ← enforces SSO and URL rewrites

````

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/YOURNAME/quick-cas-proxy.git
cd quick-cas-proxy
````

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

## 🔧 Configuration

Inside `quick-cas.php`, you can configure:

```php
const STORAGE_TYPE = 'FILE'; // or 'SQLITE'
const TICKET_PREFIX = '/tmp/cas_ticket_';
const SQLITE_PATH = '/tmp/quickcas.db';
const TICKET_TTL = 300; // seconds
```

For most users, `FILE` is sufficient. Switch to `SQLITE` for concurrent or persistent usage.

## 📡 CAS Endpoints

Use any standard CAS client library (Python, Java, etc) and configure the following URLs:

```
/cgi-bin/cas/login
/cgi-bin/cas/validate
/cgi-bin/cas/serviceValidate
```

They behave exactly as a CAS 1.0 / 2.0 endpoint would.

## 🧪 Testing

Once deployed, test login:

```bash
curl -i "https://your.site.upenn.edu/cgi-bin/cas/login?service=https://example.com"
```

Or test validation:

```bash
curl "https://your.site.upenn.edu/cgi-bin/cas/validate?service=https://example.com&ticket=ST-12345"
```

## 🛠 Example Git Pull Workflow

For self-healing deployments:

```bash
git pull && ./deploy.sh ~/public_html/cgi-bin/
```

Or create a `post-merge` Git hook:

```bash
echo '#!/bin/sh\n./deploy.sh ~/public_html/cgi-bin/' > .git/hooks/post-merge
chmod +x .git/hooks/post-merge
```

## 📜 License

Mozilla Public License V2 — simple, open, safe for internal academic use.

## 🙏 Acknowledgments

Built for Penn Engineering by [@jlumbroso](https://github.com/jlumbroso), inspired by practical needs for lightweight, CAS-compatible access control.
