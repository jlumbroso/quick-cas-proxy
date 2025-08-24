<?php
/**
 * quick-cas.php — CAS-compatible shim over Shibboleth-protected PHP
 *
 * Endpoints:
 *   - /login            : issues a service ticket (ST) and redirects back to ?ticket=...
 *   - /validate         : CAS 1.0 (text) validation (no attributes)
 *   - /serviceValidate  : CAS 2.0 (XML) validation (returns attributes captured at /login)
 *   - /p3/serviceValidate : CAS 3.0 (XML) validation (same XML shape as v2; added for client compat)
 *
 * Storage:
 *   - Default: SQLITE at ~/.quick-cas/quickcas.db
 *   - Optional: FILE tickets under ~/.quick-cas/tickets/cas_ticket_*
 *
 * Security:
 *   - Tickets are one-time, TTL-bound, and tied to 'service'
 *   - Service access control via ALLOW/BLOCK regex list (constant + file)
 *   - Security headers added to all responses
 *   - Log with rotation
 */

/* =========================
 * Configuration
 * ========================= */

// Logging
define('LOG_ENABLED', true);             // toggle server-side logging
define('LOG_ROTATE_MAX_SIZE', 1048576);  // bytes; 0 to disable rotation (default: 1 MiB)
define('LOG_ROTATE_MAX_FILES', 5);       // how many .1, .2, ... to keep

// Storage
define('STORAGE_TYPE', 'SQLITE');        // 'SQLITE' or 'FILE'
define('TICKET_TTL', 300);               // seconds (one-time ticket lifetime)
define('PURGE_FACTOR', 24);              // expired purge threshold = PURGE_FACTOR * TICKET_TTL

// Hidden state directory under $HOME (override with env QUICKCAS_HOME)
define('QUICKCAS_BASE', (function () {
    $home = getenv('QUICKCAS_HOME');
    if (!$home) {
        $home = getenv('HOME') ?: sys_get_temp_dir();
        $home = rtrim($home, '/').'/.quick-cas';
    }
    return $home;
})());
define('SQLITE_PATH', QUICKCAS_BASE.'/quickcas.db');
define('TICKET_DIR',  QUICKCAS_BASE.'/tickets');
define('TICKET_PREFIX', TICKET_DIR.'/cas_ticket_');
define('LOG_PATH', QUICKCAS_BASE.'/server.log');

// Shibboleth attributes to capture at /login and include in CAS 2.0/3.0 XML
const ATTR_KEYS = [
    'givenName','sn','displayName','mail','employeeNumber',
    'affiliation','unscoped_affiliation','eppn','pennname'
];

// Service access control
// - TYPE: 'ALLOW' or 'BLOCK' (case-insensitive)
// - FILENAME: relative paths are resolved against the CAS script directory
// - LIST: additional in-code regexes (merged with file entries). Empty ⇒ no constraints for that source.
define('ACCESS_SERVICE_LIST_TYPE', 'BLOCK');                    // 'ALLOW' or 'BLOCK'
define('ACCESS_SERVICE_LIST_FILENAME', 'quick-cas/access_list'); // e.g. './quick-cas/access_list'
define('ACCESS_SERVICE_LIST', []);                               // e.g. ['~^https://.*\\.seas\\.upenn\\.edu(/|$)~i']
define('ACCESS_ENFORCE_HTTPS', true);                            // require https service URLs

/* =========================
 * Bootstrap: dirs & logging
 * ========================= */
@umask(0077);
@mkdir(QUICKCAS_BASE, 0700, true);
@mkdir(TICKET_DIR, 0700, true);
if (LOG_ENABLED && !is_file(LOG_PATH)) {
    @file_put_contents(LOG_PATH, "[".date('c')."] quick-cas boot\n", FILE_APPEND);
    @chmod(LOG_PATH, 0600);
}

function rotate_logs_if_needed() {
    if (!LOG_ENABLED || LOG_ROTATE_MAX_SIZE <= 0) return;
    clearstatcache(true, LOG_PATH);
    $sz = @filesize(LOG_PATH);
    if ($sz !== false && $sz >= LOG_ROTATE_MAX_SIZE) {
        $max = max(1, (int)LOG_ROTATE_MAX_FILES);
        for ($i = $max - 1; $i >= 1; $i--) {
            $src = LOG_PATH . '.' . $i;
            $dst = LOG_PATH . '.' . ($i + 1);
            if (is_file($src)) @rename($src, $dst);
        }
        if (is_file(LOG_PATH)) @rename(LOG_PATH, LOG_PATH.'.1');
        @file_put_contents(LOG_PATH, "[".date('c')."] log rotated\n", FILE_APPEND);
        @chmod(LOG_PATH, 0600);
    }
}

function qlog($msg) {
    if (!LOG_ENABLED) return;
    rotate_logs_if_needed();
    @file_put_contents(LOG_PATH, "[".date('c')."] ".$msg."\n", FILE_APPEND);
}

function send_security_headers() {
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
}

/* =========================
 * Helpers: Shib & Access Control
 * ========================= */

function shib_user() {
    if (!empty($_SERVER['REMOTE_USER'])) return (string)$_SERVER['REMOTE_USER'];
    if (!empty($_SERVER['pennname']))    return (string)$_SERVER['pennname'];
    return null;
}

function capture_attrs_from_env() {
    $out = [];
    foreach (ATTR_KEYS as $k) {
        if (isset($_SERVER[$k]) && $_SERVER[$k] !== '') $out[$k] = (string)$_SERVER[$k];
    }
    return $out;
}

// Read regex list from file; ignore blank lines and lines starting with '#'
function read_access_list_file() {
    $path = ACCESS_SERVICE_LIST_FILENAME;
    if ($path && $path[0] !== '/' && $path[0] !== '\\') {
        $path = rtrim(__DIR__, '/').'/'.$path;
    }
    if (!$path || !is_file($path)) return [];
    $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) return [];
    $patterns = [];
    foreach ($lines as $ln) {
        $ln = trim($ln);
        if ($ln === '' || $ln[0] === '#') continue;
        $patterns[] = $ln;
    }
    return $patterns;
}

function match_any_regex(array $patterns, $string) {
    foreach ($patterns as $p) {
        $pat = $p;
        if (!preg_match('/^(.).*\\1[imsxuADSUXJ]*$/', $p)) {
            $pat = '~' . $p . '~i';
        }
        $ok = @preg_match($pat, $string);
        if ($ok === 1) return true;
        if ($ok === false) qlog("WARN invalid regex in access list: {$p}");
    }
    return false;
}

// Enforce scheme + allow/block list. Returns normalized $service (original).
function enforce_service_policy($service) {
    $url = $service;
    $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
    $host   = (string)parse_url($url, PHP_URL_HOST);

    if (!$scheme || !$host) {
        qlog("access DENY invalid_url service={$url}");
        http_response_code(400);
        send_security_headers();
        header('Content-Type: text/plain; charset=UTF-8');
        echo "Invalid 'service' URL.";
        exit;
    }
    if (ACCESS_ENFORCE_HTTPS && $scheme !== 'https') {
        qlog("access DENY non_https service={$url}");
        http_response_code(400);
        send_security_headers();
        header('Content-Type: text/plain; charset=UTF-8');
        echo "Service must be HTTPS.";
        exit;
    }

    $type = strtoupper(trim((string)ACCESS_SERVICE_LIST_TYPE));
    $filePatterns = read_access_list_file();
    $patterns = array_merge(ACCESS_SERVICE_LIST, $filePatterns);

    if (empty($patterns)) {
        qlog("access ALLOW (no patterns) service={$url}");
        return $url;
    }

    $matched = match_any_regex($patterns, $url);

    if ($type === 'ALLOW') {
        if ($matched) { qlog("access ALLOW (ALLOW match) service={$url}"); return $url; }
        qlog("access DENY (ALLOW miss) service={$url}");
        http_response_code(400);
        send_security_headers();
        header('Content-Type: text/plain; charset=UTF-8');
        echo "Service not permitted by allow list.";
        exit;
    } elseif ($type === 'BLOCK') {
        if ($matched) {
            qlog("access DENY (BLOCK match) service={$url}");
            http_response_code(400);
            send_security_headers();
            header('Content-Type: text/plain; charset=UTF-8');
            echo "Service blocked by policy.";
            exit;
        }
        qlog("access ALLOW (BLOCK no match) service={$url}");
        return $url;
    } else {
        qlog("access ALLOW (unknown type ".ACCESS_SERVICE_LIST_TYPE.") service={$url}");
        return $url;
    }
}

/* =========================
 * Storage: SQLITE / FILE
 * ========================= */

function sqlite_available() {
    return class_exists('PDO') && in_array('sqlite', PDO::getAvailableDrivers(), true);
}
function sqlite_db() {
    if (!sqlite_available()) {
        qlog("ERROR: SQLITE selected but PDO_SQLITE not available");
        http_response_code(500);
        send_security_headers();
        header('Content-Type: text/plain; charset=UTF-8');
        exit("quick-cas: SQLITE driver not available; switch STORAGE_TYPE to FILE or enable pdo_sqlite");
    }
    $db = new PDO("sqlite:".SQLITE_PATH, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $db->exec("CREATE TABLE IF NOT EXISTS tickets (
        ticket TEXT PRIMARY KEY,
        user TEXT NOT NULL,
        service TEXT NOT NULL,
        issued_at INTEGER NOT NULL,
        attrs TEXT
    )");
    // Best-effort migration (ignore if already exists)
    try { $db->exec("ALTER TABLE tickets ADD COLUMN attrs TEXT"); } catch (Throwable $e) { /* ignore */ }
    return $db;
}

function purge_expired() {
    $threshold = time() - (TICKET_TTL * PURGE_FACTOR);
    if (STORAGE_TYPE === 'SQLITE') {
        $db = sqlite_db();
        $stmt = $db->prepare("DELETE FROM tickets WHERE issued_at < ?");
        $stmt->execute([$threshold]);
        $cnt = $stmt->rowCount();
        if ($cnt > 0) qlog("purge SQLITE removed={$cnt}");
    } else {
        $removed = 0;
        foreach ((array)glob(TICKET_PREFIX . '*') as $file) {
            $mt = @filemtime($file);
            if ($mt !== false && $mt < $threshold) {
                if (@unlink($file)) $removed++;
            }
        }
        if ($removed > 0) qlog("purge FILE removed={$removed}");
    }
}

/** Store issued ticket with bound service and captured attrs */
function store_ticket($ticket, $user, $service, array $attrs) {
    purge_expired(); // lazy cleanup
    if (STORAGE_TYPE === 'SQLITE') {
        $db = sqlite_db();
        $stmt = $db->prepare("INSERT INTO tickets (ticket, user, service, issued_at, attrs) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$ticket, $user, $service, time(), json_encode($attrs, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)]);
        qlog("store SQLITE ticket=$ticket user=$user service=$service attrs=".count($attrs));
    } else {
        $path = TICKET_PREFIX.$ticket;
        $payload = $user."\n".time()."\n".$service."\n".json_encode($attrs, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
        @file_put_contents($path, $payload);
        @chmod($path, 0600);
        qlog("store FILE ticket=$ticket path=$path user=$user service=$service attrs=".count($attrs));
    }
}

/** Validate+consume ticket; returns ['user'=>..., 'attrs'=>[...]] or false */
function validate_ticket($ticket, $service) {
    if (!$ticket || !$service) return false;

    if (STORAGE_TYPE === 'SQLITE') {
        $db = sqlite_db();
        $stmt = $db->prepare("SELECT user, service, issued_at, attrs FROM tickets WHERE ticket = ?");
        $stmt->execute([$ticket]);
        $row = $stmt->fetch();
        if (!$row) { qlog("validate MISS SQLITE ticket=$ticket"); return false; }

        $age = time() - (int)$row['issued_at'];
        if ($age > TICKET_TTL) {
            $db->prepare("DELETE FROM tickets WHERE ticket = ?")->execute([$ticket]);
            qlog("validate EXPIRED SQLITE ticket=$ticket age=$age");
            return false;
        }
        if (!hash_equals((string)$row['service'], (string)$service)) {
            qlog("validate SERVICE_MISMATCH SQLITE ticket=$ticket expected={$row['service']} got=$service");
            return false;
        }
        $db->prepare("DELETE FROM tickets WHERE ticket = ?")->execute([$ticket]); // consume
        $attrs = json_decode($row['attrs'] ?? '[]', true);
        if (!is_array($attrs)) $attrs = [];
        qlog("validate OK SQLITE ticket=$ticket user={$row['user']} attrs=".count($attrs));
        return ['user'=>$row['user'], 'attrs'=>$attrs];
    }

    // FILE mode
    $path = TICKET_PREFIX.$ticket;
    if (!is_file($path)) { qlog("validate MISS FILE ticket=$ticket path=$path"); return false; }
    $content = @file_get_contents($path);
    if ($content === false) { qlog("validate READ_FAIL FILE ticket=$ticket"); return false; }
    $parts = explode("\n", $content, 4); // user \n issued \n service \n json-attrs
    $user = $parts[0] ?? '';
    $issued = (int)($parts[1] ?? 0);
    $storedService = trim($parts[2] ?? '');
    $attrs = json_decode($parts[3] ?? '[]', true);
    if (!is_array($attrs)) $attrs = [];

    $age = time() - $issued;
    if ($age > TICKET_TTL) {
        @unlink($path);
        qlog("validate EXPIRED FILE ticket=$ticket age=$age");
        return false;
    }
    if (!hash_equals($storedService, (string)$service)) {
        qlog("validate SERVICE_MISMATCH FILE ticket=$ticket expected=$storedService got=$service");
        return false;
    }
    @unlink($path); // consume
    qlog("validate OK FILE ticket=$ticket user=$user attrs=".count($attrs));
    return ['user'=>$user, 'attrs'=>$attrs];
}

/* =========================
 * Endpoints
 * ========================= */

function run_login() {
    $service = $_GET['service'] ?? '';
    if (!$service) {
        http_response_code(400);
        send_security_headers();
        header('Content-Type: text/plain; charset=UTF-8');
        echo "Missing 'service' parameter.";
        qlog("login FAIL missing_service");
        exit;
    }

    // Policy check (https + allow/block list)
    $service = enforce_service_policy($service);

    $user = shib_user();
    if (!$user) {
        http_response_code(403);
        send_security_headers();
        header('Content-Type: text/plain; charset=UTF-8');
        echo "User not authenticated (Shibboleth REMOTE_USER/pennname missing).";
        qlog("login FAIL no_remote_user service=$service");
        exit;
    }

    $attrs = capture_attrs_from_env();
    $ticket = 'ST-'.bin2hex(random_bytes(16));
    store_ticket($ticket, $user, $service, $attrs);

    $redir = $service.(strpos($service, '?') === false ? '?' : '&')."ticket=".$ticket;
    qlog("login OK user=$user ticket=$ticket redirect=$redir attrs=".count($attrs));
    header("Location: ".$redir);
    exit;
}

function run_validate() {
    send_security_headers();
    header('Content-Type: text/plain; charset=UTF-8');
    $ticket  = $_GET['ticket']  ?? '';
    $service = $_GET['service'] ?? '';
    if (!$ticket || !$service) {
        echo "no\n";
        qlog("validate v1 FAIL missing_params");
        exit;
    }
    $res = validate_ticket($ticket, $service);
    if ($res) {
        echo "yes\n".$res['user']."\n";
    } else {
        echo "no\n";
    }
    exit;
}

/** Emit <cas:attributes> with child elements named after each attribute.
 *  Multivalues: split on ';' or honor arrays by repeating child tag. */
function emit_attributes_named_tags(array $attrs) {
    if (empty($attrs)) return;
    echo "    <cas:attributes>\n";
    foreach ($attrs as $name => $value) {
        $tag = preg_replace('/[^A-Za-z0-9_:-]/', '_', (string)$name); // defensive
        $values = is_array($value) ? $value : preg_split('/\s*;\s*/', (string)$value, -1, PREG_SPLIT_NO_EMPTY);
        if (!$values) $values = [(string)$value];
        foreach ($values as $v) {
            $v = (string)$v;
            echo "      <cas:{$tag}>".htmlspecialchars($v, ENT_QUOTES, 'UTF-8')."</cas:{$tag}>\n";
        }
    }
    echo "    </cas:attributes>\n";
}

/** Core XML renderer used by both v2 and p3 serviceValidate */
function render_service_validate_xml($ticket, $service, $version_label = 'v2') {
    send_security_headers();
    header('Content-Type: text/xml; charset=UTF-8');

    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    echo "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>\n";

    if (!$ticket || !$service) {
        echo "  <cas:authenticationFailure code='INVALID_REQUEST'>Missing service or ticket</cas:authenticationFailure>\n";
        echo "</cas:serviceResponse>";
        qlog("serviceValidate {$version_label} FAIL missing_params");
        exit;
    }

    $res = validate_ticket($ticket, $service);
    if ($res) {
        $user  = $res['user'];
        $attrs = $res['attrs'] ?? [];
        echo "  <cas:authenticationSuccess>\n";
        echo "    <cas:user>".htmlspecialchars($user, ENT_QUOTES, 'UTF-8')."</cas:user>\n";
        if (!empty($attrs)) {
            emit_attributes_named_tags($attrs);
        }
        echo "  </cas:authenticationSuccess>\n";
        qlog("serviceValidate {$version_label} OK ticket=$ticket user=$user attrs=".count($attrs));
    } else {
        echo "  <cas:authenticationFailure code='INVALID_TICKET'>Ticket ".htmlspecialchars($ticket, ENT_QUOTES, 'UTF-8')." not recognized</cas:authenticationFailure>\n";
        qlog("serviceValidate {$version_label} FAIL invalid_ticket ticket=$ticket");
    }
    echo "</cas:serviceResponse>";
    exit;
}

function run_serviceValidate() {
    $ticket  = $_GET['ticket']  ?? '';
    $service = $_GET['service'] ?? '';
    render_service_validate_xml($ticket, $service, 'v2');
}

// function run_p3_serviceValidate() {
//     $ticket  = $_GET['ticket']  ?? '';
//     $service = $_GET['service'] ?? '';
//     render_service_validate_xml($ticket, $service, 'p3');
// }

/* ===== CAS p3 helpers (put near your other helpers) ===== */

function xml_text($s) {
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

/** Make a safe XML element name (letters/underscore to start; then letters/digits/._-). */
function safe_tag($name) {
    $t = preg_replace('/[^A-Za-z0-9._-]/', '_', (string)$name);
    if ($t === '' || !preg_match('/^[A-Za-z_]/', $t)) $t = '_'.$t;
    return $t;
}

/** Emit one or more <cas:foo>value</cas:foo> for p3. Repeats tag for multi-values. */
function emit_p3_attribute_tags($name, $value) {
    $tag = safe_tag($name);
    // Split semicolon lists into multiple tags (affiliation, etc.)
    $values = is_array($value) ? $value : preg_split('/\s*;\s*/', (string)$value, -1, PREG_SPLIT_NO_EMPTY);
    if (!$values) $values = [(string)$value];
    foreach ($values as $v) {
        echo '      <cas:' . $tag . '>' . xml_text($v) . '</cas:' . $tag . '>' . "\n";
    }
}

/* ===== CAS p3 endpoint ===== */

function run_p3_serviceValidate() {
    send_security_headers();
    header('Content-Type: text/xml; charset=UTF-8');

    $ticket  = $_GET['ticket']  ?? '';
    $service = $_GET['service'] ?? '';

    // XML MUST start at the very first byte — no BOM/whitespace before this echo.
    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    echo "<cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\">\n";

    if (!$ticket || !$service) {
        echo "  <cas:authenticationFailure code=\"INVALID_REQUEST\">Missing service or ticket</cas:authenticationFailure>\n";
        echo "</cas:serviceResponse>";
        qlog("p3 serviceValidate FAIL missing_params");
        exit;
    }

    // Validate + consume ticket
    $res = validate_ticket($ticket, $service);
    if (!$res) {
        echo "  <cas:authenticationFailure code=\"INVALID_TICKET\">Ticket " . xml_text($ticket) . " not recognized</cas:authenticationFailure>\n";
        echo "</cas:serviceResponse>";
        qlog("p3 serviceValidate FAIL invalid_ticket ticket=$ticket");
        exit;
    }

    $user  = $res['user'];
    $attrs = $res['attrs'] ?? [];

    echo "  <cas:authenticationSuccess>\n";
    echo "    <cas:user>" . xml_text($user) . "</cas:user>\n";
    echo "    <cas:attributes>\n";
    foreach ($attrs as $k => $v) {
        emit_p3_attribute_tags($k, $v);
    }
    echo "    </cas:attributes>\n";
    echo "  </cas:authenticationSuccess>\n";
    echo "</cas:serviceResponse>";
    qlog("p3 serviceValidate OK ticket=$ticket user=$user attrs=" . count($attrs));
    exit;
}

/* =========================
 * Optional index.php dispatcher
 * ========================= */
if (basename($_SERVER['SCRIPT_NAME']) === 'index.php') {
    $path = $_SERVER['PATH_INFO'] ?? ($_GET['action'] ?? '');
    if ($path === '' || $path === '/') {
        send_security_headers();
        header('Content-Type: text/plain; charset=UTF-8');
        echo "quick-cas proxy is live.\n";
        echo "Use /index.php/login, /index.php/validate,\n";
        echo "    /index.php/serviceValidate, or /index.php/p3/serviceValidate\n";
        exit;
    }
    if ($path[0] !== '/') $path = '/'.$path;
    switch ($path) {
        case '/login':             run_login(); break;
        case '/validate':          run_validate(); break;
        case '/serviceValidate':   run_serviceValidate(); break;
        case '/p3/serviceValidate':run_p3_serviceValidate(); break;
        default:
            http_response_code(404);
            send_security_headers();
            header('Content-Type: text/plain; charset=UTF-8');
            echo "Unknown endpoint: $path\n";
            exit;
    }
}

// If you keep thin wrappers (login.php / validate.php / serviceValidate.php),
// they should simply include this file and call the corresponding run_*()
// and, optionally, you can add a p3 wrapper that calls run_p3_serviceValidate().
