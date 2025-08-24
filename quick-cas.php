<?php
/**
 * quick-cas.php — CAS-compatible shim over Shibboleth-protected PHP
 * Endpoints: login (issues ST), validate (CAS 1.0), serviceValidate (CAS 2.0 XML)
 * Storage: SQLITE (default) or FILE, with TTL and single-use tickets
 * Tickets are bound to the `service` and carry captured Shibboleth attributes
 */

define('LOG_ENABLED', true);          // toggle server-side logging
define('STORAGE_TYPE', 'SQLITE');     // 'SQLITE' or 'FILE'
define('TICKET_TTL', 300);            // seconds

// Where to persist data (hidden dir under $HOME by default)
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

// Attribute allowlist we capture at login and include in CAS 2.0 XML
const ATTR_KEYS = [
    'givenName','sn','displayName','mail','employeeNumber',
    'affiliation','unscoped_affiliation','eppn','pennname'
];

// Bootstrap dirs/files with secure perms
function ensure_dirs() {
    @umask(0077);
    @mkdir(QUICKCAS_BASE, 0700, true);
    @mkdir(TICKET_DIR, 0700, true);
    if (LOG_ENABLED && !is_file(LOG_PATH)) {
        @file_put_contents(LOG_PATH, "[".date('c')."] quick-cas boot\n", FILE_APPEND);
        @chmod(LOG_PATH, 0600);
    }
}
ensure_dirs();

function qlog($msg) {
    if (!LOG_ENABLED) return;
    @file_put_contents(LOG_PATH, "[".date('c')."] ".$msg."\n", FILE_APPEND);
}

// ---------- Storage (SQLITE/FILE) ----------

function sqlite_available() {
    return class_exists('PDO') && in_array('sqlite', PDO::getAvailableDrivers(), true);
}

function sqlite_db() {
    if (!sqlite_available()) {
        qlog("ERROR: SQLITE selected but PDO_SQLITE not available");
        http_response_code(500);
        exit("quick-cas: SQLITE driver not available; switch STORAGE_TYPE to FILE or enable pdo_sqlite");
    }
    $db = new PDO("sqlite:".SQLITE_PATH, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    // Create (new) table with attrs column
    $db->exec("CREATE TABLE IF NOT EXISTS tickets (
        ticket TEXT PRIMARY KEY,
        user TEXT NOT NULL,
        service TEXT NOT NULL,
        issued_at INTEGER NOT NULL,
        attrs TEXT
    )");
    // Migrate old table missing 'attrs'
    try { $db->exec("ALTER TABLE tickets ADD COLUMN attrs TEXT"); } catch (Exception $e) { /* already there */ }
    return $db;
}

/**
 * Store newly issued ticket with service binding and captured attrs.
 * $attrs is an associative array of allowed attributes.
 */
function store_ticket($ticket, $user, $service, array $attrs) {
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

/**
 * Validate & consume ticket; returns ['user'=>..., 'attrs'=>[...]] or false.
 */
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
    // user \n issued \n service \n json-attrs
    $parts = explode("\n", $content, 4);
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

// ---------- Endpoints ----------

function run_login() {
    $service = $_GET['service'] ?? '';
    if (!$service) {
        http_response_code(400);
        echo "Missing 'service' parameter.";
        qlog("login FAIL missing_service");
        exit;
    }
    $user = $_SERVER['REMOTE_USER'] ?? ($_SERVER['pennname'] ?? null);
    if (!$user) {
        http_response_code(403);
        echo "User not authenticated (Shibboleth REMOTE_USER missing).";
        qlog("login FAIL no_remote_user service=$service");
        exit;
    }
    // Capture Shibboleth attributes now (browser has Shib session here)
    $attrs = [];
    foreach (ATTR_KEYS as $k) {
        if (isset($_SERVER[$k]) && $_SERVER[$k] !== '') $attrs[$k] = (string)$_SERVER[$k];
    }

    $ticket = 'ST-'.bin2hex(random_bytes(16));
    store_ticket($ticket, $user, $service, $attrs);

    $redir = $service.(strpos($service, '?') === false ? '?' : '&')."ticket=".$ticket;
    qlog("login OK user=$user ticket=$ticket redirect=$redir");
    header("Location: ".$redir);
    exit;
}

function run_validate() {
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

function run_serviceValidate() {
    header('Content-Type: text/xml; charset=UTF-8');
    $ticket  = $_GET['ticket']  ?? '';
    $service = $_GET['service'] ?? '';

    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    echo "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>\n";

    if (!$ticket || !$service) {
        echo "  <cas:authenticationFailure code='INVALID_REQUEST'>Missing service or ticket</cas:authenticationFailure>\n";
        echo "</cas:serviceResponse>";
        qlog("serviceValidate FAIL missing_params");
        exit;
    }

    $res = validate_ticket($ticket, $service);
    if ($res) {
        $user  = $res['user'];
        $attrs = $res['attrs'] ?? [];
        echo "  <cas:authenticationSuccess>\n";
        echo "    <cas:user>".htmlspecialchars($user, ENT_QUOTES, 'UTF-8')."</cas:user>\n";
        foreach ($attrs as $name => $value) {
            // name is from allowlist; value may be multi-valued but we pass as-is
            echo "    <cas:attribute name=\"".htmlspecialchars($name, ENT_QUOTES, 'UTF-8')."\">"
                .htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8')
                ."</cas:attribute>\n";
        }
        echo "  </cas:authenticationSuccess>\n";
        qlog("serviceValidate OK ticket=$ticket user=$user attrs=".count($attrs));
    } else {
        echo "  <cas:authenticationFailure code='INVALID_TICKET'>Ticket ".htmlspecialchars($ticket, ENT_QUOTES, 'UTF-8')." not recognized</cas:authenticationFailure>\n";
        qlog("serviceValidate FAIL invalid_ticket ticket=$ticket");
    }
    echo "</cas:serviceResponse>";
    exit;
}

// ---------- index.php dispatcher support ----------
if (basename($_SERVER['SCRIPT_NAME']) === 'index.php') {
    $path = $_SERVER['PATH_INFO'] ?? ($_GET['action'] ?? '');
    if ($path === '' || $path === '/') {
        header('Content-Type: text/plain; charset=UTF-8');
        echo "quick-cas proxy is live.\n";
        echo "Use /index.php/login, /index.php/validate, or /index.php/serviceValidate\n";
        exit;
    }
    if ($path[0] !== '/') $path = '/'.$path;
    switch ($path) {
        case '/login':           run_login(); break;
        case '/validate':        run_validate(); break;
        case '/serviceValidate': run_serviceValidate(); break;
        default:
            http_response_code(404);
            header('Content-Type: text/plain; charset=UTF-8');
            echo "Unknown endpoint: $path\n";
            exit;
    }
}
