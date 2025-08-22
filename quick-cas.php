<?php
#!/usr/bin/env php

// quick-cas-proxy: Unified CAS endpoint router using index.php dispatcher mode
// Author: Jérémie Lumbroso
// License: MPL-2.0

// Configuration
const STORAGE_TYPE = 'FILE'; // or 'SQLITE'
const TICKET_PREFIX = '/tmp/cas_ticket_';
const SQLITE_PATH = '/tmp/quickcas.db';
const TICKET_TTL = 300; // seconds

// ----- STORAGE LAYER -----
function store_ticket($ticket, $user) {
    if (STORAGE_TYPE === 'SQLITE') {
        $db = new PDO("sqlite:" . SQLITE_PATH);
        $db->exec("CREATE TABLE IF NOT EXISTS tickets (ticket TEXT PRIMARY KEY, user TEXT NOT NULL, issued_at INTEGER NOT NULL)");
        $stmt = $db->prepare("INSERT INTO tickets (ticket, user, issued_at) VALUES (?, ?, ?)");
        $stmt->execute([$ticket, $user, time()]);
    } else {
        file_put_contents(TICKET_PREFIX . $ticket, $user . "\n" . time());
    }
}

function validate_ticket($ticket) {
    if (STORAGE_TYPE === 'SQLITE') {
        $db = new PDO("sqlite:" . SQLITE_PATH);
        $stmt = $db->prepare("SELECT user, issued_at FROM tickets WHERE ticket = ?");
        $stmt->execute([$ticket]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row || (time() - (int)$row['issued_at']) > TICKET_TTL) return false;
        $db->prepare("DELETE FROM tickets WHERE ticket = ?")->execute([$ticket]);
        return $row['user'];
    } else {
        $path = TICKET_PREFIX . $ticket;
        if (!file_exists($path)) return false;
        [$user, $ts] = explode("\n", file_get_contents($path));
        if (time() - (int)$ts > TICKET_TTL) {
            unlink($path);
            return false;
        }
        unlink($path);
        return $user;
    }
}

// ----- CAS ENDPOINTS -----
function run_login() {
    $service = $_GET['service'] ?? '';
    if (!$service) {
        http_response_code(400);
        echo "Missing 'service' parameter.";
        exit;
    }
    $user = $_SERVER['REMOTE_USER'] ?? null;
    if (!$user) {
        http_response_code(403);
        echo "User not authenticated.";
        exit;
    }
    $ticket = 'ST-' . bin2hex(random_bytes(16));
    store_ticket($ticket, $user);
    header("Location: {$service}?ticket={$ticket}");
    exit;
}

function run_validate() {
    $ticket = $_GET['ticket'] ?? '';
    $service = $_GET['service'] ?? '';
    if (!$ticket || !$service) {
        echo "no\n";
        exit;
    }
    $user = validate_ticket($ticket);
    echo $user ? "yes\n$user\n" : "no\n";
    exit;
}

function run_serviceValidate() {
    header('Content-Type: text/xml');
    $ticket = $_GET['ticket'] ?? '';
    $service = $_GET['service'] ?? '';
    if (!$ticket || !$service) {
        echo "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'><cas:authenticationFailure code='INVALID_REQUEST'>Missing service or ticket</cas:authenticationFailure></cas:serviceResponse>";
        exit;
    }
    $user = validate_ticket($ticket);
    if ($user) {
        echo "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'><cas:authenticationSuccess><cas:user>{$user}</cas:user>";
        // Forward Shibboleth attributes if available
        $attrs = ['givenName', 'sn', 'displayName', 'mail', 'employeeNumber', 'affiliation', 'unscoped_affiliation'];
        foreach ($attrs as $attr) {
            if (!empty($_SERVER[$attr])) {
                echo "<cas:attribute name=\"$attr\">" . htmlspecialchars($_SERVER[$attr]) . "</cas:attribute>";
            }
        }
        echo "</cas:authenticationSuccess></cas:serviceResponse>";
    } else {
        echo "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'><cas:authenticationFailure code='INVALID_TICKET'>Ticket {$ticket} not recognized</cas:authenticationFailure></cas:serviceResponse>";
    }
    exit;
}

// ----- DISPATCH FROM index.php (optional) -----
if (basename($_SERVER['SCRIPT_NAME']) === 'index.php') {
    $path = $_SERVER['PATH_INFO'] ?? ($_GET['action'] ?? '');
    if ($path[0] !== '/') $path = '/' . $path;

    switch ($path) {
        case '/login': run_login(); break;
        case '/validate': run_validate(); break;
        case '/serviceValidate': run_serviceValidate(); break;
        default:
            http_response_code(404);
            echo "Unknown path: $path\n";
            exit;
    }
}
?>
