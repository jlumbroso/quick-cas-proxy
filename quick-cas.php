<?php
// CONFIGURATION
const STORAGE_TYPE = 'FILE'; // or 'SQLITE'
const TICKET_PREFIX = '/tmp/cas_ticket_';
const SQLITE_PATH = '/tmp/quickcas.db';
const TICKET_TTL = 300; // seconds

// Ticket Storage Abstraction
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

// login.php
if (basename($_SERVER['SCRIPT_NAME']) === 'login.php') {
    $service = $_GET['service'] ?? '';
    if (!$service) die("Missing 'service' parameter.");
    $user = $_SERVER['REMOTE_USER'] ?? null;
    if (!$user) die("User not authenticated.");

    $ticket = 'ST-' . bin2hex(random_bytes(16));
    store_ticket($ticket, $user);
    header("Location: {$service}?ticket={$ticket}");
    exit;
}

// validate.php
if (basename($_SERVER['SCRIPT_NAME']) === 'validate.php') {
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

// serviceValidate.php
if (basename($_SERVER['SCRIPT_NAME']) === 'serviceValidate.php') {
    header('Content-Type: text/xml');
    $ticket = $_GET['ticket'] ?? '';
    $service = $_GET['service'] ?? '';
    if (!$ticket || !$service) {
        echo "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'><cas:authenticationFailure code='INVALID_REQUEST'>Missing service or ticket</cas:authenticationFailure></cas:serviceResponse>";
        exit;
    }
    $user = validate_ticket($ticket);
    if ($user) {
        echo "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'><cas:authenticationSuccess><cas:user>{$user}</cas:user></cas:authenticationSuccess></cas:serviceResponse>";
    } else {
        echo "<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'><cas:authenticationFailure code='INVALID_TICKET'>Ticket {$ticket} not recognized</cas:authenticationFailure></cas:serviceResponse>";
    }
    exit;
}
?>
