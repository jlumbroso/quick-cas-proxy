#!/usr/bin/env php
<?php
require_once 'quick-cas.php';

// Dispatch based on PATH_INFO or fallback
$path = $_SERVER['PATH_INFO'] ?? ($_GET['action'] ?? '');
if ($path === '') {
    echo "CAS proxy is live.\nUse /index.php/login, /validate, or /serviceValidate\n";
    exit;
}
if ($path[0] !== '/') $path = '/' . $path;

switch ($path) {
    case '/login': run_login(); break;
    case '/validate': run_validate(); break;
    case '/serviceValidate': run_serviceValidate(); break;
    default:
        http_response_code(404);
        echo "Unknown path: $path\n";
        break;
}