<?php
/**
 * DEV helper for IP-preview DNS tunneling.
 * Mirrors DNS-shaped hostnames into a writable collector log (and optional local dig).
 */
header("Content-Type: application/json");
header("Cache-Control: no-store");

$name = $_GET["name"] ?? "";
$name = strtolower(trim($name));

if ($name === "" || strlen($name) > 253 || !preg_match('/^[a-z0-9.-]+$/', $name)) {
    http_response_code(400);
    echo json_encode(["success" => false, "message" => "Invalid name"]);
    exit;
}

$uploadsDir = __DIR__ . "/uploads";
if (!is_dir($uploadsDir) && !mkdir($uploadsDir, 0770, true)) {
    http_response_code(500);
    echo json_encode(["success" => false, "message" => "Upload directory unavailable"]);
    exit;
}

$log = $uploadsDir . "/dns-tunnel-hosts.log";
$line = sprintf("%d %s\n", time(), $name);
if (file_put_contents($log, $line, FILE_APPEND | LOCK_EX) === false) {
    http_response_code(500);
    echo json_encode(["success" => false, "message" => "Failed to record hostname"]);
    exit;
}

// Best-effort: also ask local named so classic query.log may contain the name.
$cmd = "dig @127.0.0.1 +time=1 +tries=1 +short " . escapeshellarg($name) . " A 2>/dev/null";
@shell_exec($cmd);

echo json_encode(["success" => true]);
