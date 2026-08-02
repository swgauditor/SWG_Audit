<?php
declare(strict_types=1);

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

$username = isset($_POST['swg_audit_username'])
    ? trim((string) $_POST['swg_audit_username'])
    : trim((string) ($_POST['username'] ?? ''));
$password = isset($_POST['swg_audit_password'])
    ? (string) $_POST['swg_audit_password']
    : (string) ($_POST['password'] ?? '');

if ($username === '' || $password === '') {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Username and password are required.']);
    exit;
}

echo json_encode([
    'success' => true,
    'received' => true,
    'discarded' => true,
]);
