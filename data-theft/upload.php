<?php
declare(strict_types=1);

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

if (!isset($_FILES['personal_data_file']) || !is_array($_FILES['personal_data_file'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'No file was uploaded.']);
    exit;
}

$file = $_FILES['personal_data_file'];
if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Upload failed.']);
    exit;
}

$uploadDir = __DIR__ . '/uploads';
if (!is_dir($uploadDir) && !mkdir($uploadDir, 0750, true)) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Unable to prepare upload directory.']);
    exit;
}

$original = basename((string) ($file['name'] ?? 'uploaded-file'));
$safeName = preg_replace('/[^A-Za-z0-9._-]+/', '-', $original);
$safeName = trim((string) $safeName, '.-');
if ($safeName === '') {
    $safeName = 'uploaded-file';
}

$storedName = sprintf('%s-%s', bin2hex(random_bytes(6)), $safeName);
$target = $uploadDir . '/' . $storedName;

if (!move_uploaded_file((string) $file['tmp_name'], $target)) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Unable to store uploaded file.']);
    exit;
}

chmod($target, 0640);

echo json_encode([
    'success' => true,
    'received' => true,
    'stored' => true,
    'fileUrl' => '/data-theft/uploads/' . rawurlencode($storedName),
    'delete_after_minutes' => 10,
]);
