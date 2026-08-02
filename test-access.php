<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

const CONFIG_FILE = '/etc/swgaudit-v2/recaptcha.php';
const INTEGRATION_CONFIG_FILE = '/etc/swgaudit-v2/integrations.php';
const STORAGE_DIR = '/var/lib/swgaudit-v3';
const TOKEN_FILE = STORAGE_DIR . '/test-access-tokens.json';
const VISITOR_FILE = STORAGE_DIR . '/visitor-submissions.csv';
const TOKEN_TTL = 43200;

function respond(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

function loadConfig(): array
{
    if (!is_file(CONFIG_FILE)) respond(['error' => 'reCAPTCHA is not configured.'], 503);
    $config = require CONFIG_FILE;
    if (!is_array($config) || empty($config['site_key']) || empty($config['secret_key'])) {
        respond(['error' => 'reCAPTCHA is not configured.'], 503);
    }
    return $config;
}

function ensureStorage(): void
{
    if (!is_dir(STORAGE_DIR) && !mkdir(STORAGE_DIR, 0700, true) && !is_dir(STORAGE_DIR)) {
        respond(['error' => 'Submission storage is unavailable.'], 503);
    }
}

function readActiveTokens($handle): array
{
    rewind($handle);
    $records = json_decode((string) stream_get_contents($handle), true);
    if (!is_array($records)) $records = [];
    return array_values(array_filter($records, static fn ($record): bool => is_array($record)
        && isset($record['token_hash'], $record['email'], $record['expires_at'])
        && (int) $record['expires_at'] >= time()));
}

function writeTokens($handle, array $records): void
{
    rewind($handle);
    ftruncate($handle, 0);
    fwrite($handle, json_encode($records, JSON_UNESCAPED_SLASHES));
    fflush($handle);
}

function tokenRecord(string $token): ?array
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) return null;
    ensureStorage();
    $handle = @fopen(TOKEN_FILE, 'c+b');
    if ($handle === false || !flock($handle, LOCK_EX)) {
        if (is_resource($handle)) fclose($handle);
        return null;
    }
    $records = readActiveTokens($handle);
    $hash = hash('sha256', $token);
    $found = null;
    foreach ($records as $record) {
        if (hash_equals((string) $record['token_hash'], $hash)) {
            $found = $record;
            break;
        }
    }
    writeTokens($handle, $records);
    flock($handle, LOCK_UN);
    fclose($handle);
    return $found;
}

function rememberVisitor(string $email): ?array
{
    ensureStorage();
    $handle = @fopen(TOKEN_FILE, 'c+b');
    if ($handle === false || !flock($handle, LOCK_EX)) {
        if (is_resource($handle)) fclose($handle);
        return null;
    }
    $records = readActiveTokens($handle);
    $token = bin2hex(random_bytes(32));
    $record = [
        'token_hash' => hash('sha256', $token),
        'email' => $email,
        'expires_at' => time() + TOKEN_TTL,
    ];
    $records[] = $record;
    writeTokens($handle, $records);
    flock($handle, LOCK_UN);
    fclose($handle);
    return ['token' => $token, 'token_hash' => $record['token_hash']];
}

function clientIp(): string
{
    $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    return filter_var($ip, FILTER_VALIDATE_IP) === false ? '' : $ip;
}

function lookupLocation(string $ip): array
{
    if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return ['country' => '', 'region' => '', 'city' => ''];
    }
    $curl = curl_init('https://ipwho.is/' . rawurlencode($ip));
    if ($curl === false) return ['country' => '', 'region' => '', 'city' => ''];
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
    ]);
    $body = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    curl_close($curl);
    $result = is_string($body) ? json_decode($body, true) : null;
    if ($status !== 200 || !is_array($result) || empty($result['success'])) {
        return ['country' => '', 'region' => '', 'city' => ''];
    }
    return [
        'country' => substr(trim((string) ($result['country'] ?? '')), 0, 100),
        'region' => substr(trim((string) ($result['region'] ?? '')), 0, 100),
        'city' => substr(trim((string) ($result['city'] ?? '')), 0, 100),
    ];
}

function safePage(mixed $value): string
{
    $page = substr(trim((string) $value), 0, 255);
    return str_starts_with($page, '/') ? explode('?', $page, 2)[0] : '/';
}

function recordsFromCsv($handle): array
{
    rewind($handle);
    $rows = [];
    while (($row = fgetcsv($handle)) !== false) $rows[] = $row;
    return $rows;
}

function testNames(array $tests): string
{
    return implode(' | ', array_keys($tests));
}

function saveVisitor(array $visitor): bool
{
    ensureStorage();
    $handle = @fopen(VISITOR_FILE, 'c+b');
    if ($handle === false || !flock($handle, LOCK_EX)) {
        if (is_resource($handle)) fclose($handle);
        return false;
    }
    $header = ['visitor_id', 'submitted_at_utc', 'updated_at_utc', 'work_email', 'ip_address', 'country', 'region', 'city', 'first_page', 'tests_performed', 'test_names'];
    $rows = recordsFromCsv($handle);
    $newRow = [
        $visitor['visitor_id'], $visitor['submitted_at'], $visitor['updated_at'], $visitor['email'], $visitor['ip'],
        $visitor['country'], $visitor['region'], $visitor['city'], $visitor['first_page'], count($visitor['tests']), testNames($visitor['tests']),
    ];
    $replaced = false;
    foreach ($rows as $index => $row) {
        if ($index > 0 && ($row[0] ?? '') === $visitor['visitor_id']) {
            $rows[$index] = $newRow;
            $replaced = true;
            break;
        }
    }
    if (!$replaced) {
        if ($rows === []) $rows[] = $header;
        $rows[] = $newRow;
    }
    rewind($handle);
    ftruncate($handle, 0);
    foreach ($rows as $row) fputcsv($handle, $row);
    fflush($handle);
    flock($handle, LOCK_UN);
    fclose($handle);
    return true;
}

function syncSubmissionToGoogleSheet(array $visitor): void
{
    if (!is_file(INTEGRATION_CONFIG_FILE)) return;
    $config = require INTEGRATION_CONFIG_FILE;
    $url = is_array($config) ? (string) ($config['google_sheets_webhook_url'] ?? '') : '';
    $secret = is_array($config) ? (string) ($config['google_sheets_webhook_secret'] ?? '') : '';
    if ($url === '' || $secret === '') return;
    $curl = curl_init($url);
    if ($curl === false) return;
    curl_setopt_array($curl, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode([
            'secret' => $secret,
            'visitor_id' => $visitor['visitor_id'],
            'email' => $visitor['email'],
            'ip_address' => $visitor['ip'],
            'country' => $visitor['country'],
            'region' => $visitor['region'],
            'city' => $visitor['city'],
            'page' => $visitor['first_page'],
            'submitted_at' => $visitor['submitted_at'],
            'updated_at' => $visitor['updated_at'],
            'tests_performed' => count($visitor['tests']),
            'test_names' => testNames($visitor['tests']),
        ], JSON_UNESCAPED_SLASHES),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_HTTPHEADER => ['Accept: application/json', 'Content-Type: application/json'],
    ]);
    curl_exec($curl);
    curl_close($curl);
}

function verifyRecaptcha(string $secret, string $response, string $remoteIp): bool
{
    $curl = curl_init('https://www.google.com/recaptcha/api/siteverify');
    if ($curl === false) return false;
    curl_setopt_array($curl, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query(['secret' => $secret, 'response' => $response, 'remoteip' => $remoteIp]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
    ]);
    $body = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    curl_close($curl);
    $result = is_string($body) ? json_decode($body, true) : null;
    return $status === 200 && is_array($result) && !empty($result['success'])
        && in_array(strtolower((string) ($result['hostname'] ?? '')), ['www.swgaudit.com', 'swgaudit.com'], true);
}

$config = loadConfig();
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $token = trim((string) ($_GET['token'] ?? ''));
    respond(['site_key' => (string) $config['site_key'], 'email_remembered' => $token !== '' && tokenRecord($token) !== null]);
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: GET, POST');
    respond(['error' => 'Method not allowed.'], 405);
}
$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
$payload = str_contains($contentType, 'application/json') ? json_decode((string) file_get_contents('php://input'), true) : $_POST;
if (!is_array($payload) || !empty($payload['company'])) respond(['error' => 'Invalid submission.'], 400);

$action = (string) ($payload['action'] ?? 'verify');
if ($action === 'activity') {
    $token = trim((string) ($payload['token'] ?? ''));
    $tokenData = tokenRecord($token);
    if ($tokenData === null) respond(['error' => 'Verification expired.'], 401);
    $visitor = $tokenData['visitor'] ?? null;
    if (!is_array($visitor)) respond(['error' => 'Visitor record unavailable.'], 409);
    $test = safePage($payload['test'] ?? '/');
    $outcome = (string) ($payload['outcome'] ?? 'completed');
    if (!in_array($outcome, ['passed', 'failed', 'completed'], true)) $outcome = 'completed';
    $visitor['tests'][$test] = ['outcome' => $outcome, 'completed_at' => gmdate('c')];
    $visitor['updated_at'] = gmdate('c');
    $tokenData['visitor'] = $visitor;
    // Keep the activity record available for the remainder of the verified session.
    ensureStorage();
    $handle = fopen(TOKEN_FILE, 'c+b');
    if ($handle === false || !flock($handle, LOCK_EX)) respond(['error' => 'Submission storage is unavailable.'], 503);
    $records = readActiveTokens($handle);
    foreach ($records as &$record) {
        if (hash_equals((string) $record['token_hash'], (string) $tokenData['token_hash'])) $record['visitor'] = $visitor;
    }
    unset($record);
    writeTokens($handle, $records);
    flock($handle, LOCK_UN);
    fclose($handle);
    if (!saveVisitor($visitor)) respond(['error' => 'We could not save your activity.'], 503);
    syncSubmissionToGoogleSheet($visitor);
    respond(['ok' => true]);
}

$email = strtolower(trim((string) ($payload['email'] ?? '')));
if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    respond(['error' => 'Enter a valid work email address.', 'email_required' => true], 422);
}
$recaptchaResponse = trim((string) ($payload['recaptcha_response'] ?? ''));
if ($recaptchaResponse === '') respond(['error' => 'Complete the reCAPTCHA challenge.'], 422);
$ip = clientIp();
if (!verifyRecaptcha((string) $config['secret_key'], $recaptchaResponse, $ip)) {
    respond(['error' => 'reCAPTCHA verification failed. Please try again.'], 422);
}
$session = rememberVisitor($email);
if ($session === null) respond(['error' => 'We could not remember this browser. Please try again shortly.'], 503);
$location = lookupLocation($ip);
$now = gmdate('c');
$visitor = [
    'visitor_id' => substr((string) $session['token_hash'], 0, 24), 'email' => $email, 'ip' => $ip,
    'country' => $location['country'], 'region' => $location['region'], 'city' => $location['city'],
    'first_page' => safePage($payload['page'] ?? '/'), 'submitted_at' => $now, 'updated_at' => $now, 'tests' => [],
];
// Persist visitor data against the session token without storing the token itself.
$handle = fopen(TOKEN_FILE, 'c+b');
if ($handle === false || !flock($handle, LOCK_EX)) respond(['error' => 'Submission storage is unavailable.'], 503);
$records = readActiveTokens($handle);
foreach ($records as &$record) {
    if (hash_equals((string) $record['token_hash'], (string) $session['token_hash'])) $record['visitor'] = $visitor;
}
unset($record);
writeTokens($handle, $records);
flock($handle, LOCK_UN);
fclose($handle);
if (!saveVisitor($visitor)) respond(['error' => 'We could not save your submission. Please try again shortly.'], 503);
syncSubmissionToGoogleSheet($visitor);
respond(['verified' => true, 'token' => $session['token']]);
