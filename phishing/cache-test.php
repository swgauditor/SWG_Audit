<?php

declare(strict_types=1);

const CACHE_TEST_STATE_TTL = 3600;

function failCacheTest(int $status, string $message): never
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo $message;
    exit;
}

$token = strtolower(trim((string) ($_GET['test'] ?? '')));

if (!preg_match('/\A[a-f0-9]{32}\z/', $token)) {
    failCacheTest(400, 'Invalid cache test identifier. Start the test from the Phishing catalog.');
}

$stateDirectory = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'swgaudit-cache-tests';

if (!is_dir($stateDirectory) && !mkdir($stateDirectory, 0700, true) && !is_dir($stateDirectory)) {
    failCacheTest(500, 'The cache test state directory could not be created.');
}

foreach (glob($stateDirectory . DIRECTORY_SEPARATOR . '*.prime') ?: [] as $oldStateFile) {
    $modifiedAt = filemtime($oldStateFile);
    if ($modifiedAt !== false && $modifiedAt < time() - CACHE_TEST_STATE_TTL) {
        @unlink($oldStateFile);
    }
}

$stateFile = $stateDirectory . DIRECTORY_SEPARATOR . $token . '.prime';
$stateHandle = @fopen($stateFile, 'x');
$isPrimeResponse = is_resource($stateHandle);

if ($isPrimeResponse) {
    fclose($stateHandle);
}

header('Content-Type: text/html; charset=utf-8');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex, nofollow');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'");

if (!$isPrimeResponse) {
    header('Cache-Control: no-store, max-age=0');
    header('X-SWG-Audit-Cache-Phase: changed');
    readfile(__DIR__ . '/rnicrosoft-Iogin/index.html');
    exit;
}

header('Cache-Control: no-store, max-age=0');
header('X-SWG-Audit-Cache-Phase: prime');
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SWG Audit Cache Test - Harmless Page</title>
  <style>
    * { box-sizing: border-box; }
    body {
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 24px;
      color: #f4f7fb;
      background: #090b10;
      font-family: Inter, system-ui, sans-serif;
    }
    main {
      width: min(620px, 100%);
      padding: clamp(28px, 7vw, 52px);
      border: 1px solid #303744;
      border-radius: 12px;
      background: #11151d;
      box-shadow: 0 24px 80px rgba(0, 0, 0, 0.45);
    }
    h1 { margin: 0; font-size: clamp(30px, 7vw, 48px); line-height: 1; }
    p { margin: 20px 0 0; color: #c8d0dc; font-size: 18px; line-height: 1.6; }
    strong { color: #fff; }
  </style>
</head>
<body>
  <main>
    <h1>Page not loaded</h1>
    <p>Click <strong>Refresh</strong> in your browser to try loading this page again.</p>
  </main>
</body>
</html>
