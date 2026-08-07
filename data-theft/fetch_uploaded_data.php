<?php
header("Content-Type: application/json");

define("DNS_QUERY_LOG", "/var/log/named/query.log");
define("DNS_HOST_LOG", __DIR__ . "/uploads/dns-tunnel-hosts.log");
define("DNS_SUFFIX", "swgaudit.com");
define("MAX_LOOKBACK_SECONDS", 600);

try {
    $id = $_GET["id"] ?? "";

    if (!preg_match("/^[a-f0-9]{16}$/", $id)) {
        throw new Exception("Missing or invalid test ID");
    }

    $chunks = [];

    if (is_readable(DNS_QUERY_LOG)) {
        $recentLog = read_recent_dns_log(DNS_QUERY_LOG, MAX_LOOKBACK_SECONDS);
        if ($recentLog !== "") {
            $chunks = extract_dns_chunks($recentLog, $id);
        }
    }

    // DEV / IP-preview fallback: reconstruct from mirrored hostnames.
    if (!isset($chunks[0]) && is_readable(DNS_HOST_LOG)) {
        $hostLog = read_recent_dns_log(DNS_HOST_LOG, MAX_LOOKBACK_SECONDS);
        if ($hostLog !== "") {
            $chunks = extract_host_header_chunks($hostLog, $id);
        }
    }

    if (!isset($chunks[0])) {
        if (!is_readable(DNS_QUERY_LOG) && !is_readable(DNS_HOST_LOG)) {
            throw new Exception("DNS query log is not readable");
        }
        throw new Exception("Invalid or missing metadata in chunks");
    }

    $metadata = json_decode(base32_decode_dns($chunks[0]), true);
    if (!is_array($metadata)) {
        throw new Exception("Invalid or missing metadata in chunks");
    }

    $filenameFromMetadata = $metadata["name"] ?? $metadata["n"] ?? "";
    $typeFromMetadata = $metadata["type"] ?? $metadata["t"] ?? "";
    $sizeFromMetadata = $metadata["size"] ?? $metadata["s"] ?? null;
    $totalDataChunks = (int)($metadata["totalDataChunks"] ?? $metadata["c"] ?? 0);
    $encodedLength = $metadata["encodedLength"] ?? $metadata["l"] ?? null;

    if ($filenameFromMetadata === "") {
        throw new Exception("Invalid or missing metadata in chunks");
    }

    if ($totalDataChunks < 1) {
        throw new Exception("Invalid metadata chunk count");
    }

    $encodedData = "";
    $missing = [];
    for ($chunkNumber = 1; $chunkNumber <= $totalDataChunks; $chunkNumber++) {
        if (!isset($chunks[$chunkNumber])) {
            $missing[] = $chunkNumber;
            continue;
        }
        $encodedData .= $chunks[$chunkNumber];
    }

    if ($missing !== []) {
        $receivedDataChunks = $totalDataChunks - count($missing);
        echo json_encode([
            "success" => false,
            "partial" => $receivedDataChunks > 0,
            "receivedChunks" => $receivedDataChunks,
            "totalDataChunks" => $totalDataChunks,
            "blockedChunks" => count($missing),
            "message" => $receivedDataChunks > 0
                ? "Partial transmission: " . $receivedDataChunks . " of " . $totalDataChunks . " data chunks reached the server"
                : "No data chunks reached the server",
        ]);
        exit;
    }

    if ($encodedLength !== null && strlen($encodedData) !== (int)$encodedLength) {
        echo json_encode([
            "success" => false,
            "partial" => strlen($encodedData) > 0,
            "receivedChunks" => $totalDataChunks,
            "totalDataChunks" => $totalDataChunks,
            "blockedChunks" => 0,
            "message" => "Incomplete transmission: reconstructed encoded data length does not match original",
        ]);
        exit;
    }

    $fileData = base32_decode_dns($encodedData);
    if ($sizeFromMetadata !== null && strlen($fileData) !== (int)$sizeFromMetadata) {
        echo json_encode([
            "success" => false,
            "partial" => strlen($encodedData) > 0,
            "receivedChunks" => $totalDataChunks,
            "totalDataChunks" => $totalDataChunks,
            "blockedChunks" => 0,
            "message" => "Incomplete transmission: reconstructed file size does not match original",
        ]);
        exit;
    }

    $uploadsDir = __DIR__ . "/uploads";
    if (!is_dir($uploadsDir) && !mkdir($uploadsDir, 0750, true)) {
        throw new Exception("Failed to create upload directory");
    }

    $filename = preg_replace("/[^a-zA-Z0-9_.-]/", "_", basename($filenameFromMetadata));
    $filepath = $uploadsDir . "/" . uniqid("", true) . "_" . $filename;

    if (file_put_contents($filepath, $fileData) === false) {
        throw new Exception("Failed to save reconstructed file");
    }

    echo json_encode([
        "success" => true,
        "message" => "File reconstructed successfully",
        "fileUrl" => "/data-theft/uploads/" . basename($filepath),
        "filename" => $filenameFromMetadata,
        "type" => $typeFromMetadata,
        "delete_after_minutes" => 10,
    ]);
} catch (Exception $exception) {
    echo json_encode([
        "success" => false,
        "message" => $exception->getMessage(),
    ]);
}

function read_recent_dns_log(string $path, int $lookbackSeconds): string
{
    $size = filesize($path);
    if ($size === false || $size === 0) {
        return "";
    }

    $fh = fopen($path, "rb");
    if ($fh === false) {
        return "";
    }

    $readBytes = min($size, 2_000_000);
    if ($size > $readBytes) {
        fseek($fh, -$readBytes, SEEK_END);
    }

    $data = stream_get_contents($fh);
    fclose($fh);
    if ($data === false || $data === "") {
        return "";
    }

    $cutoff = time() - $lookbackSeconds;
    $kept = [];
    foreach (explode("\n", $data) as $line) {
        if ($line === "") {
            continue;
        }
        if (preg_match('/^(\\d{2})-([A-Za-z]{3})-(\\d{4})\\s+(\\d{2}):(\\d{2}):(\\d{2})/', $line, $m)) {
            $ts = strtotime(sprintf("%s-%s-%s %s:%s:%s", $m[1], $m[2], $m[3], $m[4], $m[5], $m[6]));
            if ($ts !== false && $ts < $cutoff) {
                continue;
            }
        } elseif (preg_match('/^(\\d{10,})\\b/', $line, $m)) {
            if ((int)$m[1] < $cutoff) {
                continue;
            }
        }
        $kept[] = $line;
    }

    return $kept === [] ? $data : implode("\n", $kept);
}

function extract_dns_chunks(string $log, string $id): array
{
    $chunks = [];
    $pattern = "/\\b" . preg_quote($id, "/") . "\\.(\\d+)\\.([a-z0-9.]+)\\." . preg_quote(DNS_SUFFIX, "/") . "\\b/i";

    foreach (explode("\n", $log) as $line) {
        if (!preg_match($pattern, $line, $match)) {
            continue;
        }
        $chunkNumber = (int)$match[1];
        $labels = strtoupper(str_replace(".", "", $match[2]));
        if ($labels === "") {
            continue;
        }
        if (!isset($chunks[$chunkNumber])) {
            $chunks[$chunkNumber] = $labels;
        }
    }

    return $chunks;
}

function extract_host_header_chunks(string $log, string $id): array
{
    $chunks = [];
    $pattern = "/\\b" . preg_quote($id, "/") . "\\.(\\d+)\\.([A-Za-z0-9.-]+)/";

    foreach (explode("\n", $log) as $line) {
        if (!preg_match($pattern, $line, $match)) {
            continue;
        }
        $chunkNumber = (int)$match[1];
        $rest = $match[2];
        $rest = preg_replace("/(?:\\.\\d{1,3}){4}\\.sslip\\.io$/i", "", $rest);
        $rest = preg_replace("/\\.swgaudit\\.com$/i", "", $rest);
        $labels = strtoupper(str_replace(".", "", $rest));
        if ($labels === "") {
            continue;
        }
        if (!isset($chunks[$chunkNumber])) {
            $chunks[$chunkNumber] = $labels;
        }
    }

    return $chunks;
}

function base32_decode_dns(string $input): string
{
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    $input = strtoupper(preg_replace("/[^A-Z2-7]/", "", $input));
    $buffer = 0;
    $bitsLeft = 0;
    $output = "";

    $length = strlen($input);
    for ($i = 0; $i < $length; $i++) {
        $val = strpos($alphabet, $input[$i]);
        if ($val === false) {
            continue;
        }
        $buffer = ($buffer << 5) | $val;
        $bitsLeft += 5;
        if ($bitsLeft >= 8) {
            $bitsLeft -= 8;
            $output .= chr(($buffer >> $bitsLeft) & 0xFF);
        }
    }

    return $output;
}
