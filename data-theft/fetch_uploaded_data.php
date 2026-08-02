<?php
header("Content-Type: application/json");

const DNS_QUERY_LOG = "/var/log/named/query.log";
const DNS_SUFFIX = "swgaudit.com";
const MAX_LOOKBACK_SECONDS = 600;

try {
    $id = $_GET["id"] ?? "";

    if (!preg_match("/^[a-f0-9]{16}$/", $id)) {
        throw new Exception("Missing or invalid test ID");
    }

    if (!is_readable(DNS_QUERY_LOG)) {
        throw new Exception("DNS query log is not readable");
    }

    $recentLog = read_recent_dns_log(DNS_QUERY_LOG, MAX_LOOKBACK_SECONDS);
    if ($recentLog === "") {
        echo json_encode(["success" => false, "message" => "No recent DNS queries found"]);
        exit;
    }

    $chunks = extract_dns_chunks($recentLog, $id);

    if (!isset($chunks[0])) {
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
        "message" => "Error processing data: " . $exception->getMessage(),
    ]);
}

function read_recent_dns_log($path, $lookbackSeconds) {
    $lines = file($path, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return "";
    }

    $cutoff = time() - $lookbackSeconds;
    $recentLines = [];

    foreach ($lines as $line) {
        $timestamp = strtotime(substr($line, 0, 20));
        if ($timestamp !== false && $timestamp >= $cutoff) {
            $recentLines[] = $line;
        }
    }

    return implode("\n", $recentLines);
}

function extract_dns_chunks($log, $id) {
    $escapedId = preg_quote($id, "/");
    $escapedSuffix = preg_quote(DNS_SUFFIX, "/");
    $recordTypes = "(?:A|AAAA|HTTPS|SVCB)";
    $pattern = "/queries: info: client @\\S+ [^#]+#\\d+ \\(" . $escapedId . "\\.(\\d+)\\.([A-Z2-7.]+)\\." . $escapedSuffix . "\\): query: " . $escapedId . "\\.\\1\\.\\2\\." . $escapedSuffix . " IN " . $recordTypes . "\\b/i";
    preg_match_all($pattern, $log, $matches, PREG_SET_ORDER);

    $chunks = [];
    foreach ($matches as $match) {
        $chunkNumber = (int)$match[1];
        if (!isset($chunks[$chunkNumber])) {
            $chunks[$chunkNumber] = strtoupper(str_replace(".", "", $match[2]));
        }
    }

    ksort($chunks);
    return $chunks;
}

function base32_decode_dns($input) {
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    $input = preg_replace("/[^A-Z2-7]/", "", strtoupper($input));
    $output = "";
    $value = 0;
    $bits = 0;

    for ($i = 0; $i < strlen($input); $i++) {
        $index = strpos($alphabet, $input[$i]);
        if ($index === false) {
            continue;
        }

        $value = ($value << 5) | $index;
        $bits += 5;

        while ($bits >= 8) {
            $output .= chr(($value >> ($bits - 8)) & 255);
            $bits -= 8;
        }
    }

    return $output;
}
