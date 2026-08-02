<?php
header("Content-Type: application/json");

const PATH_TUNNEL_MAX_FILE_BYTES = 204800;
const PATH_TUNNEL_MAX_CHUNK_BYTES = 4096;
const PATH_TUNNEL_MAX_CHUNKS = 1000;
const PATH_TUNNEL_MAX_AGE_SECONDS = 600;

try {
    if ($_SERVER["REQUEST_METHOD"] !== "GET") {
        http_response_code(405);
        throw new Exception("Unsupported request method");
    }

    cleanup_old_path_tunnel_tests();

    if (($_GET["status"] ?? "") === "1") {
        echo json_encode(handle_status_request($_GET["id"] ?? ""));
        exit;
    }

    [$id, $chunkNumber, $payload] = parse_path_chunk_request();
    echo json_encode(handle_chunk_request($id, $chunkNumber, $payload));
} catch (Exception $exception) {
    if (http_response_code() === 200) {
        http_response_code(400);
    }

    echo json_encode([
        "success" => false,
        "reconstructed" => false,
        "message" => $exception->getMessage(),
    ]);
}

function handle_chunk_request(string $id, int $chunkNumber, string $payload): array {
    validate_test_id($id);
    validate_chunk_number($chunkNumber);
    validate_base64url_payload($payload);

    if (strlen($payload) > PATH_TUNNEL_MAX_CHUNK_BYTES) {
        throw new Exception("Chunk payload is too large");
    }

    $testDir = get_test_dir($id, true);
    $chunkPath = get_chunk_path($testDir, $chunkNumber);

    if (file_put_contents($chunkPath, $payload, LOCK_EX) === false) {
        throw new Exception("Failed to store chunk");
    }

    $result = attempt_reconstruction($id, $testDir);

    return [
        "success" => true,
        "received" => true,
        "reconstructed" => $result["reconstructed"],
        "complete" => $result["reconstructed"],
        "chunkNumber" => $chunkNumber,
        "fileUrl" => $result["fileUrl"] ?? null,
    ];
}

function handle_status_request(string $id): array {
    validate_test_id($id);

    $testDir = get_test_dir($id, false);
    if (!is_dir($testDir)) {
        return [
            "success" => false,
            "reconstructed" => false,
            "message" => "No URL path chunks have reached the server for this test",
        ];
    }

    return attempt_reconstruction($id, $testDir);
}

function parse_path_chunk_request(): array {
    $pathInfo = $_SERVER["PATH_INFO"] ?? "";
    $path = trim($pathInfo, "/");

    if ($path === "") {
        $requestPath = parse_url($_SERVER["REQUEST_URI"] ?? "", PHP_URL_PATH);
        $marker = "/data-theft/path-tunnel.php/";
        $position = is_string($requestPath) ? strpos($requestPath, $marker) : false;

        if ($position !== false) {
            $path = substr($requestPath, $position + strlen($marker));
        }
    }

    $segments = array_map("rawurldecode", explode("/", trim($path, "/")));
    if (count($segments) !== 3 || $segments[0] === "" || $segments[1] === "" || $segments[2] === "") {
        throw new Exception("Missing path tunnel chunk segments");
    }

    if (!ctype_digit($segments[1])) {
        throw new Exception("Invalid chunk number");
    }

    return [$segments[0], (int)$segments[1], $segments[2]];
}

function attempt_reconstruction(string $id, string $testDir): array {
    $resultPath = $testDir . "/result.json";
    if (is_readable($resultPath)) {
        $storedResult = json_decode((string)file_get_contents($resultPath), true);
        if (is_array($storedResult)) {
            return $storedResult;
        }
    }

    $metadataPath = get_chunk_path($testDir, 0);
    if (!is_readable($metadataPath)) {
        return [
            "success" => false,
            "reconstructed" => false,
            "message" => "Metadata chunk has not reached the server",
        ];
    }

    $metadata = decode_metadata((string)file_get_contents($metadataPath));
    $missing = [];
    $encodedData = "";

    for ($chunkNumber = 1; $chunkNumber <= $metadata["totalDataChunks"]; $chunkNumber++) {
        $chunkPath = get_chunk_path($testDir, $chunkNumber);
        if (!is_readable($chunkPath)) {
            $missing[] = $chunkNumber;
            continue;
        }

        $chunk = trim((string)file_get_contents($chunkPath));
        validate_base64url_payload($chunk);
        $encodedData .= $chunk;
    }

    if ($missing !== []) {
        $receivedDataChunks = $metadata["totalDataChunks"] - count($missing);
        return [
            "success" => false,
            "reconstructed" => false,
            "partial" => $receivedDataChunks > 0,
            "receivedChunks" => $receivedDataChunks,
            "totalDataChunks" => $metadata["totalDataChunks"],
            "blockedChunks" => count($missing),
            "message" => "Incomplete transmission: missing " . count($missing) . " data chunk(s)",
        ];
    }

    if (strlen($encodedData) !== $metadata["encodedLength"]) {
        return [
            "success" => false,
            "reconstructed" => false,
            "partial" => strlen($encodedData) > 0,
            "receivedChunks" => $metadata["totalDataChunks"],
            "totalDataChunks" => $metadata["totalDataChunks"],
            "blockedChunks" => 0,
            "message" => "Incomplete transmission: encoded length mismatch",
        ];
    }

    $fileData = base64url_decode_path_tunnel($encodedData);
    if ($fileData === false || strlen($fileData) !== $metadata["size"]) {
        return [
            "success" => false,
            "reconstructed" => false,
            "partial" => strlen($encodedData) > 0,
            "receivedChunks" => $metadata["totalDataChunks"],
            "totalDataChunks" => $metadata["totalDataChunks"],
            "blockedChunks" => 0,
            "message" => "Incomplete transmission: reconstructed file size mismatch",
        ];
    }

    $uploadsDir = get_uploads_dir();
    $filename = sanitize_output_filename($metadata["name"]);
    $filepath = $uploadsDir . "/path-tunnel-" . gmdate("YmdHis") . "-" . bin2hex(random_bytes(6)) . "_" . $filename;

    if (file_put_contents($filepath, $fileData, LOCK_EX) === false) {
        throw new Exception("Failed to save reconstructed file");
    }

    $result = [
        "success" => true,
        "reconstructed" => true,
        "message" => "File reconstructed successfully",
        "fileUrl" => "/data-theft/uploads/" . basename($filepath),
        "filename" => $metadata["name"],
        "type" => $metadata["type"],
        "delete_after_minutes" => 10,
    ];

    file_put_contents($resultPath, json_encode($result), LOCK_EX);
    return $result;
}

function decode_metadata(string $payload): array {
    validate_base64url_payload($payload);
    $json = base64url_decode_path_tunnel($payload);
    $metadata = $json === false ? null : json_decode($json, true);

    if (!is_array($metadata)) {
        throw new Exception("Invalid metadata chunk");
    }

    $name = (string)($metadata["name"] ?? "");
    $type = (string)($metadata["type"] ?? "application/octet-stream");
    $size = (int)($metadata["size"] ?? 0);
    $totalDataChunks = (int)($metadata["totalDataChunks"] ?? 0);
    $encodedLength = (int)($metadata["encodedLength"] ?? 0);

    if ($name === "" || strlen($name) > 255) {
        throw new Exception("Invalid metadata filename");
    }

    if ($size < 1 || $size > PATH_TUNNEL_MAX_FILE_BYTES) {
        throw new Exception("Invalid metadata file size");
    }

    if ($totalDataChunks < 1 || $totalDataChunks > PATH_TUNNEL_MAX_CHUNKS) {
        throw new Exception("Invalid metadata chunk count");
    }

    $maxEncodedLength = (int)ceil(PATH_TUNNEL_MAX_FILE_BYTES / 3) * 4;
    if ($encodedLength < 1 || $encodedLength > $maxEncodedLength) {
        throw new Exception("Invalid metadata encoded length");
    }

    return [
        "name" => $name,
        "type" => $type !== "" ? $type : "application/octet-stream",
        "size" => $size,
        "totalDataChunks" => $totalDataChunks,
        "encodedLength" => $encodedLength,
    ];
}

function validate_test_id(string $id): void {
    if (!preg_match("/^[a-f0-9]{16}$/", $id)) {
        throw new Exception("Missing or invalid test ID");
    }
}

function validate_chunk_number(int $chunkNumber): void {
    if ($chunkNumber < 0 || $chunkNumber > PATH_TUNNEL_MAX_CHUNKS) {
        throw new Exception("Invalid chunk number");
    }
}

function validate_base64url_payload(string $payload): void {
    if ($payload === "" || !preg_match("/^[A-Za-z0-9_-]+$/", $payload)) {
        throw new Exception("Invalid URL path payload");
    }
}

function base64url_decode_path_tunnel(string $payload): string|false {
    $base64 = strtr($payload, "-_", "+/");
    $padding = strlen($base64) % 4;
    if ($padding > 0) {
        $base64 .= str_repeat("=", 4 - $padding);
    }

    return base64_decode($base64, true);
}

function get_uploads_dir(): string {
    $uploadsDir = __DIR__ . "/uploads";
    if (!is_dir($uploadsDir) && !mkdir($uploadsDir, 0750, true)) {
        throw new Exception("Failed to create upload directory");
    }

    return $uploadsDir;
}

function get_test_dir(string $id, bool $create): string {
    $testRoot = get_uploads_dir() . "/path-tunnel";
    if (!is_dir($testRoot) && !mkdir($testRoot, 0750, true)) {
        throw new Exception("Failed to create path tunnel directory");
    }

    $testDir = $testRoot . "/" . $id;
    if ($create && !is_dir($testDir) && !mkdir($testDir, 0750, true)) {
        throw new Exception("Failed to create test directory");
    }

    return $testDir;
}

function get_chunk_path(string $testDir, int $chunkNumber): string {
    return $testDir . "/chunk-" . str_pad((string)$chunkNumber, 6, "0", STR_PAD_LEFT) . ".txt";
}

function sanitize_output_filename(string $name): string {
    $filename = preg_replace("/[^a-zA-Z0-9_.-]/", "_", basename($name));
    return $filename !== "" ? $filename : "path-tunnel-file.bin";
}

function cleanup_old_path_tunnel_tests(): void {
    $testRoot = __DIR__ . "/uploads/path-tunnel";
    if (!is_dir($testRoot)) {
        return;
    }

    $entries = scandir($testRoot);
    if ($entries === false) {
        return;
    }

    $cutoff = time() - PATH_TUNNEL_MAX_AGE_SECONDS;
    foreach ($entries as $entry) {
        if ($entry === "." || $entry === ".." || !preg_match("/^[a-f0-9]{16}$/", $entry)) {
            continue;
        }

        $dir = $testRoot . "/" . $entry;
        if (!is_dir($dir) || filemtime($dir) === false || filemtime($dir) >= $cutoff) {
            continue;
        }

        delete_path_tunnel_dir($dir);
    }
}

function delete_path_tunnel_dir(string $dir): void {
    $files = scandir($dir);
    if ($files === false) {
        return;
    }

    foreach ($files as $file) {
        if ($file === "." || $file === "..") {
            continue;
        }

        $path = $dir . "/" . $file;
        if (is_file($path)) {
            unlink($path);
        }
    }

    rmdir($dir);
}
