<?php
header("Content-Type: application/json");

try {
    $testType = $_POST["test_type"] ?? "";
    $metadata = json_decode($_POST["metadata"] ?? "", true);

    if (!is_array($metadata) || empty($metadata["name"])) {
        throw new Exception("Missing original file metadata");
    }

    if ($testType === "encoding") {
        $fileData = reconstruct_encoded_file($_POST["encoding_mode"] ?? "");
    } elseif ($testType === "encryption") {
        $fileData = reconstruct_encrypted_file();
    } elseif ($testType === "chunking") {
        $fileData = reconstruct_chunked_file();
    } else {
        throw new Exception("Unsupported evasion test type");
    }

    $expectedSize = isset($metadata["size"]) ? (int)$metadata["size"] : null;
    if ($expectedSize !== null && strlen($fileData) !== $expectedSize) {
        throw new Exception("Reconstructed file size does not match the original");
    }

    $uploadsDir = __DIR__ . "/uploads";
    if (!is_dir($uploadsDir) && !mkdir($uploadsDir, 0750, true)) {
        throw new Exception("Failed to create upload directory");
    }

    $filename = preg_replace("/[^a-zA-Z0-9_.-]/", "_", basename($metadata["name"]));
    $path = $uploadsDir . "/" . $testType . "-" . gmdate("YmdHis") . "-" . bin2hex(random_bytes(6)) . "_" . $filename;

    if (file_put_contents($path, $fileData) === false) {
        throw new Exception("Failed to save reconstructed file");
    }

    echo json_encode([
        "success" => true,
        "reconstructed" => true,
        "stored" => true,
        "filename" => $metadata["name"],
        "fileUrl" => "/data-theft/uploads/" . basename($path),
        "delete_after_minutes" => 10,
    ]);
} catch (Exception $exception) {
    echo json_encode([
        "success" => false,
        "reconstructed" => false,
        "message" => $exception->getMessage(),
    ]);
}

function read_uploaded_part($field) {
    if (!isset($_FILES[$field]) || $_FILES[$field]["error"] !== UPLOAD_ERR_OK) {
        throw new Exception("Missing uploaded part: " . $field);
    }

    $data = file_get_contents($_FILES[$field]["tmp_name"]);
    if ($data === false) {
        throw new Exception("Unable to read uploaded part: " . $field);
    }

    return $data;
}

function reconstruct_encoded_file($mode) {
    $payload = read_uploaded_part("encoded_payload");

    if ($mode === "base64") {
        $decoded = base64_decode($payload, true);
    } elseif ($mode === "double-base64") {
        $firstPass = base64_decode($payload, true);
        $decoded = $firstPass === false ? false : base64_decode($firstPass, true);
    } elseif ($mode === "hex") {
        $clean = preg_replace("/\s+/", "", $payload);
        if (!ctype_xdigit($clean) || strlen($clean) % 2 !== 0) {
            $decoded = false;
        } else {
            $decoded = hex2bin($clean);
        }
    } elseif ($mode === "url") {
        $decoded = base64_decode(rawurldecode($payload), true);
    } else {
        throw new Exception("Unsupported encoding mode");
    }

    if ($decoded === false) {
        throw new Exception("Failed to decode uploaded file");
    }

    return $decoded;
}

function reconstruct_encrypted_file() {
    $password = $_POST["password"] ?? "";
    $salt = base64_decode($_POST["salt"] ?? "", true);
    $iv = base64_decode($_POST["iv"] ?? "", true);
    $tag = base64_decode($_POST["tag"] ?? "", true);
    $ciphertext = read_uploaded_part("ciphertext");

    if ($password === "" || $salt === false || $iv === false || $tag === false) {
        throw new Exception("Missing encryption metadata");
    }

    $key = hash_pbkdf2("sha256", $password, $salt, 200000, 32, true);
    $decrypted = openssl_decrypt($ciphertext, "aes-256-gcm", $key, OPENSSL_RAW_DATA, $iv, $tag);

    if ($decrypted === false) {
        throw new Exception("Failed to decrypt uploaded file");
    }

    return $decrypted;
}

function reconstruct_chunked_file() {
    $manifest = json_decode($_POST["manifest"] ?? "", true);

    if (!is_array($manifest)) {
        throw new Exception("Missing chunk manifest");
    }

    $chunks = [];
    foreach ($manifest as $chunk) {
        if (empty($chunk["include"])) {
            continue;
        }

        $chunks[] = [
            "order" => (int)$chunk["order"],
            "data" => read_uploaded_part($chunk["field"] ?? ""),
        ];
    }

    usort($chunks, function ($left, $right) {
        return $left["order"] <=> $right["order"];
    });

    $fileData = "";
    foreach ($chunks as $chunk) {
        $fileData .= $chunk["data"];
    }

    return $fileData;
}
