<?php
$target = $_GET["url"] ?? "/phishing/rnicrosoft-Iogin/";
$allowedTargets = [
  "/phishing/rnicrosoft-Iogin/",
  "/phishing/micr%D0%BEsoft-Iogin/",
  "/phishing/micrоsoft-Iogin/",
];

if (!in_array($target, $allowedTargets, true)) {
  http_response_code(400);
  header("Content-Type: text/plain; charset=utf-8");
  echo "Unsupported redirect target.";
  exit;
}

header("Cache-Control: no-store");
header("Location: " . $target, true, 302);
exit;
