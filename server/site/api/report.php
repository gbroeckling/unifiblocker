<?php
// UniFi Blocker — opt-in usage and issue report receiver.
// Deployed at https://unifiblocker.enerx.ca/api/report.php (bcmail, docroot
// web10/web/unifiblocker/). Same design as PadSpan's telemetry.php.
//
// Appends one JSON line per report to private/unifiblocker-telemetry/
// YYYY-MM-DD.jsonl and keeps installs.json (first/last day per install id).
// Stores the report as sent plus the server-side day. It does NOT store the
// client IP, user agent, or anything else from the request.
//
// The integration only ever sends counts/versions (usage_report.py
// assert_shareable refuses anything identifier-shaped before sending) and
// this checks again: dropped if it isn't JSON, is over 8 KB, has unexpected
// top-level keys, or contains a MAC, a UUID other than install_id, a 32-hex
// string, an IP, an email address or an entity id anywhere in it.

$DIR = __DIR__ . '/../../../private/unifiblocker-telemetry';
$MAX = 8192;

header('Content-Type: application/json');
header('X-Robots-Tag: noindex, nofollow');
function nope($code, $why) { http_response_code($code); echo json_encode(['ok' => false, 'why' => $why]); exit; }

if ($_SERVER['REQUEST_METHOD'] !== 'POST') nope(405, 'method');
$raw = file_get_contents('php://input', false, null, 0, $MAX + 1);
if ($raw === false || strlen($raw) > $MAX) nope(413, 'size');
$r = json_decode($raw, true);
if (!is_array($r)) nope(400, 'json');

$allowed = ['schema', 'install_id', 'day', 'version', 'ha_version', 'python', 'env', 'counts', 'usage', 'health'];
foreach (array_keys($r) as $k) {
    if (!in_array($k, $allowed, true)) nope(400, 'key');
}
if (!isset($r['schema']) || (int)$r['schema'] !== 1) nope(400, 'schema');
$id = isset($r['install_id']) ? (string)$r['install_id'] : '';
if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $id)) nope(400, 'id');

// The identifier shapes the client refuses, checked over everything but install_id.
$copy = $r; unset($copy['install_id']);
$flat = json_encode($copy, JSON_UNESCAPED_SLASHES);
$shapes = [
    '/\b[0-9A-Fa-f]{2}(?:[:\-.][0-9A-Fa-f]{2}){5}\b/',
    '/\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b/',
    '/\b[0-9A-Fa-f]{32}\b/',
    '/\b\d{1,3}(?:\.\d{1,3}){3}\b/',
    '/[A-Za-z0-9._%+\'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/',
    '/\b[a-z_]{2,}\.[a-z0-9_]{2,}\b/',
];
foreach ($shapes as $rx) {
    if (preg_match($rx, $flat)) nope(400, 'shape');
}

if (!is_dir($DIR) && !mkdir($DIR, 0750, true)) nope(500, 'store');
$day = gmdate('Y-m-d');
$line = json_encode(['recv_day' => $day, 'report' => $r], JSON_UNESCAPED_SLASHES) . "\n";
if (file_put_contents("$DIR/$day.jsonl", $line, FILE_APPEND | LOCK_EX) === false) nope(500, 'store');

// Ledger: first/last day and days reported per install id. Best effort.
$lh = @fopen("$DIR/installs.json", 'c+');
if ($lh && flock($lh, LOCK_EX)) {
    $cur = stream_get_contents($lh);
    $led = json_decode($cur === '' ? '{}' : $cur, true);
    if (!is_array($led)) $led = [];
    $e = isset($led[$id]) && is_array($led[$id]) ? $led[$id] : ['first' => $day, 'last' => '', 'days' => 0];
    if ($e['last'] !== $day) $e['days'] = (int)$e['days'] + 1;
    $e['last'] = $day;
    $e['version'] = substr((string)($r['version'] ?? ''), 0, 32);
    $led[$id] = $e;
    ftruncate($lh, 0); rewind($lh);
    fwrite($lh, json_encode($led, JSON_UNESCAPED_SLASHES));
    fflush($lh); flock($lh, LOCK_UN);
}
if ($lh) fclose($lh);

echo '{"ok":true}';
