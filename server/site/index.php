<?php
// UniFi Blocker — opt-in report totals, behind a password. Same gate as
// pad.traks.ca (server/pad_report/index.php in PadspanHA).
//
// Deployed at https://unifiblocker.enerx.ca/ (vhost /etc/apache2/sites-available/
// unifiblocker.enerx.ca.conf on bcmail, docroot web10/web/unifiblocker/) with
// api/report.php (the receiver) and robots.txt beside it.
//
// The password's hash (password_hash) is the one line of
// private/unifiblocker-report-pass. Failed sign-ins are counted across all
// callers in private/unifiblocker-report-fails.json: each costs a second, and
// 20 in 15 minutes stop all sign-ins until the oldest ages out.

$PRIV  = __DIR__ . '/../../private';
$PASS  = $PRIV . '/unifiblocker-report-pass';
$FAILS = $PRIV . '/unifiblocker-report-fails.json';
$DIR   = $PRIV . '/unifiblocker-telemetry';
$FAIL_WINDOW_S = 900;
$FAIL_MAX = 20;
$DAYS = 30;

header('Cache-Control: no-store');
header('X-Robots-Tag: noindex, nofollow');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');

// The session cookie is Secure, so a plain-http visit could never sign in.
if (strpos($_SERVER['HTTP_CF_VISITOR'] ?? '', '"http"') !== false) {
    header('Location: https://unifiblocker.enerx.ca/', true, 301);
    exit;
}

session_name('unifiblocker_report');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
session_start();

if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: /', true, 303);
    exit;
}

function recent_fails($file, $window) {
    $t = is_readable($file) ? json_decode((string)file_get_contents($file), true) : [];
    $now = time();
    return array_values(array_filter(is_array($t) ? $t : [], fn($x) => is_int($x) && $now - $x < $window));
}

$msg = '';
if (empty($_SESSION['ok']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $fails = recent_fails($FAILS, $FAIL_WINDOW_S);
    $hash = is_readable($PASS) ? trim((string)file_get_contents($PASS)) : '';
    if (count($fails) >= $FAIL_MAX) {
        $msg = 'Too many wrong passwords. Try again in a few minutes.';
    } elseif ($hash !== '' && password_verify((string)($_POST['password'] ?? ''), $hash)) {
        session_regenerate_id(true);
        $_SESSION['ok'] = 1;
        header('Location: /', true, 303);
        exit;
    } else {
        $fails[] = time();
        @file_put_contents($FAILS, json_encode($fails), LOCK_EX);
        sleep(1);
        $msg = 'Wrong password.';
    }
}

$h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES);

// ── numbers (signed in only) ──────────────────────────────────────────────
$S = null;
if (!empty($_SESSION['ok'])) {
    $reports = [];                          // install_id => [day => report] (last one that day wins)
    for ($i = $DAYS - 1; $i >= 0; $i--) {
        $day = gmdate('Y-m-d', time() - $i * 86400);
        $f = "$DIR/$day.jsonl";
        if (!is_readable($f)) continue;
        foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $x = json_decode($line, true);
            $r = $x['report'] ?? null;
            if (!is_array($r) || empty($r['install_id'])) continue;
            $reports[$r['install_id']][$x['recv_day'] ?? $day] = $r;
        }
    }
    $ledger = is_readable("$DIR/installs.json") ? (json_decode((string)file_get_contents("$DIR/installs.json"), true) ?: []) : [];
    $today = gmdate('Y-m-d');
    $since = fn($n) => gmdate('Y-m-d', time() - ($n - 1) * 86400);

    $S = ['active1' => 0, 'active7' => 0, 'active30' => count($reports), 'ever' => count($ledger),
          'per_day' => [], 'version' => [], 'ha' => [], 'controller' => [], 'usage' => [], 'views' => [],
          'api' => [], 'log' => [], 'cats' => [], 'adv' => [], 'polls' => 0, 'poll_fail' => 0,
          'poll_ms_sum' => 0, 'poll_ms_max' => 0, 'slow' => 0, 'oversize' => 0, 'slow_inst' => 0,
          'oversize_inst' => 0, 'api_inst' => [], 'log_inst' => [], 'sizes' => [], 'settings' => []];
    $bump = function (&$a, $k, $n = 1) { $a[$k] = ($a[$k] ?? 0) + $n; };

    foreach ($reports as $id => $byDay) {
        ksort($byDay);
        $last = end($byDay);
        $lastDay = array_key_last($byDay);
        if ($lastDay === $today) $S['active1']++;
        if ($lastDay >= $since(7)) $S['active7']++;
        $bump($S['version'], $last['version'] ?? '?');
        $bump($S['ha'], $last['ha_version'] ?? '?');
        $bump($S['controller'], $last['env']['controller_version'] ?? '?');
        $c = $last['counts'] ?? [];
        $S['sizes'][] = ['clients' => (int)($c['clients'] ?? 0), 'cameras' => (int)($c['cameras'] ?? 0)];
        foreach (($c['categories'] ?? []) as $k => $n) $bump($S['cats'], $k, (int)$n);
        foreach (($c['advisories'] ?? []) as $k => $n) $bump($S['adv'], $k, (int)$n);
        $e = $last['env'] ?? [];
        $bump($S['settings'], 'auto-scan ' . ($e['auto_scan_count'] ?? '?'));
        $bump($S['settings'], 'poll every ' . ($e['scan_interval'] ?? '?') . ' s');
        if (isset($e['local_cidr_default']) && !$e['local_cidr_default']) $bump($S['settings'], 'custom local-only subnet');
        $hadSlow = $hadOver = false; $apiSeen = []; $logSeen = [];
        foreach ($byDay as $day => $r) {
            $bump($S['per_day'], $day);
            foreach (($r['usage'] ?? []) as $k => $n) {
                if (str_starts_with($k, 'view_')) $bump($S['views'], substr($k, 5), (int)$n);
                else $bump($S['usage'], $k, (int)$n);
            }
            $hl = $r['health'] ?? [];
            $p = (int)($hl['polls'] ?? 0);
            $S['polls'] += $p;
            $S['poll_fail'] += (int)($hl['poll_failures'] ?? 0);
            $S['poll_ms_sum'] += $p * (float)($hl['poll_ms_avg'] ?? 0);
            $S['poll_ms_max'] = max($S['poll_ms_max'], (float)($hl['poll_ms_max'] ?? 0));
            $S['slow'] += (int)($hl['slow_updates'] ?? 0);
            $S['oversize'] += (int)($hl['recorder_oversize'] ?? 0);
            $hadSlow = $hadSlow || !empty($hl['slow_updates']);
            $hadOver = $hadOver || !empty($hl['recorder_oversize']);
            foreach (($hl['api_errors'] ?? []) as $k => $n) { $bump($S['api'], $k, (int)$n); $apiSeen[$k] = 1; }
            foreach (($hl['log'] ?? []) as $k => $n) { $bump($S['log'], $k, (int)$n); $logSeen[$k] = 1; }
        }
        $S['slow_inst'] += $hadSlow; $S['oversize_inst'] += $hadOver;
        foreach ($apiSeen as $k => $_) $bump($S['api_inst'], $k);
        foreach ($logSeen as $k => $_) $bump($S['log_inst'], $k);
    }
    foreach (['version', 'ha', 'controller', 'usage', 'views', 'api', 'log', 'cats', 'adv', 'settings'] as $k) arsort($S[$k]);
    ksort($S['per_day']);
}

function table($rows, $cols, $empty = 'Nothing yet.') {
    if (!$rows) return '<p class="muted">' . $empty . '</p>';
    $o = '<table><thead><tr>';
    foreach ($cols as $c) $o .= '<th>' . htmlspecialchars($c) . '</th>';
    $o .= '</tr></thead><tbody>';
    foreach ($rows as $r) {
        $o .= '<tr>';
        foreach ($r as $v) $o .= '<td>' . htmlspecialchars((string)$v) . '</td>';
        $o .= '</tr>';
    }
    return $o . '</tbody></table>';
}
function pairs($a, $label, $n = 'Count', $limit = 30) {
    $rows = [];
    foreach (array_slice($a, 0, $limit, true) as $k => $v) $rows[] = [$k, $v];
    return table($rows, [$label, $n]);
}
function median($xs) { if (!$xs) return 0; sort($xs); $m = intdiv(count($xs), 2); return count($xs) % 2 ? $xs[$m] : ($xs[$m - 1] + $xs[$m]) / 2; }
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>UniFi Blocker reports</title>
<style>
  body{margin:0;padding:16px;background:#0f1420;color:#e2e8f0;font-family:Inter,system-ui,Arial,sans-serif}
  .wrap{max-width:1180px;margin:0 auto}
  .top{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px}
  .top a{color:rgba(226,232,240,.6);font-size:12px;text-decoration:none}
  h1{margin:0;font-size:24px;font-weight:800}
  .k{font:600 11px/1 ui-monospace,Consolas,monospace;letter-spacing:.14em;text-transform:uppercase;color:#42a5f5}
  .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}
  .tile{background:#151c2c;border:1px solid #243049;border-radius:12px;padding:12px 14px}
  .tile b{display:block;font-size:24px;font-weight:800}
  .tile span{font-size:12px;color:#94a3b8}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:12px}
  .card{background:#151c2c;border:1px solid #243049;border-radius:12px;padding:12px 14px}
  .card h2{margin:0 0 8px;font-size:14px;color:#cbd5e1}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:4px 6px;border-bottom:1px solid #243049}
  th{color:#94a3b8;font-weight:600}
  td:last-child,th:last-child{text-align:right}
  .muted{color:#94a3b8;font-size:13px}
  .bars{display:flex;align-items:flex-end;gap:3px;height:80px}
  .bars div{flex:1;background:#42a5f5;border-radius:2px 2px 0 0;min-height:2px}
  .login{max-width:340px;margin:18vh auto 0;display:flex;flex-direction:column;gap:12px}
  .login input{padding:10px 12px;border-radius:10px;border:1px solid #2c3a57;background:#151c2c;color:#e2e8f0;font-size:15px}
  .login button{padding:10px 12px;border-radius:10px;border:1px solid #42a5f5;background:#1b2a44;color:#e2e8f0;font-weight:700;cursor:pointer}
  .login .m{min-height:1.2em;color:#f87171;font-size:13px}
</style>
</head>
<body>
<?php if (empty($_SESSION['ok'])): ?>
<form class="login" method="post" action="/">
  <div class="k">UniFi Blocker opt-in reports</div>
  <h1>Install base</h1>
  <input type="password" name="password" placeholder="Password" autocomplete="current-password" autofocus required aria-label="Password">
  <button type="submit">Sign in</button>
  <div class="m" role="status"><?= $h($msg) ?></div>
</form>
<?php else: ?>
<div class="wrap">
  <div class="top"><div><div class="k">UniFi Blocker opt-in reports · last <?= $DAYS ?> days</div><h1>Install base</h1></div><a href="?logout=1">Sign out</a></div>

  <div class="tiles">
    <div class="tile"><b><?= $S['active1'] ?></b><span>reported today (UTC)</span></div>
    <div class="tile"><b><?= $S['active7'] ?></b><span>active, 7 days</span></div>
    <div class="tile"><b><?= $S['active30'] ?></b><span>active, 30 days</span></div>
    <div class="tile"><b><?= $S['ever'] ?></b><span>installs ever</span></div>
    <div class="tile"><b><?= median(array_column($S['sizes'], 'clients')) ?></b><span>median clients</span></div>
    <div class="tile"><b><?= array_sum(array_column($S['sizes'], 'cameras')) ?></b><span>cameras across installs</span></div>
    <div class="tile"><b><?= $S['polls'] ? round($S['poll_ms_sum'] / $S['polls']) : '—' ?> ms</b><span>average poll (max <?= round($S['poll_ms_max']) ?>)</span></div>
    <div class="tile"><b><?= $S['polls'] ? round(100 * $S['poll_fail'] / $S['polls'], 1) : 0 ?>%</b><span>polls failed (<?= $S['poll_fail'] ?>)</span></div>
  </div>

  <div class="card" style="margin-bottom:12px"><h2>Reports per day</h2>
    <?php $mx = max([1] + array_values($S['per_day'])); ?>
    <div class="bars"><?php for ($i = $DAYS - 1; $i >= 0; $i--): $d = gmdate('Y-m-d', time() - $i * 86400); $n = $S['per_day'][$d] ?? 0; ?>
      <div title="<?= $h("$d: $n") ?>" style="height:<?= max(2, round(80 * $n / $mx)) ?>px"></div><?php endfor; ?></div>
  </div>

  <div class="grid">
    <div class="card"><h2>Integration version (latest report per install)</h2><?= pairs($S['version'], 'Version', 'Installs') ?></div>
    <div class="card"><h2>Home Assistant</h2><?= pairs($S['ha'], 'Version', 'Installs') ?></div>
    <div class="card"><h2>UniFi Network</h2><?= pairs($S['controller'], 'Version', 'Installs') ?></div>
    <div class="card"><h2>Controller API errors</h2>
      <?php $rows = []; foreach (array_slice($S['api'], 0, 30, true) as $k => $n) $rows[] = [$k, $S['api_inst'][$k] ?? 0, $n]; echo table($rows, ['Endpoint and status', 'Installs', 'Count']); ?></div>
    <div class="card"><h2>Warnings and errors logged</h2>
      <?php $rows = []; foreach (array_slice($S['log'], 0, 30, true) as $k => $n) $rows[] = [$k, $S['log_inst'][$k] ?? 0, $n]; echo table($rows, ['Module and level', 'Installs', 'Count']); ?></div>
    <div class="card"><h2>Home Assistant complaints</h2>
      <?= table([['Slow entity updates', $S['slow_inst'], $S['slow']], ['Attributes too big for the recorder', $S['oversize_inst'], $S['oversize']]], ['Warning', 'Installs', 'Count']) ?></div>
    <div class="card"><h2>Tools used</h2><?= pairs($S['usage'], 'Tool', 'Uses') ?></div>
    <div class="card"><h2>Panel views opened</h2><?= pairs($S['views'], 'View', 'Opens') ?></div>
    <div class="card"><h2>Devices by category (all installs)</h2><?= pairs($S['cats'], 'Category', 'Devices') ?></div>
    <div class="card"><h2>Devices matching a vendor advisory</h2><?= pairs($S['adv'], 'Vendor', 'Devices') ?></div>
    <div class="card"><h2>Settings</h2><?= pairs($S['settings'], 'Setting', 'Installs') ?></div>
  </div>
  <p class="muted">Counts only. The integration refuses to send MACs, IPs, names, vendor strings or entity ids, and the receiver checks again.</p>
</div>
<?php endif; ?>
</body>
</html>
