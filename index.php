<?php
declare(strict_types=1);
session_start();
header('Content-Type: text/html; charset=UTF-8');
require __DIR__.'/lib.php';
$_SESSION['csrf'] ??= bin2hex(random_bytes(24));
$error=''; $notice=$_SESSION['notice'] ?? ''; unset($_SESSION['notice']); $pdo=null;
try { $pdo=db(); } catch (Throwable $e) { $error='Database connection or initialization failed. Start MySQL in XAMPP and check the port, username, password, and database permissions in config.php.'; error_log($e->getMessage()); }
if ($_SERVER['REQUEST_METHOD']==='POST') {
 try {
    if (!hash_equals($_SESSION['csrf'],(string)($_POST['csrf'] ?? ''))) throw new RuntimeException('Page validation has expired. Refresh the page and upload the file again.');
    if (!$pdo) throw new RuntimeException('The database is not connected. Correct the database configuration first.');
    $f=$_FILES['csv'] ?? null;
    if (!$f || !is_int($f['error'] ?? null)) throw new RuntimeException('No file was received. Select a CSV and check the PHP post_max_size setting.');
    if ($f['error']!==UPLOAD_ERR_OK) throw new RuntimeException('Upload failed (code '.$f['error'].'). Check the file size and PHP upload settings. The file must not exceed 5 MB.');
    if (strtolower(pathinfo($f['name'],PATHINFO_EXTENSION))!=='csv') throw new RuntimeException('Only .csv files are accepted. EVTX, PHP, and other file types are not supported.');
    if (!is_uploaded_file($f['tmp_name']) || $f['size']>MAX_UPLOAD) throw new RuntimeException('The upload is invalid or the file exceeds 5 MB.');
    $mime=(new finfo(FILEINFO_MIME_TYPE))->file($f['tmp_name']);
    if (!in_array($mime,['text/plain','text/csv','application/csv','application/vnd.ms-excel','text/x-csv','text/tab-separated-values','application/octet-stream','application/x-empty','inode/x-empty'],true)) throw new RuntimeException('Unsupported file type. Upload a plain-text CSV file.');
    $result=importEvents($pdo,parseCsv($f['tmp_name']),basename($f['name']));
    $_SESSION['notice']="Import completed: {$result['events']} events and {$result['alerts']} alerts." . ($result['alerts']===0 ? ' Every event scored below 30; this does not prove that the events are safe.' : '');
    header('Location: index.php'); exit;
 } catch (RuntimeException $e) { $error=$e instanceof PDOException ? 'Database storage failed and this import was rolled back. Check the database service and permissions.' : $e->getMessage(); }
 catch (Throwable $e) { error_log($e->getMessage()); $error='The file could not be processed. Check the CSV content and database configuration.'; }
}
$alerts=[]; $events=[]; $stats=['events'=>0,'total'=>0,'Medium'=>0,'High'=>0,'Critical'=>0]; $detail=null;
if ($pdo) try {
 $stats['events']=(int)$pdo->query('SELECT COUNT(*) FROM events')->fetchColumn();
 foreach ($pdo->query('SELECT severity,COUNT(*) n FROM alerts GROUP BY severity') as $r) { $stats[$r['severity']]=(int)$r['n']; $stats['total']+=(int)$r['n']; }
 $alerts=$pdo->query('SELECT a.*,e.event_time,e.hostname FROM alerts a JOIN events e ON e.id=a.event_id ORDER BY a.id DESC LIMIT 100')->fetchAll(PDO::FETCH_ASSOC);
 $events=$pdo->query('SELECT e.*,a.id alert_id,a.score,a.severity FROM events e LEFT JOIN alerts a ON a.event_id=e.id ORDER BY e.id DESC LIMIT 100')->fetchAll(PDO::FETCH_ASSOC);
 if (isset($_GET['event']) && ctype_digit((string)$_GET['event'])) {
   $q=$pdo->prepare('SELECT e.*,a.score,a.severity,a.rules_json,i.filename FROM events e JOIN imports i ON i.id=e.import_id LEFT JOIN alerts a ON a.event_id=e.id WHERE e.id=?'); $q->execute([$_GET['event']]); $detail=$q->fetch(PDO::FETCH_ASSOC);
   if (!$detail) $error='The source event could not be found.';
 }
} catch (Throwable $e) { error_log($e->getMessage()); $error='The database query failed. Check the table structure and MySQL service.'; }
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LOTL-Detect · SOC Dashboard</title><link rel="stylesheet" href="assets/style.css"></head>
<body><main><header><div class="eyebrow">SECURITY OPERATIONS · FINAL YEAR PROJECT PROTOTYPE</div><h1>LOTL<span>-Detect</span></h1><p>Offline Windows event CSV analysis · Transparent rules · Traceable events</p></header>
<div class="warning">A rule match is a suspicious signal, not proof of an attack. False positives are possible. This prototype does not provide real-time monitoring or enterprise-grade detection.</div>
<?php if($error):?><div role="alert" class="error"><?=h($error)?></div><?php endif?>
<?php if($notice):?><div role="status" class="success"><?=h($notice)?></div><?php endif?>
<section class="stats"><?php foreach(['events'=>'Imported Events','total'=>'Total Alerts','Medium'=>'Medium','High'=>'High','Critical'=>'Critical'] as $k=>$label):?><article><small><?=h($label)?></small><strong><?=h($stats[$k])?></strong></article><?php endforeach?></section>
<section><h2>Import Events</h2><form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>"><label for="csv">CSV file (maximum 5 MB / 10,000 events)</label><input id="csv" name="csv" type="file" accept=".csv" required><button <?=!$pdo?'disabled':''?>>Upload and Analyse</button><a href="sample_events.csv" download>Download simulated sample</a></form><p class="muted">Supports UTF-8 and BOM-marked UTF-16 with comma, semicolon, or tab delimiters. Each upload creates a new batch, so uploading the same file again will duplicate its counts. Event times are displayed exactly as supplied.</p></section>
<?php if($detail): $d=detect($detail); $detailRules=englishRules($detail['rules_json'] ? json_decode($detail['rules_json'],true) : $d['rules']);?><section id="detail"><h2>Source Event #<?=h($detail['id'])?></h2><p><?=h($detail['event_time'])?> · <?=h($detail['hostname'])?> · User <?=h($detail['username'])?> · Event ID <?=h($detail['event_id'])?></p><p>Source file <?=h($detail['filename'])?> · CSV record <?=h($detail['source_row'])?> · <?=h($detail['severity'] ?? 'Below alert threshold')?> · <?=h($detail['score'] ?? $d['score'])?> / 100</p><h3>Command Line / Script / Original Message</h3><pre><?=h($detail['command_line'])?></pre><h3>Matched Rules and Explanations</h3><?php foreach($detailRules as $r):?><p><b><?=h($r['id'].' · '.$r['name'].' +'.$r['points'].' · '.$r['mitre'])?></b><br><?=h($r['reason'])?></p><?php endforeach?><?php if(!$d['rules']):?><p>None of the four current rules matched this event.</p><?php endif?><details><summary>Complete source fields</summary><pre><?=h(json_encode(json_decode($detail['raw_json'],true),JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES))?></pre></details></section><?php endif?>
<section><h2>Alert Queue <small>Latest 100</small></h2><div class="table"><table><thead><tr><th>Severity / Score</th><th>Event Time</th><th>Hostname</th><th>Matched Rules</th><th>MITRE ATT&CK</th><th>Details</th></tr></thead><tbody><?php foreach($alerts as $a): $rules=englishRules(json_decode($a['rules_json'],true));?><tr><td><span class="badge <?=h($a['severity'])?>"><?=h($a['severity'])?></span> <?=h($a['score'])?></td><td><?=h($a['event_time'])?></td><td><?=h($a['hostname'])?></td><td><?=h(implode(', ',array_column($rules,'name')))?></td><td><?=h(implode(' / ',array_unique(array_column($rules,'mitre'))))?></td><td><a href="?event=<?=h($a['event_id'])?>#detail">View source and reasons</a></td></tr><?php endforeach?><?php if(!$alerts):?><tr><td colspan="6">No alerts are available. Upload a CSV; events scoring below 30 will appear in the source event table below.</td></tr><?php endif?></tbody></table></div></section>
<section><h2>Source Events <small>Latest 100 · includes events without alerts</small></h2><div class="table"><table><thead><tr><th>Time</th><th>Hostname</th><th>Event ID</th><th>Result</th><th>Source</th></tr></thead><tbody><?php foreach($events as $e):?><tr><td><?=h($e['event_time'])?></td><td><?=h($e['hostname'])?></td><td><?=h($e['event_id'])?></td><td><?=h($e['severity'] ?? 'Below alert threshold')?></td><td><a href="?event=<?=h($e['id'])?>#detail">Event #<?=h($e['id'])?></a></td></tr><?php endforeach?><?php if(!$events):?><tr><td colspan="5">No events have been imported.</td></tr><?php endif?></tbody></table></div></section>
<footer>Scoring: 30–49 Medium · 50–74 High · 75–100 Critical · Scores below 30 do not create alerts. Each rule scores once per event, with a maximum total of 100.</footer></main></body></html>

