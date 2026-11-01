<?php
declare(strict_types=1);
const MAX_UPLOAD = 5242880;
function h($value): string { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function db(): PDO {
    $c = require __DIR__ . '/config.php';
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $c['database'])) throw new RuntimeException('The database name may contain only letters, numbers, and underscores.');
    $pdo = new PDO("mysql:host={$c['host']};port={$c['port']};charset=utf8mb4", $c['username'], $c['password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
    $pdo->exec('CREATE DATABASE IF NOT EXISTS `' . $c['database'] . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    $pdo->exec('USE `' . $c['database'] . '`');
    $sql = file_get_contents(__DIR__ . '/schema.sql');
    foreach (explode(';', $sql) as $statement) {
        if (str_starts_with(trim($statement), 'CREATE TABLE')) $pdo->exec($statement);
    }
    return $pdo;
}
function detect(array $event): array {
    $text = $event['command_line'];
    $ps = preg_match('/\b(?:powershell|pwsh)(?:\.exe)?\b/i', $text) || in_array($event['event_id'], [4103,4104], true);
    $rules = [];
    $add = function($id, $name, $points, $mitre, $reason) use (&$rules) { $rules[] = compact('id','name','points','mitre','reason'); };
    if ($ps && preg_match('/(?<![\w-])-(?:encodedcommand|enc)(?=\s|:|$)/i', $text)) $add('PS001','Encoded command parameter',40,'T1059.001','Found -EncodedCommand or -enc. Encoding can hide commands, but it may also be used by legitimate automation.');
    if ($ps && preg_match('/\b(?:DownloadString|Invoke-WebRequest|iwr)\b/i', $text)) $add('PS002','PowerShell download-related keyword',35,'T1059.001','Found a download-related keyword in a PowerShell context. The system only matched text and did not access the network.');
    if (stripos($text, 'FromBase64String') !== false) $add('PS003','Base64 decoding keyword',30,'T1027','Found FromBase64String. It may indicate obfuscation, but it can also be used for normal data processing.');
    if ($ps && preg_match('/(?<![\w-])-(?:WindowStyle|w)\s+[\x22\x27]?Hidden\b/i', $text)) $add('PS004','Hidden window parameter',20,'T1059.001','Found a hidden-window parameter. Legitimate background administration scripts may also use it.');
    $score = min(100, array_sum(array_column($rules,'points')));
    return ['score'=>$score, 'severity'=>$score >= 75 ? 'Critical' : ($score >= 50 ? 'High' : ($score >= 30 ? 'Medium' : null)), 'rules'=>$rules];
}
function englishRules(array $rules): array {
    $labels = [
        'PS001'=>['Encoded command parameter','Found -EncodedCommand or -enc. Encoding can hide commands, but it may also be used by legitimate automation.'],
        'PS002'=>['PowerShell download-related keyword','Found a download-related keyword in a PowerShell context. The system only matched text and did not access the network.'],
        'PS003'=>['Base64 decoding keyword','Found FromBase64String. It may indicate obfuscation, but it can also be used for normal data processing.'],
        'PS004'=>['Hidden window parameter','Found a hidden-window parameter. Legitimate background administration scripts may also use it.'],
    ];
    foreach ($rules as &$rule) if (isset($labels[$rule['id']])) {
        [$rule['name'],$rule['reason']] = $labels[$rule['id']];
    }
    unset($rule);
    return $rules;
}
function parseCsv(string $path): array {
    $data = file_get_contents($path);
    if ($data === false || trim($data) === '') throw new RuntimeException('The CSV file is empty. Select a CSV containing a header row and event records.');
    if (strlen($data) > MAX_UPLOAD) throw new RuntimeException('The CSV file exceeds the 5 MB limit.');
    if (str_starts_with($data,"\xFF\xFE")) $data = mb_convert_encoding(substr($data,2),'UTF-8','UTF-16LE');
    elseif (str_starts_with($data,"\xFE\xFF")) $data = mb_convert_encoding(substr($data,2),'UTF-8','UTF-16BE');
    $data = preg_replace('/^\xEF\xBB\xBF/', '', $data);
    if (!mb_check_encoding($data,'UTF-8') || str_contains($data,"\0")) throw new RuntimeException('Unsupported encoding or binary content. Export a UTF-8 CSV; UTF-16 with a BOM is also supported.');
    $stream = fopen('php://temp','w+'); fwrite($stream,$data); rewind($stream);
    $first = fgets($stream); rewind($stream);
    $delimiter = ','; $most = 0;
    foreach ([',', ';', "\t"] as $candidate) { $n = count(str_getcsv($first,$candidate,'"','')); if ($n > $most) { $most=$n; $delimiter=$candidate; } }
    $headers = fgetcsv($stream,0,$delimiter,'"','');
    $normalize = fn($s) => mb_strtolower(preg_replace('/[\s_\-\.]+/u','', trim($s)));
    $aliases = [
      'event_time'=>['TimeCreated','Time','Date and Time','Timestamp','UtcTime'],
      'hostname'=>['MachineName','Computer','ComputerName','Hostname','Host'],
      'event_id'=>['Id','EventID','Event ID'],
      'username'=>['UserName','User','UserId'],
      'command_line'=>['CommandLine','ProcessCommandLine','ScriptBlockText','Message','Description']
    ];
    $map=[]; $normalized=array_map($normalize,$headers);
    if (count(array_unique($normalized)) !== count($normalized)) throw new RuntimeException('The CSV contains duplicate column names. Use a unique name for every column.');
    foreach ($aliases as $field=>$names) foreach ($names as $name) { $i=array_search($normalize($name),$normalized,true); if ($i !== false) { $map[$field]=$i; break; } }
    foreach (['event_time','hostname','event_id','command_line'] as $field) if (!isset($map[$field])) throw new RuntimeException('A required field could not be identified: ' . $field . '. See sample_events.csv or the field table in README.md.');
    $events=[]; $row=1;
    try {
      while (($cells=fgetcsv($stream,0,$delimiter,'"','')) !== false) {
        $row++; if (count($cells)===1 && trim((string)$cells[0])==='') continue;
        if ($row > 10001) throw new RuntimeException('A maximum of 10,000 events is supported. Split the CSV into smaller files.');
        if (count($cells)!==count($headers)) throw new RuntimeException("CSV record {$row} does not have the same number of columns as the header. Fields containing commas or line breaks must be enclosed in double quotes.");
        $e=['source_row'=>$row]; foreach ($aliases as $field=>$_) $e[$field]=isset($map[$field]) ? trim($cells[$map[$field]]) : 'Not provided';
        if ($e['event_time']==='' || strtotime($e['event_time'])===false) throw new RuntimeException("The time in record {$row} could not be parsed. Use YYYY-MM-DD HH:mm:ss or ISO 8601.");
        if ($e['hostname']==='' || !preg_match('/^\d{1,5}$/',$e['event_id']) || (int)$e['event_id']>65535) throw new RuntimeException("Record {$row} has an empty hostname or an invalid Event ID.");
        foreach (['event_time'=>100,'hostname'=>255,'username'=>255,'command_line'=>100000] as $key=>$max) if (mb_strlen($e[$key])>$max) throw new RuntimeException("Field {$key} is too long in record {$row}.");
        $e['event_id']=(int)$e['event_id']; $e['raw_json']=json_encode(array_combine($headers,$cells),JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR); $events[]=$e;
      }
    } finally { fclose($stream); }
    if (!$events) throw new RuntimeException('The CSV contains a header row but no event records.');
    return $events;
}
function importEvents(PDO $pdo, array $events, string $filename): array {
    $pdo->beginTransaction(); $count=0;
    try {
      $s=$pdo->prepare('INSERT INTO imports(filename) VALUES (?)'); $s->execute([mb_substr($filename,0,255)]); $batch=$pdo->lastInsertId();
      $insert=$pdo->prepare('INSERT INTO events(import_id,source_row,event_time,hostname,event_id,username,command_line,raw_json) VALUES (?,?,?,?,?,?,?,?)');
      $alert=$pdo->prepare('INSERT INTO alerts(event_id,score,severity,rules_json) VALUES (?,?,?,?)');
      foreach ($events as $e) {
        $insert->execute([$batch,$e['source_row'],$e['event_time'],$e['hostname'],$e['event_id'],$e['username'],$e['command_line'],$e['raw_json']]);
        $id=$pdo->lastInsertId(); $d=detect($e);
        if ($d['severity']!==null) { $alert->execute([$id,$d['score'],$d['severity'],json_encode($d['rules'],JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR)]); $count++; }
      }
      $pdo->commit(); return ['import_id'=>(int)$batch,'events'=>count($events),'alerts'=>$count];
    } catch (Throwable $e) { if ($pdo->inTransaction()) $pdo->rollBack(); throw $e; }
}

