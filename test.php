<?php
// CLI only: uses config.php database and leaves imported data for review.
if (PHP_SAPI !== 'cli') { http_response_code(403); exit; }
require __DIR__.'/lib.php';
function check(bool $ok,string $message): void { if (!$ok) throw new RuntimeException($message); echo "PASS $message\n"; }
$events=parseCsv(__DIR__.'/sample_events.csv');
check(count($events)===8,'8 sample events');
$results=array_map('detect',$events);
check(array_column($results,'score')===[0,40,35,30,20,60,100,0],'scores and cap');
check(array_column($results,'severity')===[null,'Medium','Medium','Medium',null,'High','Critical',null],'severity thresholds');
check(array_values(array_unique(array_merge(...array_map(fn($r)=>array_column($r['rules'],'mitre'),$results))))===['T1059.001','T1027'],'MITRE mappings');
$tmp=tempnam(sys_get_temp_dir(),'lotl_');
try {
 foreach (['',"TimeCreated,MachineName,Id,CommandLine\n", "foo,bar\nx,y\n", "TimeCreated,MachineName,Id,CommandLine\nwrong,host,1,test\n"] as $bad) {
   file_put_contents($tmp,$bad); $rejected=false; try { parseCsv($tmp); } catch(RuntimeException $e) { $rejected=true; } check($rejected,'reject invalid/empty CSV');
 }
 file_put_contents($tmp,"Date and Time;Computer;Event ID;Message\n2026-10-01 09:00:00;FICT-HOST;4104;FromBase64String\n");
 check(detect(parseCsv($tmp)[0])['score']===30,'English aliases and semicolon delimiter');
} finally { unlink($tmp); }
if (in_array('--mysql',$argv,true)) {
 $pdo=db();
 $r=importEvents($pdo,$events,'CLI verification sample_events.csv');
 check($r['events']===8 && $r['alerts']===5,'actual MySQL import: 8 events / 5 alerts');
 $q=$pdo->prepare('SELECT a.score,a.severity,a.rules_json FROM alerts a JOIN events e ON a.event_id=e.id WHERE e.import_id=? ORDER BY e.id'); $q->execute([$r['import_id']]); $rows=$q->fetchAll(PDO::FETCH_ASSOC);
 check(array_map('intval',array_column($rows,'score'))===[40,35,30,60,100],'persisted alert scores');
 $maps=array_map(fn($a)=>array_values(array_unique(array_column(json_decode($a['rules_json'],true),'mitre'))),$rows);
 check($maps===[['T1059.001'],['T1059.001'],['T1027'],['T1059.001'],['T1059.001','T1027']],'persisted MITRE mappings');
 echo "Verified import ID: {$r['import_id']} (data retained).\n";
}

