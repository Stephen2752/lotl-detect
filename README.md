# LOTL-Detect Final Year Project Prototype

LOTL-Detect is a local SOC-style dashboard built with PHP and MySQL. It analyses manually uploaded Windows event log CSV files using transparent PowerShell rules. It supports CSV only: there is no EVTX ingestion, real-time monitoring, or enterprise-grade detection. No Composer, Node.js, or Python installation is required.

## 1. Setup on Windows with XAMPP

1. Open XAMPP Control Panel. Click **Start** beside **Apache** and **MySQL**, then wait until both services are green.
2. Copy the complete `lotl-detect` folder to `C:\xampp\htdocs\lotl-detect`. Confirm that the final path is `C:\xampp\htdocs\lotl-detect\index.php`, without an extra nested folder.
3. Copy `config.example.php` to `config.php`. If your MySQL account has a password, edit the local `config.php`; this file is ignored by Git and is not included in the repository.
4. Visit **http://localhost/lotl-detect/**. If Apache uses port 8080, visit **http://localhost:8080/lotl-detect/** instead.
5. On the first visit, the application attempts to create the database and its three tables. The account therefore needs database and table creation permissions. For manual setup, visit **http://localhost/phpmyadmin/**, open Import, and import `schema.sql`.
6. Select `sample_events.csv` and click **Upload and Analyse**. Starting with an empty database, the expected result is **8 events and 5 alerts: 3 Medium, 1 High, and 1 Critical**.
7. Click **View source and reasons** to inspect the original event, score, matched rules, explanations, and MITRE ATT&CK mappings.

Uploading the same file more than once creates another batch and duplicates the counts. Tables display the latest 100 records; statistic cards count all database records.

## 2. Simulated sample and detection rules

Every hostname and username in `sample_events.csv` is fictional. The file uses `SIMULATED_TEXT_ONLY`, invalid encoded placeholder text, and the reserved domain `example.invalid`. These are detection inputs, not commands to run. The application never executes, decodes, or downloads CSV content.

| Rule | Case-insensitive text condition | Score | MITRE ATT&CK |
|---|---|---:|---|
| PS001 | PowerShell context contains the independent parameter `-EncodedCommand` or `-enc` | 40 | T1059.001 |
| PS002 | PowerShell context contains `DownloadString`, `Invoke-WebRequest`, or `iwr` | 35 | T1059.001 |
| PS003 | Command text contains `FromBase64String` | 30 | T1027 |
| PS004 | PowerShell context contains `-WindowStyle Hidden` or `-w hidden` | 20 | T1059.001 |

A PowerShell context means the text contains `powershell` or `pwsh`, optionally followed by `.exe`, or the Event ID is 4103 or 4104. Each rule scores once per event and the total is capped at 100.

- Below 30: the event is stored but no alert is created.
- 30–49: Medium.
- 50–74: High.
- 75–100: Critical.

The eight sample scores are **0, 40, 35, 30, 20, 60, 100, and 0**.

A rule match is a suspicious signal, not proof of an attack. Legitimate administration can cause false positives, and an event with no match is not necessarily safe. The MITRE mappings are behavioural classifications for this educational prototype. Simple keyword rules cannot reconstruct complete process context, combine fragmented 4104 events, detect every evasion method, or confirm an attack.

## 3. Supported CSV format

The parser accepts UTF-8 with or without a BOM and UTF-16LE/BE with a BOM. It automatically detects comma, semicolon, and tab delimiters. A file may contain up to 5 MB and 10,000 event records. Fields containing commas or line breaks must be enclosed in double quotes. A double quote inside a quoted field must be written as two double quotes.

ISO 8601 timestamps with a time-zone offset are recommended. Original time text is stored and displayed without time-zone conversion. If a date cannot be parsed, a required column is missing, or a row has the wrong number of columns, the complete import is rejected and no partial batch is stored.

| Logical field | Recognised column names |
|---|---|
| Time, required | `TimeCreated`, `Time`, `Date and Time`, `Timestamp`, `UtcTime` |
| Hostname, required | `MachineName`, `Computer`, `ComputerName`, `Hostname`, `Host` |
| Event ID, required | `Id`, `EventID`, `Event ID` |
| Analysis text, required column but value may be empty | `CommandLine`, `ProcessCommandLine`, `ScriptBlockText`, `Message`, `Description` |
| Username, optional | `UserName`, `User`, `UserId` |

Column matching ignores case, spaces, underscores, hyphens, and periods. If several aliases for one field appear, the first recognised alias above is used. `Message` or `Description` is analysed as one complete text field. An empty analysis field is stored but does not match a rule. The parser does not extract a command line or username from complex localised message text.

## 4. Exporting real Windows PowerShell logs

Open **Event Viewer → Applications and Services Logs → Microsoft → Windows → PowerShell → Operational**. Select the required events and use **Save All Events As**, or save the filtered events in CSV format where that option is available. CSV output varies between Windows versions and may omit hostname or message fields. If required columns are missing, use the structured PowerShell export below. EVTX files cannot be uploaded directly.

Event ID **4104** requires **PowerShell Script Block Logging** to be enabled before the event occurs; enabling it does not recreate historical events. With appropriate administrative authority, open Group Policy Editor and go to **Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging**, then enable the setting. Some Windows editions do not include Group Policy Editor; use Microsoft documentation or contact the administrator. Do not disable security features or run attack commands. Logs may contain sensitive information, so export only data you are authorised to analyse.

This read-only PowerShell pipeline exports up to 1,000 existing 4104 records as a compatible UTF-8 CSV. It does not execute text stored in the logs:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 1000 |
    Select-Object @{Name='TimeCreated';Expression={$_.TimeCreated.ToString('o')}},
                  MachineName, Id, @{Name='UserName';Expression={[string]$_.UserId}}, Message |
    Export-Csv -Path "$env:USERPROFILE\Desktop\powershell_events.csv" -NoTypeInformation -Encoding UTF8
```

If no records are returned, verify that the log is enabled and that suitable events exist. Event 4104 contains script-block text rather than a full process command line. Event 4688 or Sysmon records can be analysed only when the source contains command-line data exported under a supported column name. PowerShell 7 can use the `PowerShellCore/Operational` channel, depending on the environment.

References: [Microsoft PowerShell logging documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows), [Microsoft 4104 overview](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/), [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/), and [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/).

## 5. Verification and troubleshooting

Open a PowerShell terminal in the project folder and run:

```powershell
Get-ChildItem -Filter *.php | ForEach-Object { & C:\xampp\php\php.exe -l $_.FullName }
& C:\xampp\php\php.exe .\test.php

# This imports another sample batch into the configured database.
# Start MySQL before running it.
& C:\xampp\php\php.exe .\test.php --mysql
```

If the database connection fails, confirm that MySQL is running, then check the port, username, and password in `config.php`. Automatic initialization requires `CREATE` permission. Detailed errors are written to the PHP error log rather than shown in the browser. An empty root password is suitable only for a local learning environment. Do not expose this prototype directly to the public internet. It has no authentication, role management, or deletion interface.

If an upload fails because of PHP settings, edit `C:\xampp\php\php.ini`, set `upload_max_filesize` to at least `5M` and `post_max_size` to at least `8M`, save, and restart Apache. The application still enforces its own 5 MB limit. Empty files, header-only files, unsupported encodings, and mismatched column counts produce clear messages.

Uploads remain in PHP-managed temporary storage and are not copied into the public project directory. The application validates the extension, detected type, size, encoding, columns, and event values. Page output is HTML-escaped, database writes use PDO prepared statements, and each import uses a transaction. PHP, HTML, or script text inside a CSV is treated only as text. `.htaccess` additionally blocks direct access to configuration, library, schema, README, and test files when Apache permits overrides.

## Project files

- `index.php`: dashboard, upload handling, alert list, and event details.
- `lib.php`: database initialization, CSV parsing, detection rules, and transactional storage.
- `config.example.php`: safe template for local MySQL settings.
- `config.php`: local MySQL connection settings; create it from the example and do not commit it.
- `schema.sql`: database schema for phpMyAdmin import.
- `assets/style.css`: responsive SOC-style interface.
- `sample_events.csv`: eight completely simulated events.
- `test.php`: command-line detection tests and optional MySQL verification.
- `.htaccess`: Apache access restrictions.
- `README.md`: setup, operation, limitations, and troubleshooting instructions.

