# Intrusion Detection System

This project is a starter network intrusion detection system (IDS) written in Python.

It now supports:

- Offline analysis from JSONL and CSV event files
- Continuous monitoring mode for tailed log files
- Optional live packet capture with `scapy`
- Persistent alert storage with JSONL
- Authenticated web dashboard
- Configurable thresholds and allowlists
- Optional automated IP blocking response
- Rule-based alerts for:
  - Port scan behavior
  - Repeated failed login attempts
  - Suspicious port usage
  - Traffic bursts from a single source

## Project Structure

- `main.py` - command line entrypoint
- `config/ids_config.json` - thresholds, auth settings, and response settings
- `ids/models.py` - event and alert data models
- `ids/detector.py` - detection engine and rules
- `ids/ingest.py` - JSONL, CSV, Windows Event Log, Sysmon, Suricata, Zeek, and Windows firewall loaders
- `ids/monitor.py` - continuous monitoring loop
- `ids/responders.py` - optional automated response actions
- `ids/storage.py` - JSONL alert persistence
- `ids/web.py` - built-in dashboard server
- `ids/sniffer.py` - optional live capture support
- `tests/` - basic unit tests
- `sample_data/events.jsonl` - sample traffic events for testing

## Requirements

- Python 3.10+
- Optional: `scapy` for live sniffing

Install optional dependency:

```bash
pip install -r requirements.txt
```

## Analyze Sample Data

```bash
python main.py analyze --input sample_data/events.jsonl
```

This prints alerts and stores them in `data/alerts.jsonl`.

Analyze a Suricata `eve.json` file:

```bash
python main.py analyze --input sample_data/suricata_eve.json --format suricata-eve
```

Analyze a Zeek `conn.log` file:

```bash
python main.py analyze --input sample_data/zeek_conn.log --format zeek-conn
```

Analyze a Windows Firewall `pfirewall.log` style file:

```bash
python main.py analyze --input sample_data/windows_firewall.log --format windows-firewall
```

Analyze exported Windows Security Event Log JSON:

```bash
python main.py analyze --input sample_data/windows_events.jsonl --format windows-events-json
```

Analyze exported Sysmon JSON:

```bash
python main.py analyze --input sample_data/sysmon_events.jsonl --format sysmon-json
```

## Continuous Monitoring

Tail a JSONL file and scan it in cycles:

```bash
python main.py monitor --input sample_data/events.jsonl --cycles 1
```

Remove `--cycles 1` to keep monitoring continuously.

## Run Live Capture

```bash
python main.py monitor --live --interface Ethernet
```

Notes:

- Live capture may require administrator privileges.
- If `scapy` is not installed, live mode will show a helpful error.

## Run Dashboard

First analyze or monitor some data, then start:

```bash
python main.py dashboard
```

Open `http://127.0.0.1:5000`

Default login:

- Username: `admin`
- Password: `admin123`

For safer local use, override them with environment variables before starting the dashboard:

```powershell
$env:IDS_DASHBOARD_PASSWORD="your-strong-password"
$env:IDS_SECRET_KEY="your-long-random-secret"
python main.py dashboard
```

Supported overrides:

- `IDS_DASHBOARD_USERNAME`
- `IDS_DASHBOARD_PASSWORD`
- `IDS_DASHBOARD_PASSWORD_HASH`
- `IDS_DASHBOARD_PASSWORD_SALT`
- `IDS_SECRET_KEY`

Dashboard filters:

- Add `?severity=HIGH` to filter by severity
- Add `?src_ip=10.0.0.5` to filter by source IP
- Add `?rule=Port%20Scan` to filter by rule
- Add `?search=3389` to search descriptions, rules, and IPs
- Example: `http://127.0.0.1:5000/?severity=HIGH&src_ip=10.0.0.5`

Dashboard extras:

- Click a rule name to open the full alert detail view
- Use `/api/summary` for summary JSON
- Use `/api/alerts` for alert JSON
- Export directly from the dashboard with CSV and JSON links

## Export Alerts

Export stored alerts to CSV:

```bash
python main.py export --format csv --output exports/alerts.csv
```

Export stored alerts to JSON:

```bash
python main.py export --format json --output exports/alerts.json
```

## Input Format

Supported formats:

- `jsonl`
- `csv`
- `windows-events-json`
- `sysmon-json`
- `suricata-eve`
- `zeek-conn`
- `windows-firewall`

For Windows export workflows, you can prepare JSONL input with PowerShell and then analyze it with this project.

Example for failed logons from the Security log:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
Select-Object TimeCreated, Id, MachineName, @{Name='IpAddress';Expression={$_.Properties[19].Value}} |
ForEach-Object {
  [pscustomobject]@{
    TimeCreated = $_.TimeCreated.ToString("s")
    EventID = $_.Id
    Computer = $_.MachineName
    IpAddress = $_.IpAddress
  } | ConvertTo-Json -Compress
} | Set-Content sample_data\windows_events.jsonl
```

Each line in the JSONL file should be a JSON object like this:

```json
{
  "timestamp": "2026-04-01T12:00:00",
  "src_ip": "192.168.1.10",
  "dst_ip": "192.168.1.20",
  "protocol": "TCP",
  "src_port": 50500,
  "dst_port": 22,
  "size": 120,
  "event_type": "login_failed"
}
```

## Detection Rules

Current rules are intentionally simple and configurable:

1. Port scan: too many unique destination ports from the same source in a short time
2. Brute force login: repeated `login_failed` or failed `auth` events from the same source
3. Suspicious port: traffic to configured risky ports such as `23`, `3389`, and `4444`
4. Traffic burst: unusually high packet count from one source in a short time window

## Configuration

Edit `config/ids_config.json` to tune:

- Detection thresholds
- Suspicious ports
- Allowlisted IPs
- Database path
- Dashboard username and password hash
- Auto-block behavior

By default, auto-blocking is disabled and the system runs in safe simulation mode.

## Testing

Run:

```bash
python -m unittest discover -s tests
```

## Notes On Production Readiness

- This is now a stronger MVP, but it still needs hardening before production.
- Replace the demo dashboard password and secret key.
- Firewall automation may require administrator rights.
- For enterprise use, add stronger auth, HTTPS, audit logs, and integrations with real network devices.
