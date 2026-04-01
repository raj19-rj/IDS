# Intrusion Detection System

This project is a starter network intrusion detection system (IDS) written in Python.

It now supports:

- Offline analysis from JSONL and CSV event files
- Continuous monitoring mode for tailed log files
- Optional live packet capture with `scapy`
- Persistent alert storage with SQLite
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
- `ids/ingest.py` - JSONL and CSV loaders
- `ids/monitor.py` - continuous monitoring loop
- `ids/responders.py` - optional automated response actions
- `ids/storage.py` - SQLite persistence
- `ids/web.py` - Flask dashboard
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

Change the dashboard credentials in `config/ids_config.json` before using this anywhere real.

## Input Format

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
- Replace the demo dashboard secret and password hash.
- Firewall automation may require administrator rights.
- For enterprise use, add stronger auth, HTTPS, audit logs, and integrations with real network devices.
