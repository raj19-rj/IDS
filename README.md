# Intrusion Detection System

This project is a starter network intrusion detection system (IDS) written in Python.

It supports:

- Offline analysis from a JSONL event file
- Optional live packet capture with `scapy`
- Rule-based alerts for:
  - Port scan behavior
  - Repeated failed login attempts
  - Suspicious port usage
  - Traffic bursts from a single source

## Project Structure

- `main.py` - command line entrypoint
- `ids/models.py` - event and alert data models
- `ids/detector.py` - detection engine and rules
- `ids/sniffer.py` - optional live capture support
- `sample_data/events.jsonl` - sample traffic events for testing

## Requirements

- Python 3.10+
- Optional: `scapy` for live sniffing

Install optional dependency:

```bash
pip install -r requirements.txt
```

## Run With Sample Data

```bash
python main.py --input sample_data/events.jsonl
```

## Run Live Capture

```bash
python main.py --live --interface Ethernet
```

Notes:

- Live capture may require administrator privileges.
- If `scapy` is not installed, live mode will show a helpful error.

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

Current rules are intentionally simple and easy to extend:

1. Port scan: too many unique destination ports from the same source in a short time
2. Brute force login: repeated `login_failed` events from the same source
3. Suspicious port: traffic to well-known risky ports such as `23`, `3389`, and `4444`
4. Traffic burst: unusually high packet count from one source in a short time window

## Next Improvements

- Add allowlists and blocklists
- Export alerts to CSV or SIEM-compatible formats
- Add email or webhook notifications
- Train anomaly-based models on historical traffic
