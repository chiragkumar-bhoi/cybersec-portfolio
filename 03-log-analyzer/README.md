# Log Analyzer — Brute-Force & Anomaly Detection

Parses SSH/auth-style logs and flags signs of brute-force login attempts and unusual login
times, with a plain-language summary report.

## What it does

1. **Parses** log lines in common auth-log formats (e.g. Linux `/var/log/auth.log` style:
   `Failed password for <user> from <ip> port <port> ssh2`)
2. **Detects brute-force patterns** — flags any source IP with more than N failed attempts
   within a time window
3. **Detects unusual login times** — flags successful logins outside a configurable
   "normal hours" window (e.g. outside 7am-11pm)
4. **Reports** a summary of suspicious IPs, usernames targeted, and timing anomalies

## Why this project

Log analysis is one of the most practical blue-team skills — most real intrusions leave
traces in logs long before anyone notices anything else wrong. This demonstrates:

- Regex-based log parsing
- Time-windowed aggregation (a simplified version of what a real SIEM does)
- Turning raw log noise into an actionable summary

## Setup

No external dependencies — pure Python standard library.

## Usage

```bash
# Analyze a real log file
python analyzer.py --log /var/log/auth.log

# Try it on the included sample log (safe, synthetic data)
python analyzer.py --log sample_data/sample_auth.log
```

Example output:

```
Parsed 214 log lines (2026-09-20 00:03:11 to 2026-09-21 23:58:47)

⚠ Brute-force suspects (5+ failed attempts within 10 minutes):
  203.0.113.45 — 47 failed attempts targeting users: root, admin, test
  198.51.100.9 — 12 failed attempts targeting users: admin

⚠ Unusual-hour logins (outside 07:00-23:00):
  Successful login for 'deploy' from 192.0.2.15 at 2026-09-21 03:14:02

Summary: 2 brute-force suspects, 1 unusual-hour login, out of 214 total log lines.
```

## Notes on the sample data

`sample_data/sample_auth.log` is entirely synthetic — fake IPs (from the [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)
documentation ranges), fake usernames, generated for this project. No real log data is
included in this repo.
