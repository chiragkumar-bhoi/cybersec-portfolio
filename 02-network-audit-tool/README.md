# Home Network Security Audit Tool

A Python tool that discovers devices on your local network, scans them for open ports, and
flags commonly risky services — with a plain-language report at the end.

## What it does

1. **Host discovery** — finds live devices on your subnet (e.g. `192.168.1.0/24`)
2. **Port scan** — checks each live host against a list of common ports
3. **Risk flagging** — flags well-known risky/legacy services if found open
   (e.g. Telnet, FTP, unauthenticated RDP/VNC, SMBv1)
4. **Report** — prints a summary, and can export to JSON/HTML

## Why this project

Home/small-network audits are a real, foundational security skill: understanding what's
actually reachable on your network is step one before you can secure it. This project
demonstrates:

- Practical use of `nmap` (via `python-nmap`) or raw sockets as a fallback
- Understanding of common ports/services and why certain ones are risky
- Structuring scan results into a usable report

## ⚠️ Legal/ethical note

**Only scan networks you own or have explicit permission to scan.** Port scanning networks
you don't control can be illegal in many jurisdictions, even if unintentional. This tool
defaults to your own local subnet and warns before scanning anything else.

## Setup

Requires `nmap` installed on your system (the tool falls back to a slower pure-Python scan
if `nmap` isn't available):

```bash
# Debian/Ubuntu
sudo apt install nmap

# macOS
brew install nmap

pip install -r requirements.txt
```

## Usage

```bash
# Auto-detect your local subnet and scan it
python audit.py

# Specify a subnet explicitly
python audit.py --subnet 192.168.1.0/24

# Export a JSON report
python audit.py --output report.json
```

Example output:

```
Scanning 192.168.1.0/24 ...
Found 6 live hosts.

192.168.1.1  (router)
  Open ports: 80 (http), 443 (https), 53 (dns)
  ⚠  Port 23 (telnet) is open — legacy, unencrypted, high risk. Disable if unused.

192.168.1.14
  Open ports: 22 (ssh)

Summary: 1 host flagged with risky open ports out of 6 scanned.
```

## Risky-service list

The tool flags these by default (see `RISKY_PORTS` in `audit.py`):

| Port | Service | Why it's risky |
|---|---|---|
| 21 | FTP | Unencrypted credentials/data |
| 23 | Telnet | Fully unencrypted remote access |
| 139/445 | SMB | Historically exploited (e.g. WannaCry via SMBv1) |
| 3389 | RDP | Common brute-force/ransomware target if exposed |
| 5900 | VNC | Often unauthenticated by default |
