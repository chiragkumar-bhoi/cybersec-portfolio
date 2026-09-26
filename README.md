# Cybersecurity Portfolio — Chiragkumar Bhoi

A collection of hands-on cybersecurity, networking, and cloud projects built while studying
Cybersecurity & Technical Computing at Humber Polytechnic. Each folder is a self-contained
project with its own README, code, and notes.

## Projects

| # | Project | Status | Description |
|---|---|---|---|
| 1 | [Password Strength Checker](./01-password-checker) | ✅ Done | CLI tool that scores password strength and checks it against known breaches (HaveIBeenPwned, k-anonymity model) |
| 2 | [Network Security Audit Tool](./02-network-audit-tool) | ✅ Done | Scans a local network for live hosts and open ports, flags risky services, generates a report |
| 3 | [Log Analyzer](./03-log-analyzer) | ✅ Done | Parses auth/SSH-style logs to detect brute-force attempts and unusual login times |
| 4 | [Phishing Detection Tool](./04-phishing-detector) | ✅ Done | Heuristic scoring of emails/URLs for common phishing indicators |
| 5 | [CTF Write-ups](./05-ctf-writeups) | 🚧 Ongoing | Write-ups of solved CTF challenges (TryHackMe / HackTheBox / picoCTF) |
| 6 | [Vulnerable Lab in a Box](./06-vulnerable-lab) | 📋 Planned | Deliberately vulnerable app/VM deployed on cloud credits, with exploit + fix documentation |
| 7 | [Cloud Network Topology](./07-cloud-network-topology) | 📋 Planned | Simulated enterprise network segmentation (firewall, DMZ, internal subnet) in the cloud |
| 8 | [Mini SIEM Dashboard](./08-siem-dashboard) | 📋 Planned | Log ingestion + alerting dashboard (ELK or lightweight alternative) on a cloud VM |

## Why this repo

Built to apply networking, cybersecurity, and cloud concepts from coursework in practical,
demonstrable form — and to have something concrete on GitHub before registering for the
[GitHub Student Developer Pack](https://education.github.com/pack).

## Setup

Each project folder has its own README with setup/run instructions. Most projects use Python 3.

```bash
# clone
git clone <this-repo-url>
cd cybersec-portfolio

# each project has its own requirements
cd 01-password-checker
pip install -r requirements.txt
```

## Roadmap

- [x] Projects 1-4: local, standalone tools
- [ ] Register for GitHub Student Developer Pack
- [ ] Projects 6-8: cloud-based, using free Azure/DigitalOcean student credits
- [ ] Project 5: ongoing, added to as CTF challenges are solved
