# Vulnerable Lab in a Box

**Status: Planned — needs a cloud VM (Azure/DigitalOcean via GitHub Student Developer Pack)**

## Plan

Deploy a deliberately vulnerable web app (e.g. [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
or [DVWA](https://github.com/digininja/DVWA)) on a small cloud VM, then:

1. Document the environment setup (infrastructure-as-code preferred: a simple Terraform or
   cloud-init script, not manual clicking)
2. Work through a set of vulnerabilities (SQLi, XSS, broken auth, IDOR, etc.) — for each one:
   - Explain the vulnerability in plain language
   - Show how it's exploited (screenshots/commands)
   - Show the fix (code-level, not just "use a WAF")
3. Tear the VM down when not actively working on it (cost control + reduces exposure —
   never leave a deliberately vulnerable box running longer than needed, and never expose it
   to more of the internet than necessary)

## Why this project

Understanding vulnerabilities by exploiting them yourself (in a safe, isolated environment
you own) is one of the best ways to learn how to defend against them. This demonstrates:

- Basic infrastructure setup (cloud VM provisioning)
- Practical understanding of the OWASP Top 10
- Both offensive (exploit) and defensive (fix) thinking

## Safety notes

- Only ever expose this to the internet with a firewall rule restricting access to your own
  IP, or keep it on a private network / VPN
- Take it down when you're done with a session — don't leave it running as a standing target
- Never test techniques learned here against systems you don't own or have permission to test

## Prerequisites

- [ ] Register for GitHub Student Developer Pack
- [ ] Claim Azure for Students or DigitalOcean credits
- [ ] Pick a target app (Juice Shop recommended — actively maintained, great docs)

## TODO once started

- [ ] `setup/` — cloud-init or Terraform script to provision the VM
- [ ] `vulnerabilities/` — one folder per vulnerability with exploit + fix write-up
- [ ] Update this README's status to "In Progress" / "Done"
