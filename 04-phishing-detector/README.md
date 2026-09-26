# Phishing Detection Tool

Analyzes a raw email (`.eml`) or a single URL and produces a heuristic phishing risk score,
explaining which signals contributed.

## What it does

Checks for common phishing indicators:

- **Sender/display-name mismatch** (e.g. display name "PayPal Support" but domain is
  `paypa1-secure.com`)
- **Look-alike domains** (typosquatting: character substitution, extra hyphens, wrong TLD)
- **URL red flags** — IP address instead of domain, `@` tricks in URLs, excessive
  subdomains, suspicious keywords like `verify`, `urgent`, `account-locked`
- **Urgency/pressure language** in the subject/body ("act now", "your account will be
  suspended", "verify immediately")
- **Mismatched link text vs. actual href** (link says `paypal.com` but points elsewhere)

Produces a 0-100 risk score and a breakdown of which checks triggered.

## Why this project

Phishing is still the #1 initial-access vector in most breaches. This project demonstrates:

- Practical email/URL parsing
- Understanding of real phishing techniques (not just spam-filter keyword matching)
- Turning multiple weak signals into a combined risk score (a simplified rules engine)

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Analyze a raw email file
python detector.py --eml sample_data/phishing_sample.eml

# Analyze a single URL
python detector.py --url "http://paypa1-secure-login.com/verify"
```

Example output:

```
Analyzing sample_data/phishing_sample.eml ...

Risk Score: 78/100 (HIGH RISK)

Triggered checks:
  [+25] Sender domain 'paypa1-secure.com' looks like a typosquat of 'paypal.com'
  [+20] Urgency language detected: "verify your account immediately", "will be suspended"
  [+15] Link text says 'paypal.com' but actually points to 'paypa1-secure.com/login'
  [+10] URL contains suspicious keyword: 'verify'
  [+8]  Sender display name 'PayPal Security' does not match sender domain

Recommendation: Do not click any links in this email. Verify by navigating to the
official site directly, not through any link in this message.
```

## Notes

- This is a heuristic/rules-based tool for learning purposes, not a production spam
  filter — real filters combine this kind of logic with reputation databases, SPF/DKIM/DMARC
  validation, and ML models trained on huge datasets.
- `sample_data/phishing_sample.eml` is a synthetic example I wrote for testing — not a real
  captured phishing email.
