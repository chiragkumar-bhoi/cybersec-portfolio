# Password Strength Checker + Breach Lookup

A command-line tool that scores a password's strength and checks whether it has appeared in
known data breaches — without ever sending your actual password anywhere.

## What it does

1. **Strength scoring** — checks length, character variety (upper/lower/digits/symbols),
   common patterns (repeated characters, sequences like `1234` or `abcd`), and whether it's
   in a list of the most common leaked passwords.
2. **Breach check** — uses the [Have I Been Pwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
   with **k-anonymity**: only the first 5 characters of your password's SHA-1 hash are ever
   sent over the network, so the real password (and even the full hash) never leaves your
   machine.

## Why this project

This is a genuinely useful security tool (not just a toy), and it demonstrates:
- Understanding of password entropy and common attack patterns
- Safe use of a real security API (k-anonymity model)
- Basic hashing (SHA-1) and HTTP requests in Python

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python checker.py
# or check a password non-interactively (careful with shell history!):
python checker.py --password "hunter2"
```

Example output:

```
Password strength: WEAK (2/5)
  ✗ Too short (8+ characters recommended)
  ✓ Contains uppercase and lowercase
  ✗ No special characters
  ✗ Found in 1,306,494 known data breaches — change this password immediately.

Suggestions:
  - Use a passphrase of 4+ random words instead of a single word + numbers
  - Avoid keyboard patterns and years
```

## How the breach check stays private

Have I Been Pwned's Pwned Passwords API is designed so you never send a plaintext password
or even a full hash. The tool:

1. Computes `SHA1(password)` locally
2. Sends only the first 5 hex characters of that hash to the API
3. The API returns *all* hash suffixes that start with those 5 characters
4. The tool checks locally whether your full hash is in that list

This means the real password never leaves your computer, and even Have I Been Pwned
can't tell which password you checked.

## Notes

- This tool does not store or log any password you check.
- No API key required — the Pwned Passwords endpoint is public and free.
