#!/usr/bin/env python3
"""
Password Strength Checker + Breach Lookup

Scores a password's strength locally and checks it against known data breaches
via the Have I Been Pwned Pwned Passwords API, using k-anonymity so the real
password never leaves your machine.
"""

import argparse
import getpass
import hashlib
import re
import sys
from dataclasses import dataclass, field

import requests

HIBP_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"

# A small sample of extremely common passwords for local pattern checks.
# (The real breach check against HIBP catches far more than this list ever could.)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "iloveyou", "admin", "letmein",
    "welcome", "monkey", "dragon", "football",
}

SEQUENTIAL_PATTERNS = [
    "0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm",
]


@dataclass
class StrengthResult:
    score: int = 0
    max_score: int = 5
    checks: list = field(default_factory=list)  # list of (passed: bool, message: str)

    def add(self, passed: bool, message: str):
        self.checks.append((passed, message))
        if passed:
            self.score += 1

    @property
    def label(self) -> str:
        if self.score <= 1:
            return "VERY WEAK"
        if self.score == 2:
            return "WEAK"
        if self.score == 3:
            return "MODERATE"
        if self.score == 4:
            return "STRONG"
        return "VERY STRONG"


def has_sequential_pattern(password: str, min_run: int = 4) -> bool:
    lower = password.lower()
    for pattern in SEQUENTIAL_PATTERNS:
        for i in range(len(pattern) - min_run + 1):
            chunk = pattern[i : i + min_run]
            if chunk in lower:
                return True
            # also check the reverse (e.g. "9876")
            if chunk[::-1] in lower:
                return True
    return False


def has_repeated_chars(password: str, run_length: int = 3) -> bool:
    return bool(re.search(r"(.)\1{" + str(run_length - 1) + ",}", password))


def check_strength(password: str) -> StrengthResult:
    result = StrengthResult()

    result.add(
        len(password) >= 12,
        "Length is 12+ characters" if len(password) >= 12 else "Too short (12+ characters recommended)",
    )

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    result.add(
        has_upper and has_lower,
        "Contains uppercase and lowercase" if has_upper and has_lower else "Missing uppercase or lowercase letters",
    )

    has_digit = any(c.isdigit() for c in password)
    result.add(
        has_digit,
        "Contains digits" if has_digit else "No digits found",
    )

    has_symbol = bool(re.search(r"[^\w\s]", password))
    result.add(
        has_symbol,
        "Contains special characters" if has_symbol else "No special characters",
    )

    no_common_patterns = (
        password.lower() not in COMMON_PASSWORDS
        and not has_sequential_pattern(password)
        and not has_repeated_chars(password)
    )
    result.add(
        no_common_patterns,
        "No obvious common patterns detected"
        if no_common_patterns
        else "Contains a common password, keyboard sequence, or repeated characters",
    )

    return result


def check_breach(password: str) -> int:
    """
    Returns the number of times this password has appeared in known breaches,
    using the HIBP Pwned Passwords k-anonymity API. Only the first 5 hex
    characters of the SHA-1 hash are ever sent over the network.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(HIBP_API_URL.format(prefix=prefix), timeout=10)
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"  (Could not reach breach database: {exc})", file=sys.stderr)
        return -1  # unknown

    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0


def print_report(password: str, result: StrengthResult, breach_count: int):
    print(f"\nPassword strength: {result.label} ({result.score}/{result.max_score})")
    for passed, message in result.checks:
        mark = "✓" if passed else "✗"
        print(f"  {mark} {message}")

    if breach_count > 0:
        print(f"  ✗ Found in {breach_count:,} known data breaches — change this password immediately.")
    elif breach_count == 0:
        print("  ✓ Not found in known breaches")
    # breach_count == -1 means the lookup failed; message already printed.

    if result.score < result.max_score or breach_count != 0:
        print("\nSuggestions:")
        print("  - Use a passphrase of 4+ random words instead of a single word + numbers")
        print("  - Avoid keyboard patterns, common words, and years")
        print("  - Use a password manager to generate and store unique passwords per site")


def main():
    parser = argparse.ArgumentParser(description="Check password strength and breach history.")
    parser.add_argument(
        "--password",
        help="Password to check (avoid using this flag on shared machines — it may be saved in shell history)",
    )
    parser.add_argument(
        "--no-breach-check",
        action="store_true",
        help="Skip the online breach check (strength scoring only, fully offline)",
    )
    args = parser.parse_args()

    password = args.password or getpass.getpass("Enter password to check (input hidden): ")
    if not password:
        print("No password entered.", file=sys.stderr)
        sys.exit(1)

    result = check_strength(password)
    breach_count = -1 if args.no_breach_check else check_breach(password)
    print_report(password, result, breach_count)


if __name__ == "__main__":
    main()
