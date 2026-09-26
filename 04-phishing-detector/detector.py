#!/usr/bin/env python3
"""
Phishing Detection Tool

Analyzes a raw .eml email or a single URL for common phishing indicators and
produces a heuristic risk score (0-100).

This is a rules-based learning project, not a production-grade spam filter.
"""

import argparse
import email
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

# A small list of commonly-impersonated brand domains, for typosquat comparison.
# (A real tool would use a much larger, regularly-updated brand/domain list.)
KNOWN_BRAND_DOMAINS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "netflix.com", "facebook.com", "instagram.com", "bankofamerica.com",
    "chase.com", "wellsfargo.com", "humber.ca", "office365.com", "dropbox.com",
]

URGENCY_PHRASES = [
    "act now", "verify your account", "account will be suspended",
    "account has been locked", "immediate action required", "urgent",
    "confirm your identity", "unusual activity", "click here immediately",
    "your account will be closed", "verify immediately", "suspended",
]

SUSPICIOUS_URL_KEYWORDS = ["verify", "secure", "account", "update", "confirm", "login", "signin"]

URL_RE = re.compile(r"https?://[^\s\"'<>\)]+", re.IGNORECASE)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr_row[j] = min(
                prev_row[j] + 1,      # deletion
                curr_row[j - 1] + 1,  # insertion
                prev_row[j - 1] + cost,  # substitution
            )
        prev_row = curr_row
    return prev_row[-1]


def extract_domain(url_or_email_domain: str) -> str:
    if "@" in url_or_email_domain and "://" not in url_or_email_domain:
        return url_or_email_domain.split("@")[-1].lower().strip(">").strip()
    parsed = urlparse(url_or_email_domain if "://" in url_or_email_domain else f"http://{url_or_email_domain}")
    return parsed.netloc.lower()


LEETSPEAK_MAP = str.maketrans({"1": "l", "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


def normalize_label(label: str) -> str:
    """Normalize common leetspeak substitutions used in typosquatting."""
    return label.lower().translate(LEETSPEAK_MAP)


def closest_brand_domain(domain: str):
    """
    Returns (brand_domain, distance) if `domain` looks like a typosquat of a known brand.

    Catches three patterns:
      1. Small edit distance to the full brand domain (e.g. "gogle.com")
      2. The brand's normalized core name embedded in the first label, possibly with
         leetspeak substitutions and/or extra words (e.g. "paypa1-secure.com",
         "secure-paypal-login.net")
      3. The brand name used only as a subdomain prefix of an unrelated domain
         (e.g. "google.com.phishing.net") — a well-known confusion technique
    """
    domain = domain.split(":")[0].lower()  # strip port
    stripped = domain[4:] if domain.startswith("www.") else domain

    # A domain equal to, or a genuine subdomain of, a known brand is not a typosquat.
    for brand in KNOWN_BRAND_DOMAINS:
        if stripped == brand or stripped.endswith("." + brand):
            return None

    first_label = domain.split(".")[0]
    normalized_label = normalize_label(first_label)

    best = None
    best_dist = None

    for brand in KNOWN_BRAND_DOMAINS:
        brand_core = brand.split(".")[0]
        candidate_dist = None

        # Pattern 1: small whole-domain edit distance, only for domains of similar
        # length to the brand (catches e.g. "gogle.com", "microsfot.com") — restricting
        # to similar lengths avoids flagging unrelated short domains as false positives.
        if abs(len(stripped) - len(brand)) <= 3:
            whole_dist = levenshtein(stripped, brand)
            if whole_dist <= 2:
                candidate_dist = whole_dist

        # Pattern 2: brand core name embedded (with leetspeak) in the first label,
        # with extra words tacked on (e.g. "paypa1-secure", "secure-paypal-login")
        if brand_core in normalized_label and normalized_label != brand_core:
            embed_extra = len(normalized_label) - len(brand_core)
            embed_dist = min(embed_extra, 5)
            candidate_dist = embed_dist if candidate_dist is None else min(candidate_dist, embed_dist)

        # Pattern 3: brand name is exactly the first label, but the domain doesn't
        # actually belong to the brand (already excluded genuine brand/subdomain above)
        elif first_label == brand_core:
            candidate_dist = 3 if candidate_dist is None else min(candidate_dist, 3)

        if candidate_dist is not None and (best_dist is None or candidate_dist < best_dist):
            best, best_dist = brand, candidate_dist

    if best_dist is not None and 1 <= best_dist <= 5:
        return best, best_dist
    return None


def analyze_urls(urls: list, link_texts: list = None):
    findings = []
    for i, url in enumerate(urls):
        parsed = urlparse(url)
        host = parsed.netloc.lower()

        # IP address instead of domain
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host.split(":")[0]):
            findings.append((15, f"URL uses a raw IP address instead of a domain: {url}"))

        # '@' trick: http://real-looking-part@actual-domain.com
        if "@" in url.split("://", 1)[-1]:
            findings.append((20, f"URL contains an '@' character, which can hide the real destination: {url}"))

        # Excessive subdomains
        if host.count(".") >= 4:
            findings.append((10, f"URL has an unusually high number of subdomains: {host}"))

        # Suspicious keywords
        for kw in SUSPICIOUS_URL_KEYWORDS:
            if kw in url.lower():
                findings.append((5, f"URL contains suspicious keyword: '{kw}' ({url})"))
                break

        # Typosquat check
        typo = closest_brand_domain(host)
        if typo:
            brand, dist = typo
            findings.append((25, f"Domain '{host}' looks like a typosquat of '{brand}' (edit distance {dist})"))

        # Link text vs href mismatch
        if link_texts and i < len(link_texts) and link_texts[i]:
            text = link_texts[i]
            text_domain_match = re.search(r"([a-z0-9-]+\.[a-z]{2,})", text.lower())
            if text_domain_match and text_domain_match.group(1) not in host:
                findings.append(
                    (15, f"Link text says '{text_domain_match.group(1)}' but actually points to '{host}'")
                )

    return findings


def analyze_text(subject: str, body: str):
    findings = []
    combined = f"{subject} {body}".lower()
    matched_phrases = [p for p in URGENCY_PHRASES if p in combined]
    if matched_phrases:
        shown = ", ".join(f'"{p}"' for p in matched_phrases[:3])
        findings.append((20, f"Urgency language detected: {shown}"))
    return findings


def analyze_sender(from_header: str):
    findings = []
    match = re.match(r'^\s*"?([^"<]*)"?\s*<?([^<>]*)>?\s*$', from_header or "")
    if not match:
        return findings
    display_name, sender_email = match.group(1).strip(), match.group(2).strip()
    if not sender_email:
        return findings

    domain = extract_domain(sender_email)

    typo = closest_brand_domain(domain)
    if typo:
        brand, dist = typo
        findings.append((25, f"Sender domain '{domain}' looks like a typosquat of '{brand}' (edit distance {dist})"))

    if display_name:
        # If display name mentions a brand but domain doesn't match it at all
        for brand in KNOWN_BRAND_DOMAINS:
            brand_name = brand.split(".")[0]
            if brand_name in display_name.lower() and brand_name not in domain:
                findings.append(
                    (8, f"Sender display name '{display_name}' does not match sender domain '{domain}'")
                )
                break
    return findings


def analyze_eml(path: str):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg.get("Subject", "")
    from_header = msg.get("From", "")

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
    else:
        body = msg.get_content()

    urls = URL_RE.findall(body)

    findings = []
    findings += analyze_sender(from_header)
    findings += analyze_text(subject, body)
    findings += analyze_urls(urls)
    return findings, {"subject": subject, "from": from_header, "urls": urls}


def score_and_report(findings: list, label: str):
    score = min(sum(points for points, _ in findings), 100)
    print(f"Analyzing {label} ...\n")
    if score >= 60:
        risk = "HIGH RISK"
    elif score >= 30:
        risk = "MEDIUM RISK"
    elif score > 0:
        risk = "LOW RISK"
    else:
        risk = "NO SIGNALS DETECTED"

    print(f"Risk Score: {score}/100 ({risk})\n")
    if findings:
        print("Triggered checks:")
        for points, message in sorted(findings, key=lambda f: -f[0]):
            print(f"  [+{points:<3}] {message}")
    else:
        print("No phishing indicators detected by this tool (does not guarantee the message is safe).")

    if score >= 30:
        print(
            "\nRecommendation: Do not click any links. Verify by navigating to the official "
            "site directly, not through any link in this message."
        )


def main():
    parser = argparse.ArgumentParser(description="Heuristic phishing detector for emails and URLs.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--eml", help="Path to a raw .eml email file to analyze")
    group.add_argument("--url", help="A single URL to analyze")
    args = parser.parse_args()

    if args.eml:
        findings, _ = analyze_eml(args.eml)
        score_and_report(findings, args.eml)
    else:
        findings = analyze_urls([args.url])
        score_and_report(findings, args.url)


if __name__ == "__main__":
    main()
