# CTF Write-ups

Write-ups of Capture The Flag challenges I've solved, documenting the approach, tools used,
and what I learned — not just the flag.

## Status: Ongoing

This isn't a one-time build — it grows as I solve challenges. Suggested platforms to start
with (all have beginner-friendly free tiers):

- [TryHackMe](https://tryhackme.com/) — guided rooms, great for absolute beginners
- [picoCTF](https://picoctf.org/) — free, aimed at students, very approachable
- [HackTheBox](https://www.hackthebox.com/) — more advanced, less hand-holding

## Structure

```
05-ctf-writeups/
  tryhackme/
    <room-name>/
      README.md       # approach, tools, what I learned
  picoctf/
    <challenge-name>/
      README.md
```

## Write-up template

Each write-up should cover, at minimum:

1. **Challenge summary** — category (web, crypto, forensics, pwn, etc.) and difficulty
2. **Approach** — how I started investigating, what I tried
3. **Tools used** — e.g. Burp Suite, nmap, CyberChef, Wireshark
4. **Solution** — the key steps that led to the flag (without literally posting the flag
   itself, per most platforms' rules on active/current challenges)
5. **What I learned** — the actual takeaway, not just "got the flag"

## A note on ethics/rules

Most platforms ask you not to publicly post flags for *currently active* challenges/events
(to keep them fair for other players). This repo will follow whatever the source platform's
write-up policy says — usually fine once a room/challenge is no longer part of a timed event.
