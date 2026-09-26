# Cloud Network Topology — Simulated Enterprise Segmentation

**Status: Planned — needs cloud VMs (Azure/DigitalOcean via GitHub Student Developer Pack)**

## Plan

Build a small simulated enterprise network in the cloud, demonstrating proper network
segmentation:

```
                    ┌──────────────┐
   Internet ───────▶│   Firewall/   │
                    │  Edge Router  │
                    └──────┬───────┘
                           │
                ┌──────────┴──────────┐
                │                     │
          ┌─────▼─────┐        ┌──────▼──────┐
          │    DMZ     │        │   Internal   │
          │ (web server)│        │   Subnet     │
          └────────────┘        │ (DB, internal│
                                 │   services)  │
                                 └──────────────┘
```

1. **DMZ subnet** — a public-facing web server, isolated from internal resources
2. **Internal subnet** — database/internal services, *not* directly reachable from the
   internet — only from the DMZ, on specific ports
3. **Firewall rules** — explicit allow-list rules (default-deny), documented with the
   reasoning for each rule
4. **Testing** — verify segmentation actually works (e.g. confirm the DB is unreachable
   directly from the internet, but reachable from the web server on the DB port only)

## Why this project

Network segmentation is a foundational defense-in-depth concept — most real breaches
escalate because a compromised public-facing box has unrestricted access to everything
else. This demonstrates:

- Practical understanding of subnets, routing, and firewall rules
- Defense-in-depth thinking (not just "one big flat network")
- Documentation skills — a network nobody can understand isn't secure, it's just confusing

## Prerequisites

- [ ] GitHub Student Developer Pack → Azure/DigitalOcean credits
- [ ] Builds on cloud skills from [06-vulnerable-lab](../06-vulnerable-lab)

## TODO once started

- [ ] Network diagram (finalized, with actual IP ranges used)
- [ ] Firewall rule set with reasoning per rule
- [ ] Verification steps/screenshots showing segmentation actually holds
