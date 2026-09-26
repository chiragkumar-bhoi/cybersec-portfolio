# Mini SIEM Dashboard

**Status: Planned — needs a cloud VM (Azure/DigitalOcean via GitHub Student Developer Pack)**

## Plan

Bring together ideas from [03-log-analyzer](../03-log-analyzer) and
[07-cloud-network-topology](../07-cloud-network-topology) into a small, real log
ingestion + alerting dashboard:

1. **Ingest** logs from the cloud VM(s) built in project 7 (auth logs, firewall logs)
2. **Store/index** them — either a lightweight ELK (Elasticsearch/Logstash/Kibana) stack,
   or a simpler alternative like Grafana + Loki if resources are limited
3. **Alert rules** — reuse/extend the brute-force and unusual-hour logic from project 3,
   but running continuously instead of on a static log file
4. **Dashboard** — a simple view showing recent alerts, top source IPs, login trends over
   time

## Why this project

This ties the whole portfolio together: it's the "so what" that shows these individual
skills (log parsing, cloud infra, network segmentation) compose into something like a real
security monitoring setup — the kind of thing a SOC analyst works with daily.

## Prerequisites

- [ ] Depends on [06-vulnerable-lab](../06-vulnerable-lab) and
      [07-cloud-network-topology](../07-cloud-network-topology) being set up first,
      since this project ingests their logs
- [ ] GitHub Student Developer Pack → cloud credits

## TODO once started

- [ ] Decide on stack (ELK vs. Grafana+Loki vs. something lighter)
- [ ] Log shipping setup (e.g. Filebeat/Vector from source VMs)
- [ ] Port the alert rules from project 3 to run continuously
- [ ] Dashboard screenshots + a short demo write-up
