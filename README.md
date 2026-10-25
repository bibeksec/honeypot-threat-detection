# Honeypot-Driven Threat Detection & Response Lab

[![ci](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.12-blue) ![license](https://img.shields.io/badge/license-MIT-green)

A blue-team lab that **captures real internet attacks** with a Cowrie SSH/Telnet
honeypot, ships them into the Elastic Stack, **detects** malicious behaviour with
10 version-controlled rules mapped to MITRE ATT&CK, **enriches** sources with threat
intel, and **responds** automatically (alerting and optional firewall blocking).

<!-- Add after your deployment: ![Dashboard](docs/screenshots/dashboard.png) -->

## Highlights
- **Detection-as-code:** YAML rules, a small engine, and unit tests that fail CI if any rule lacks coverage
- **Runs anywhere:** the detection engine needs only Python + PyYAML; no infrastructure to test rules
- **Safe automation:** dry-run by default, strict IP validation, no shell execution, allowlist, private ranges never blocked
- **Reproducible stack:** one `docker compose up`
- **Real data:** findings report template for a 2-4 week deployment

## Architecture
See [docs/architecture.md](docs/architecture.md).
<img width="2720" height="2760" alt="honeypot_detection_response_flow" src="https://github.com/user-attachments/assets/8edbdaae-fe96-406c-9bc2-38a25b79420b" />


```
Attackers -> Cowrie -> Filebeat -> Elasticsearch -> Kibana
                 \-> engine.py -> enrich_ip.py -> auto_block.py -> alert_bot.py
```

## Quick start (no server needed)
```bash
pip install -r requirements.txt
make test      # 10 tests
make demo      # replay a synthetic attack chain through the whole pipeline
```

## Full deployment
Follow [docs/setup-guide.md](docs/setup-guide.md). Short version:
```bash
cp .env.example .env && docker compose up -d
```

## Detection rules
Full table with links: [detections/attack-mapping.md](detections/attack-mapping.md)

| ID | Detects | ATT&CK |
|----|---------|--------|
| HP-001 | SSH brute force (10 fails / 60s) | T1110.001 |
| HP-002 | Password spraying (5+ usernames / 5 min) | T1110.003/.004 |
| HP-003 | Successful honeypot login | T1078 |
| HP-004 | Recon commands | T1082, T1033 |
| HP-005 | Payload download via wget/curl/tftp | T1105 |
| HP-006 | Download piped to shell | T1059.004 |
| HP-007 | authorized_keys persistence | T1098.004 |
| HP-008 | Cryptominer indicators | T1496 |
| HP-009 | History/log tampering | T1070.003 |
| HP-010 | Malware sample captured | T1105, T1204 |

**Adding a rule:** drop a `.yml` in `detections/rules/`, add a triggering event to
`detections/tests/make_sample.py`, run `make rules-doc test`.

## Results
_Fill in after your run: see [docs/findings-report.md](docs/findings-report.md)._

## Roadmap
- Sigma rule export, Elastic detection-rule export
- Sandbox detonation of captured samples (isolated, offline)
- GeoIP map and attacker-clustering by command similarity
- Session-sequence rules (login success followed by download)

## Responsible use
Deploy **only on infrastructure you own**, isolated from real systems, and within your
provider's terms. Never commit `.env`, keys, or captured malware binaries (store hashes).
Defensive research tool; not for attacking anyone.
