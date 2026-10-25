# Findings report (template)

**Period:** YYYY-MM-DD to YYYY-MM-DD   **Host:** 1 VPS, Cowrie medium-interaction

## Headline numbers
| Metric | Value |
|--------|-------|
| Total connection attempts | |
| Unique source IPs | |
| Successful honeypot logins | |
| Sessions with commands | |
| Malware samples captured (unique SHA-256) | |

## Attack trends
- Top 10 usernames / passwords:
- Top source countries and ASNs:
- Time-of-day patterns:

## Attacker behaviour
Walk through 2-3 representative sessions: initial access, recon, payload delivery,
persistence. Include the commands (sanitised) and the rule IDs that fired.

## Malware
| SHA-256 | VirusTotal verdict / family | First seen | Source URL (defanged) |
|---------|-----------------------------|------------|-----------------------|

## Detection performance
Per rule: alert count, false positives, tuning applied. What did you miss?

## Lessons learned / future work
