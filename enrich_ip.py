#!/usr/bin/env python3
"""Add threat-intel context to alerts using AbuseIPDB (optional).

Usage: python detections/engine.py ... --json | python automation/enrich_ip.py
Needs ABUSEIPDB_API_KEY; without it alerts pass through unchanged.
Results are cached in memory for the run to respect the free-tier quota.
"""
import json
import os
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from common import alerts_from_stdin, emit, is_public_ip  # noqa: E402

API = "https://api.abuseipdb.com/api/v2/check"
_cache = {}


def lookup(ip, key, timeout=10):
    if ip in _cache:
        return _cache[ip]
    req = urllib.request.Request(
        f"{API}?{urllib.parse.urlencode({'ipAddress': ip, 'maxAgeInDays': 90})}",
        headers={"Key": key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.load(resp)["data"]
        intel = {
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports"),
        }
    except Exception as exc:  # network errors must never break the pipeline
        print(f"enrich failed for {ip}: {exc}", file=sys.stderr)
        intel = None
    _cache[ip] = intel
    return intel


def main():
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        print("ABUSEIPDB_API_KEY not set: skipping enrichment", file=sys.stderr)
    for alert in alerts_from_stdin():
        ip = alert.get("src_ip")
        if key and is_public_ip(ip):
            intel = lookup(ip, key)
            if intel:
                alert["intel"] = intel
        emit(alert)


if __name__ == "__main__":
    main()
