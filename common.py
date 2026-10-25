"""Shared helpers: every automation script is a JSONL filter (stdin -> stdout)."""
import ipaddress
import json
import os
import sys


def alerts_from_stdin():
    for line in sys.stdin:
        line = line.strip()
        if line:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                print("skipping malformed alert", file=sys.stderr)


def emit(alert):
    print(json.dumps(alert), flush=True)


def is_public_ip(value):
    """True only for a syntactically valid, globally routable address."""
    try:
        ip = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return False
    return ip.is_global


def allowlisted(value):
    """Check ALLOWLIST env var (comma-separated IPs/CIDRs). Admin IPs must never be blocked."""
    try:
        ip = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return True  # if we cannot parse it, never act on it
    for item in filter(None, (s.strip() for s in os.environ.get("ALLOWLIST", "").split(","))):
        try:
            if ip in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False
