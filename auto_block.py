#!/usr/bin/env python3
"""Block repeat or dangerous attackers at the host firewall.

SAFE BY DEFAULT: prints what it WOULD do. Pass --apply (as root) to act.

Policy: block a source when it triggers a critical alert, or any `--min-alerts`
alerts, or has an AbuseIPDB score >= `--min-abuse`. Never blocks private,
loopback or allowlisted addresses. Commands are run without a shell and only
with a validated IP, so alert content can never inject arguments.

Design note: on a honeypot you usually WANT attackers to keep talking, so the
useful target for blocking is your *real* services and other hosts. Tune the
policy (or run with --after-capture) to avoid starving the honeypot of data.
"""
import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import alerts_from_stdin, allowlisted, emit, is_public_ip  # noqa: E402

STATE = Path(os.environ.get("BLOCK_STATE", "state/blocklist.json"))


def load_state():
    try:
        return set(json.loads(STATE.read_text()))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def save_state(blocked):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(sorted(blocked), indent=2))


def should_block(alert, counts, args):
    if alert.get("severity") == "critical":
        return "critical alert"
    if counts[alert["src_ip"]] >= args.min_alerts:
        return f">= {args.min_alerts} alerts"
    score = (alert.get("intel") or {}).get("abuse_score")
    if score is not None and score >= args.min_abuse:
        return f"abuse score {score}"
    return None


def block(ip, apply):
    cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    if not apply:
        print(f"[dry-run] would run: {' '.join(cmd)}", file=sys.stderr)
        return True
    try:
        subprocess.run(cmd, check=True, timeout=10)
        return True
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        print(f"block failed for {ip}: {exc}", file=sys.stderr)
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--apply", action="store_true", help="really modify the firewall")
    ap.add_argument("--min-alerts", type=int, default=5)
    ap.add_argument("--min-abuse", type=int, default=80)
    args = ap.parse_args()

    blocked = load_state()
    counts = Counter()
    for alert in alerts_from_stdin():
        ip = alert.get("src_ip")
        counts[ip] += 1
        reason = should_block(alert, counts, args) if ip else None
        if reason and ip not in blocked:
            if not is_public_ip(ip) or allowlisted(ip):
                print(f"refusing to block {ip}: private or allowlisted", file=sys.stderr)
            elif block(ip, args.apply):
                alert["action"] = f"{'blocked' if args.apply else 'would_block'} ({reason})"
                if args.apply:
                    blocked.add(ip)
        emit(alert)
    if args.apply:
        save_state(blocked)


if __name__ == "__main__":
    main()
