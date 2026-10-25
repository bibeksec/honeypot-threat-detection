#!/usr/bin/env python3
"""Send alerts to Telegram and/or Discord. Prints to stdout when neither is configured.

Env: TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID, and/or DISCORD_WEBHOOK_URL.
Only alerts at or above --min-severity are sent. Attacker-controlled text is
truncated and sent as plain text (no parse_mode) so it cannot inject markup.
"""
import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from common import alerts_from_stdin, emit  # noqa: E402

ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
ICON = {"low": "i", "medium": "!", "high": "!!", "critical": "!!!"}


def format_alert(a):
    detail = str(a.get("detail") or "")[:120]
    intel = a.get("intel") or {}
    lines = [
        f"[{ICON[a['severity']]}] {a['severity'].upper()} {a['rule_id']}: {a['title']}",
        f"src {a.get('src_ip')} ({intel.get('country', '?')}, abuse {intel.get('abuse_score', '?')})",
        f"ATT&CK {', '.join(a.get('attack', []))}",
    ]
    if detail:
        lines.append(f"detail: {detail}")
    if a.get("action"):
        lines.append(f"action: {a['action']}")
    return "\n".join(lines)


def post(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as exc:
        print(f"notify failed: {exc}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--min-severity", choices=ORDER, default="high")
    args = ap.parse_args()
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID")
    discord = os.environ.get("DISCORD_WEBHOOK_URL")

    for alert in alerts_from_stdin():
        if ORDER.get(alert.get("severity"), 0) >= ORDER[args.min_severity]:
            text = format_alert(alert)
            sent = False
            if tg_token and tg_chat:
                post(f"https://api.telegram.org/bot{tg_token}/sendMessage",
                     {"chat_id": tg_chat, "text": text})
                sent = True
            if discord:
                post(discord, {"content": text[:1900]})
                sent = True
            if not sent:
                print(text + "\n", file=sys.stderr)
        emit(alert)


if __name__ == "__main__":
    main()
