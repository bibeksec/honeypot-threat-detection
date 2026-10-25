import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detections"))
sys.path.insert(0, str(ROOT / "automation"))

import engine  # noqa: E402
from auto_block import should_block  # noqa: E402
from collections import Counter  # noqa: E402
from common import allowlisted, is_public_ip  # noqa: E402
import argparse  # noqa: E402

RULES = engine.load_rules(ROOT / "detections" / "rules")
SAMPLE = ROOT / "detections" / "tests" / "sample_cowrie.jsonl"


def alerts_for(events):
    return list(engine.run(RULES, events))


class RuleTests(unittest.TestCase):
    def test_all_rules_valid_and_unique(self):
        self.assertGreaterEqual(len(RULES), 10)

    def test_every_rule_fires_on_sample(self):
        fired = {a["rule_id"] for a in alerts_for(engine.read_events([SAMPLE]))}
        expected = {r["id"] for r in RULES}
        self.assertEqual(expected - fired, set(), "rules with no test coverage")

    def test_benign_source_is_silent(self):
        alerts = alerts_for(engine.read_events([SAMPLE]))
        self.assertFalse([a for a in alerts if a["src_ip"] == "203.0.113.99"])

    def test_brute_force_needs_threshold(self):
        ev = [{"timestamp": f"2026-01-01T00:00:{i:02d}Z", "eventid": "cowrie.login.failed",
               "src_ip": "203.0.113.1", "username": "root"} for i in range(9)]
        self.assertEqual(alerts_for(ev), [])

    def test_brute_force_window_expires(self):
        ev = [{"timestamp": f"2026-01-01T00:{i:02d}:00Z", "eventid": "cowrie.login.failed",
               "src_ip": "203.0.113.1", "username": "root"} for i in range(12)]
        self.assertEqual(alerts_for(ev), [])  # one failure per minute is below 10/60s

    def test_alert_is_deduplicated_within_window(self):
        ev = [{"timestamp": f"2026-01-01T00:00:{i:02d}Z", "eventid": "cowrie.login.failed",
               "src_ip": "203.0.113.1", "username": "root"} for i in range(30)]
        hp001 = [a for a in alerts_for(ev) if a["rule_id"] == "HP-001"]
        self.assertEqual(len(hp001), 1)

    def test_malformed_events_do_not_crash(self):
        alerts_for([{}, {"timestamp": "garbage"}, {"timestamp": "2026-01-01T00:00:00Z"}])


class SafetyTests(unittest.TestCase):
    def test_private_and_garbage_ips_are_never_public(self):
        for bad in ["10.0.0.1", "127.0.0.1", "192.168.1.1", "not-an-ip", "1.2.3.4; rm -rf /", None, ""]:
            self.assertFalse(is_public_ip(bad), bad)
        self.assertTrue(is_public_ip("8.8.8.8"))

    def test_allowlist(self):
        import os
        os.environ["ALLOWLIST"] = "8.8.8.0/24, 1.1.1.1"
        try:
            self.assertTrue(allowlisted("8.8.8.8"))
            self.assertTrue(allowlisted("1.1.1.1"))
            self.assertFalse(allowlisted("9.9.9.9"))
            self.assertTrue(allowlisted("garbage"))  # unparseable -> never act
        finally:
            del os.environ["ALLOWLIST"]

    def test_block_policy(self):
        args = argparse.Namespace(min_alerts=5, min_abuse=80)
        c = Counter()
        c["9.9.9.9"] = 1
        self.assertIsNotNone(should_block({"src_ip": "9.9.9.9", "severity": "critical"}, c, args))
        self.assertIsNone(should_block({"src_ip": "9.9.9.9", "severity": "low"}, c, args))
        self.assertIsNotNone(should_block(
            {"src_ip": "9.9.9.9", "severity": "low", "intel": {"abuse_score": 95}}, c, args))


if __name__ == "__main__":
    unittest.main()
