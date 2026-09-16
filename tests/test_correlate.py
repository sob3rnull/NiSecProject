"""
test_correlate.py — the 10 offline scenarios required by the feature spec.
None of these touch the network, Gemini, or a live VM — they build Event
objects directly and exercise grouping / dedup / cache / pipeline logic.

Run with:  python3 -m unittest tests.test_correlate -v
(from the project root, with scripts/ on the path — see sys.path hack below,
matching correlate.py's own approach since this project has no packaging.)
"""
import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from nisec_correlate.events import Event
from nisec_correlate.grouping import group_candidates
from nisec_correlate.dedup import dedupe_for_ai, group_fingerprint, event_fingerprint
from nisec_correlate.cache import Cache
from nisec_correlate.config import Config
from nisec_correlate.pipeline import run_pipeline
from nisec_correlate import gemini_client


def ev(id_, ts, src=None, dst=None, port=None, category=None, rule_id=None,
       desc=None, agent=None, sev=5):
    return Event(id=id_, timestamp=ts, source="wazuh", src_ip=src, dst_ip=dst,
                 dst_port=port, category=category, rule_id=rule_id,
                 severity=sev, description=desc, agent=agent, raw={})


def make_cfg(mode="mock", cache_dir=None, max_requests=10):
    return Config(
        mode=mode, model="gemini-2.5-flash-lite", api_key=None,
        correlation_window_seconds=300, max_requests_per_run=max_requests,
        max_events_per_request=50, timeout_seconds=30,
        cache_dir=cache_dir or tempfile.mkdtemp(), evidence_dir=tempfile.mkdtemp(),
        use_enterprise=False, gcp_project=None, gcp_location="global",
        service_account_file=None,
    )


class TestCorrelation(unittest.TestCase):

    # 1. Port scan + SSH auth failures => reconnaissance -> credential_access
    def test_01_scan_then_bruteforce_correlates(self):
        events = [
            ev("A1", "2026-09-16T14:00:00", src="10.0.0.5", dst="10.0.0.20",
               category="scan", desc="Port scan detected"),
            ev("A2", "2026-09-16T14:00:10", src="10.0.0.5", dst="10.0.0.20",
               category="scan", desc="Port scan detected"),
            ev("A3", "2026-09-16T14:01:00", src="10.0.0.5", dst="10.0.0.20",
               category="authentication_failed", desc="SSH auth failure"),
        ]
        cfg = make_cfg()
        summary = run_pipeline(events, cfg)
        self.assertEqual(summary.candidate_incidents, 1)
        inc = summary.incidents[0]
        self.assertTrue(inc.result["is_correlated"])
        stages = [s["stage"] for s in inc.result["attack_chain"]]
        self.assertIn("reconnaissance", stages)
        self.assertIn("credential_access", stages)

    # 2. Unrelated alerts from different sources => separate incidents (no incident at all, isolated)
    def test_02_unrelated_sources_stay_separate(self):
        events = [
            ev("B1", "2026-09-16T14:00:00", src="10.0.0.5", dst="10.0.0.20", category="scan"),
            ev("B2", "2026-09-16T14:00:05", src="10.0.0.99", dst="10.0.0.30", category="scan"),
        ]
        summary = run_pipeline(events, make_cfg())
        self.assertEqual(summary.candidate_incidents, 0)
        self.assertEqual(summary.skipped_isolated, 2)

    # 3. Same source, outside the correlation window => not automatically correlated
    def test_03_same_source_outside_window_not_correlated(self):
        events = [
            ev("C1", "2026-09-16T14:00:00", src="10.0.0.5", dst="10.0.0.20", category="scan"),
            ev("C2", "2026-09-16T15:00:00", src="10.0.0.5", dst="10.0.0.20", category="scan"),  # +1h
        ]
        groups = group_candidates(events, window_seconds=300)
        multi = [g for g in groups if len(g) > 1]
        self.assertEqual(len(multi), 0, "events 1 hour apart must not merge under a 300s window")

    # 4. Suricata + Wazuh events describing related behaviour => cross-tool correlation
    def test_04_cross_tool_correlation(self):
        suricata_ev = Event(id="D1", timestamp="2026-09-16T14:00:00", source="suricata",
                             src_ip="10.0.0.5", dst_ip="10.0.0.20", dst_port=22,
                             category="suricata", rule_id="100101",
                             description="SSH scan detected", severity=7, agent="monitored", raw={})
        wazuh_ev = Event(id="D2", timestamp="2026-09-16T14:00:20", source="wazuh",
                          src_ip="10.0.0.5", dst_ip="10.0.0.20", dst_port=22,
                          category="authentication_failed", rule_id="5710",
                          description="SSH auth failure", severity=5, agent="monitored", raw={})
        summary = run_pipeline([suricata_ev, wazuh_ev], make_cfg())
        self.assertEqual(summary.candidate_incidents, 1)
        ids = summary.incidents[0].candidate_event_ids
        self.assertIn("D1", ids)
        self.assertIn("D2", ids)

    # 5. Missing intermediate detection => incomplete chain, NOT a fabricated event
    def test_05_incomplete_chain_not_fabricated(self):
        # Only recon + a much-later FIM alert; no auth-failure evidence at all.
        events = [
            ev("E1", "2026-09-16T14:00:00", src="10.0.0.5", dst="10.0.0.20", category="scan"),
            ev("E2", "2026-09-16T14:00:30", src="10.0.0.5", dst="10.0.0.20", category="syscheck",
               desc="File integrity violation"),
        ]
        summary = run_pipeline(events, make_cfg())
        result = summary.incidents[0].result
        all_ids_used = set()
        for stage in result["attack_chain"]:
            all_ids_used.update(stage["event_ids"])
        # every event ID referenced must be one we actually supplied — nothing invented
        self.assertTrue(all_ids_used.issubset({"E1", "E2"}))
        self.assertNotIn("credential_access",
                          [s["stage"] for s in result["attack_chain"]],
                          "must not fabricate a stage with no supporting evidence")

    # 6. Invalid Gemini response => validation failure, original events preserved
    def test_06_invalid_response_validation_failure(self):
        # Simulate what gemini_client.call_gemini would return on a bad response
        # by directly exercising the ID-validation guard it uses.
        from nisec_correlate.schema import all_event_ids_referenced_exist
        fake_result = {
            "attack_chain": [{"stage": "reconnaissance", "event_ids": ["GHOST1"], "confidence": 0.9}],
            "relationships": [], "mitre_attack": [],
        }
        problems = all_event_ids_referenced_exist(fake_result, valid_ids={"F1", "F2"})
        self.assertTrue(problems, "a fabricated event_id must be caught, not silently accepted")

    # 7. Gemini unavailable => deterministic correlation still available
    def test_07_gemini_unavailable_falls_back_gracefully(self):
        cfg = make_cfg(mode="gemini")  # no api_key set in make_cfg()
        result, status, detail = gemini_client.call_gemini([{"id": "G1"}], cfg)
        self.assertIsNone(result)
        self.assertEqual(status, "unavailable")
        # Pipeline-level: grouping still produced a candidate incident even though
        # no AI analysis could run for it.
        events = [
            ev("G1", "2026-09-16T14:00:00", src="10.0.0.5", dst="10.0.0.20", category="scan"),
            ev("G2", "2026-09-16T14:00:05", src="10.0.0.5", dst="10.0.0.20", category="scan"),
        ]
        summary = run_pipeline(events, cfg)  # mode=gemini, no key -> pipeline still groups
        self.assertEqual(summary.candidate_incidents, 1)

    # 8. Repeated identical candidate group => cache hit, zero additional "API calls"
    def test_08_cache_hit_avoids_second_call(self):
        cache_dir = tempfile.mkdtemp()
        cfg = make_cfg(mode="mock", cache_dir=cache_dir)
        events = [
            ev("H1", "2026-09-16T14:00:00", src="10.0.0.5", dst="10.0.0.20", category="scan"),
            ev("H2", "2026-09-16T14:00:05", src="10.0.0.5", dst="10.0.0.20", category="scan"),
        ]
        first = run_pipeline(events, cfg)
        second = run_pipeline(events, cfg)  # identical group, same fingerprint
        self.assertEqual(first.incidents[0].ai_status, "ok")
        self.assertEqual(second.incidents[0].ai_status, "cached")
        self.assertEqual(second.cached, 1)
        shutil.rmtree(cache_dir, ignore_errors=True)

    # 9. Request limit reached => remaining incidents processed without Gemini
    def test_09_request_limit_stops_new_calls(self):
        cfg = make_cfg(mode="gemini", max_requests=1)  # no api_key -> every call is "unavailable"
        cfg.__dict__  # (frozen dataclass; fine, we just read it)
        # Build 2 separate candidate groups (different source IPs) so both are
        # eligible for analysis, then confirm only 1 actually attempts a call.
        events = [
            ev("I1", "2026-09-16T14:00:00", src="10.0.0.5", dst="10.0.0.20", category="scan"),
            ev("I2", "2026-09-16T14:00:05", src="10.0.0.5", dst="10.0.0.20", category="scan"),
            ev("I3", "2026-09-16T14:05:00", src="10.0.0.6", dst="10.0.0.21", category="scan"),
            ev("I4", "2026-09-16T14:05:05", src="10.0.0.6", dst="10.0.0.21", category="scan"),
        ]
        summary = run_pipeline(events, cfg)
        self.assertEqual(summary.candidate_incidents, 2)
        statuses = [i.ai_status for i in summary.incidents]
        self.assertIn("skipped_limit_reached", statuses)
        self.assertLessEqual(summary.new_api_calls, 1)

    # 10. Duplicate alerts => deduplicated before AI input
    def test_10_duplicate_alerts_deduplicated(self):
        events = [
            ev("J1", "2026-09-16T14:00:00", src="10.0.0.5", dst="10.0.0.20",
               category="scan", rule_id="100102"),
            # exact duplicate of J1's content, different ID (as a re-delivered alert might be)
            ev("J1-dup", "2026-09-16T14:00:00", src="10.0.0.5", dst="10.0.0.20",
               category="scan", rule_id="100102"),
            ev("J2", "2026-09-16T14:00:05", src="10.0.0.5", dst="10.0.0.20",
               category="authentication_failed", rule_id="5710"),
        ]
        deduped = dedupe_for_ai(events)
        self.assertEqual(len(deduped), 2, "one of the two identical-content alerts must be dropped")

    # --- extra coverage: dry-run must never touch the cache or make a call ---
    def test_dry_run_makes_no_calls_and_no_cache_writes(self):
        cache_dir = tempfile.mkdtemp()
        cfg = make_cfg(mode="gemini", cache_dir=cache_dir)  # would need a key if it ever called out
        events = [
            ev("K1", "2026-09-16T14:00:00", src="10.0.0.5", dst="10.0.0.20", category="scan"),
            ev("K2", "2026-09-16T14:00:05", src="10.0.0.5", dst="10.0.0.20", category="scan"),
        ]
        summary = run_pipeline(events, cfg, dry_run=True)
        self.assertEqual(summary.incidents[0].ai_status, "dry_run")
        self.assertEqual(os.listdir(cache_dir), [], "dry-run must not write to the cache")
        shutil.rmtree(cache_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
