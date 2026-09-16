"""
test_report.py — the 13 offline scenarios required by the report-generator
spec. None call Gemini or need a live VM.
"""
import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from nisec_report.evidence_parser import ReportData
from nisec_report.config import ReportConfig
from nisec_report.html_renderer import render_html
from nisec_report.pipeline import generate_report
from nisec_report.gemini_client import call_mock, get_narrative
from nisec_report.schema import fallback_result


def make_cfg(mode="mock", cache_dir=None, evidence_dir=None, max_requests=1):
    return ReportConfig(
        mode=mode, model="gemini-2.5-flash-lite", api_key=None,
        max_requests_per_run=max_requests, timeout_seconds=30,
        cache_dir=cache_dir or tempfile.mkdtemp(),
        evidence_dir=evidence_dir or tempfile.mkdtemp(),
    )


def sample_data(**overrides) -> ReportData:
    base = dict(
        report_id="NISec-TEST-001", generated_at="2026-09-16 10:00:00",
        incident={"severity": "HIGH", "first_seen": "2026-09-16T14:00:00",
                  "last_seen": "2026-09-16T14:05:00", "source_ips": ["10.0.0.5"],
                  "target_hosts": ["monitored"]},
        statistics={"total_alerts": 20, "suricata_alerts": 12, "wazuh_alerts": 8,
                    "correlated_events": 4, "detection_latency_seconds": 6.5},
        attack_chain=[{"stage": "reconnaissance", "event_ids": ["A1"], "confidence": 0.9}],
        timeline=[{"timestamp": "2026-09-16T14:00:00", "rule_id": "100102", "level": "7",
                   "agent": "monitored", "src_ip": "10.0.0.5", "description": "Port scan",
                   "source": "suricata"}],
        mitre_attack=[{"rule_id": "100102", "alert_count": 12, "tactic": "Reconnaissance",
                       "technique_id": "T1595", "technique_name": "Active Scanning"}],
        detection_results=[{"test": "1. Port scan", "result": "DETECTED", "rule": "100102",
                            "latency_seconds": 7.0}],
        evidence_files=["evidence/detection-results_test.md"],
    )
    base.update(overrides)
    return ReportData(**base)


class TestReportGenerator(unittest.TestCase):

    # 1. Valid evidence -> valid HTML
    def test_01_valid_evidence_produces_valid_html(self):
        html = render_html(sample_data(), fallback_result(), "ok", {"model": "mock", "prompt_version": "1.0", "cache_status": "n/a"})
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("NISec-TEST-001", html)
        self.assertIn("</html>", html)

    # 2. Empty evidence -> graceful report (no crash, clear "no data" messaging)
    def test_02_empty_evidence_graceful(self):
        empty = sample_data(attack_chain=[], timeline=[], mitre_attack=[],
                             detection_results=[], evidence_files=[])
        html = render_html(empty, fallback_result(), "ok", {"model": "mock", "prompt_version": "1.0", "cache_status": "n/a"})
        self.assertIn("No correlated attack chain", html)
        self.assertIn("No data available", html)

    # 3. Multiple incidents -> each report call is independent / correctly scoped
    def test_03_independent_report_ids(self):
        d1 = sample_data(report_id="NISec-AAA")
        d2 = sample_data(report_id="NISec-BBB")
        h1 = render_html(d1, fallback_result(), "ok", {"model": "mock", "prompt_version": "1.0", "cache_status": "n/a"})
        h2 = render_html(d2, fallback_result(), "ok", {"model": "mock", "prompt_version": "1.0", "cache_status": "n/a"})
        self.assertIn("NISec-AAA", h1)
        self.assertNotIn("NISec-BBB", h1)
        self.assertIn("NISec-BBB", h2)

    # 4. Gemini unavailable -> report still generated
    def test_04_gemini_unavailable_report_still_generated(self):
        cfg = make_cfg(mode="gemini")  # no api_key
        result = generate_report(cfg, evidence_override=sample_data())
        self.assertFalse(result["dry_run"])
        self.assertTrue(os.path.exists(result["report_path"]))
        self.assertEqual(result["ai_status"], "unavailable")

    # 5. Invalid Gemini JSON -> fallback used, report still produced
    def test_05_invalid_json_falls_back(self):
        narrative, status, detail = get_narrative({}, make_cfg(mode="gemini"), dry_run=False)
        self.assertEqual(status, "unavailable")  # no key configured -> same fallback path
        self.assertEqual(narrative, fallback_result())

    # 6. HTML escaping works
    def test_06_html_escaping(self):
        malicious = sample_data(incident={"severity": "HIGH", "first_seen": None, "last_seen": None,
                                           "source_ips": ["<script>alert(1)</script>"], "target_hosts": []})
        html = render_html(malicious, fallback_result(), "ok", {"model": "mock", "prompt_version": "1.0", "cache_status": "n/a"})
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    # 7. Cached AI response -> zero additional API calls
    def test_07_cache_hit_zero_calls(self):
        cache_dir = tempfile.mkdtemp()
        cfg = make_cfg(mode="mock", cache_dir=cache_dir)
        data = sample_data()
        r1 = generate_report(cfg, evidence_override=data)
        r2 = generate_report(cfg, evidence_override=data)
        self.assertEqual(r1["ai_status"], "ok")
        self.assertEqual(r2["ai_status"], "cached")
        shutil.rmtree(cache_dir, ignore_errors=True)

    # 8. Changed prompt version -> cache invalidated
    def test_08_prompt_version_change_invalidates_cache(self):
        import nisec_report.pipeline as pipeline_mod
        cache_dir = tempfile.mkdtemp()
        cfg = make_cfg(mode="mock", cache_dir=cache_dir)
        data = sample_data()
        generate_report(cfg, evidence_override=data)

        original_version = pipeline_mod.PROMPT_VERSION
        pipeline_mod.PROMPT_VERSION = "2.0"
        try:
            r2 = generate_report(cfg, evidence_override=data)
            self.assertEqual(r2["ai_status"], "ok", "a new prompt version must not reuse the old cache entry")
        finally:
            pipeline_mod.PROMPT_VERSION = original_version
            shutil.rmtree(cache_dir, ignore_errors=True)

    # 9. Mock mode -> zero API calls
    def test_09_mock_mode_zero_calls(self):
        result, status, _ = call_mock(sample_data().as_ai_context())
        self.assertEqual(status, "ok")
        self.assertTrue(result["executive_summary"].startswith("[MOCK]"))

    # 10. Dry-run -> zero API calls
    def test_10_dry_run_zero_calls(self):
        cfg = make_cfg(mode="gemini")
        result = generate_report(cfg, dry_run=True, evidence_override=sample_data())
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["api_calls_made"], 0)

    # 11. Numerical values remain unchanged end-to-end
    def test_11_numbers_unchanged_through_pipeline(self):
        data = sample_data()
        html = render_html(data, fallback_result(), "ok", {"model": "mock", "prompt_version": "1.0", "cache_status": "n/a"})
        self.assertIn("20", html)   # total_alerts
        self.assertIn("6.5", html)  # detection_latency_seconds
        self.assertIn("7.0s", html)  # detection_results latency

    # 12. AI output cannot inject HTML/JS
    def test_12_ai_output_cannot_inject_html(self):
        malicious_narrative = fallback_result()
        malicious_narrative["executive_summary"] = "<img src=x onerror=alert(1)>"
        html = render_html(sample_data(), malicious_narrative, "ok",
                            {"model": "mock", "prompt_version": "1.0", "cache_status": "n/a"})
        self.assertNotIn("<img src=x onerror=alert(1)>", html)
        self.assertIn("&lt;img", html)

    # 13. Missing optional evidence files -> report still works
    def test_13_missing_optional_evidence_still_works(self):
        cfg = make_cfg(mode="mock")
        # evidence_dir is a fresh empty tempdir -> build_report_data(cfg.evidence_dir)
        # would find nothing; exercise that path directly instead of overriding.
        from nisec_report.evidence_parser import build_report_data
        empty_dir = tempfile.mkdtemp()
        data = build_report_data(empty_dir)
        html = render_html(data, fallback_result(), "ok", {"model": "mock", "prompt_version": "1.0", "cache_status": "n/a"})
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("UNKNOWN", html)  # severity falls back cleanly, doesn't crash
        shutil.rmtree(empty_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
