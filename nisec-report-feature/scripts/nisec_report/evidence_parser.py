"""
evidence_parser.py — turns NISec's existing evidence files into ONE
deterministic, structured report-data object. Nothing in this file calls
Gemini or knows Gemini exists; it is pure fact extraction.

Sources (all optional — degrade gracefully if any are missing, spec test 13):
    evidence/detection-results_*.md   (latest)  -> detection_results
    evidence/threat-hunt_*.md         (latest)  -> timeline, mitre_attack, statistics
    evidence/attack-correlation_*.md  (latest)  -> attack_chain (reuses the
                                                    correlation engine's own
                                                    output — never redrawn here)
"""
from __future__ import annotations
import glob
import os
import re
import time
from dataclasses import dataclass, field


def _latest(evidence_dir: str, pattern: str) -> str | None:
    matches = sorted(glob.glob(os.path.join(evidence_dir, pattern)))
    return matches[-1] if matches else None


def _read(path: str | None) -> str:
    if not path or not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# detection-results_*.md  ->  list of {test, result, rule, latency_seconds}
# ---------------------------------------------------------------------------
def _parse_detection_results(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        m = re.match(r"^\|\s*(\d+\.\s.+?)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*([\d.]+)\s*s?\s*\|", line)
        if m:
            rows.append({
                "test": m.group(1), "result": m.group(2),
                "rule": m.group(3), "latency_seconds": float(m.group(4)),
            })
    return rows


# ---------------------------------------------------------------------------
# threat-hunt_*.md  ->  ## Rule Frequency Breakdown  (full-window counts —
# used for suricata/wazuh alert totals instead of the capped 30-row timeline,
# which under-samples a long attack run).
# ---------------------------------------------------------------------------
# Rule IDs fed by the Suricata->Wazuh integration in this lab (see
# docs/architecture.md / provisioning: nisec-local.rules). Everything else
# numeric is a native Wazuh host-based rule.
SURICATA_RULE_IDS = {"100101", "100102", "100120"}


def _parse_rule_frequency(text: str) -> dict[str, int]:
    counts = {}
    in_section = False
    for line in text.splitlines():
        if line.startswith("## Rule Frequency Breakdown"):
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if not in_section:
            continue
        m = re.match(r"^\|\s*(\d+)\s*\|\s*(\d+)\s*\|", line)
        if m:
            counts[m.group(1)] = int(m.group(2))
    return counts


# ---------------------------------------------------------------------------
# threat-hunt_*.md  ->  total_alerts, timeline[], mitre_attack[]
# ---------------------------------------------------------------------------
def _parse_hunt_total(text: str) -> int:
    m = re.search(r"Total alerts in window \| \*\*(\d+)\*\*", text)
    return int(m.group(1)) if m else 0


def _parse_hunt_timeline(text: str) -> list[dict]:
    events = []
    in_timeline = False
    for line in text.splitlines():
        if line.startswith("## Event Timeline"):
            in_timeline = True
            continue
        if in_timeline and line.startswith("## "):
            break
        if not in_timeline:
            continue
        m = re.match(r"^\|\s*([\d T:.-]+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(.+?)\s*\|$", line)
        if m and m.group(1) != "Timestamp" and not set(m.group(1)) <= {"-", " "}:
            ts, rule_id, level, agent, srcip, desc = m.groups()
            events.append({
                "timestamp": ts, "rule_id": rule_id, "level": level,
                "agent": agent, "src_ip": None if srcip == "—" else srcip,
                "description": desc,
                "source": "suricata" if rule_id in SURICATA_RULE_IDS else "wazuh",
            })
    return events


def _parse_hunt_mitre(text: str) -> list[dict]:
    techniques = []
    in_mitre = False
    for line in text.splitlines():
        if line.startswith("## MITRE ATT&CK Mapping"):
            in_mitre = True
            continue
        if in_mitre and line.startswith("## "):
            break
        if not in_mitre:
            continue
        m = re.match(r"^\|\s*(\S+)\s*\|\s*(\d+)×\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|$", line)
        if m and m.group(1) != "Rule ID":
            rule_id, count, tactic, technique_id, technique_name = m.groups()
            if technique_id.strip() == "—":
                continue  # no established technique for this rule — don't invent one
            techniques.append({
                "rule_id": rule_id, "alert_count": int(count), "tactic": tactic,
                "technique_id": technique_id, "technique_name": technique_name,
            })
    return techniques


# ---------------------------------------------------------------------------
# attack-correlation_*.md  ->  attack_chain[]  (reuses the correlation engine's
# own output verbatim — this module never invents or redraws a chain)
# ---------------------------------------------------------------------------
def _parse_attack_chain(text: str) -> list[dict]:
    chain = []
    in_chain = False
    for line in text.splitlines():
        if line.strip().startswith("**Attack chain:**"):
            in_chain = True
            continue
        if in_chain and (line.startswith("**") or line.startswith("---")):
            in_chain = False
            continue
        if not in_chain:
            continue
        m = re.match(r"^\|\s*(\S+)\s*\|\s*(.+?)\s*\|\s*([\d.]+)\s*\|$", line)
        if m and m.group(1) != "Stage":
            stage, event_ids, confidence = m.groups()
            chain.append({
                "stage": stage,
                "event_ids": [e.strip() for e in event_ids.split(",")],
                "confidence": float(confidence),
            })
    return chain


@dataclass
class ReportData:
    report_id: str
    generated_at: str
    incident: dict = field(default_factory=dict)
    statistics: dict = field(default_factory=dict)
    attack_chain: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    mitre_attack: list = field(default_factory=list)
    detection_results: list = field(default_factory=list)
    evidence_files: list = field(default_factory=list)

    def as_ai_context(self) -> dict:
        """
        The COMPACT subset actually sent to Gemini — facts only, no raw
        markdown, no unrelated files. This is deliberately smaller than the
        full ReportData object (spec: keep the prompt bounded).
        """
        return {
            "incident": self.incident,
            "statistics": self.statistics,
            "attack_chain": self.attack_chain,
            "mitre_attack": self.mitre_attack,
            "detection_results": self.detection_results,
        }


def build_report_data(evidence_dir: str) -> ReportData:
    dr_path = _latest(evidence_dir, "detection-results_*.md")
    th_path = _latest(evidence_dir, "threat-hunt_*.md")
    ac_path = _latest(evidence_dir, "attack-correlation_*.md")

    detection_results = _parse_detection_results(_read(dr_path))
    hunt_text = _read(th_path)
    timeline = _parse_hunt_timeline(hunt_text)
    mitre = _parse_hunt_mitre(hunt_text)
    total_alerts = _parse_hunt_total(hunt_text)
    rule_frequency = _parse_rule_frequency(hunt_text)
    attack_chain = _parse_attack_chain(_read(ac_path))

    suricata_count = sum(c for rid, c in rule_frequency.items() if rid in SURICATA_RULE_IDS)
    wazuh_count = sum(c for rid, c in rule_frequency.items() if rid not in SURICATA_RULE_IDS)

    correlated_ids: set[str] = set()
    for stage in attack_chain:
        correlated_ids.update(stage["event_ids"])

    latencies = [r["latency_seconds"] for r in detection_results if r["result"] == "DETECTED"]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None

    timestamps = [e["timestamp"] for e in timeline if e.get("timestamp")]
    first_seen = min(timestamps) if timestamps else None
    last_seen = max(timestamps) if timestamps else None
    source_ips = sorted({e["src_ip"] for e in timeline if e.get("src_ip")})
    target_hosts = sorted({e["agent"] for e in timeline if e.get("agent")})

    detected_high_risk = any(
        r["result"] == "DETECTED" and r["rule"] in {"5710", "100120", "100200"}
        for r in detection_results
    )
    severity = "HIGH" if detected_high_risk else ("MEDIUM" if detection_results else "UNKNOWN")

    evidence_files = [p for p in (dr_path, th_path, ac_path) if p]

    return ReportData(
        report_id=f"NISec-{time.strftime('%Y%m%d-%H%M%S')}",
        generated_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        incident={
            "severity": severity, "first_seen": first_seen, "last_seen": last_seen,
            "source_ips": source_ips, "target_hosts": target_hosts,
        },
        statistics={
            "total_alerts": total_alerts, "suricata_alerts": suricata_count,
            "wazuh_alerts": wazuh_count, "correlated_events": len(correlated_ids),
            "detection_latency_seconds": avg_latency,
        },
        attack_chain=attack_chain,
        timeline=timeline,
        mitre_attack=mitre,
        detection_results=detection_results,
        evidence_files=evidence_files,
    )
