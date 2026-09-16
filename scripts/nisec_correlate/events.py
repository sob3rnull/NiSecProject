"""
events.py — getting alerts in, and shrinking them down to what correlation
actually needs.

Two sources, both producing the same normalized shape:
  - fetch_live(hours)     : same manager, same clock as hunt.sh (no VM-skew).
  - load_from_file(path)  : a JSON array or JSONL file of raw Wazuh alerts —
                             used by tests, --dry-run demos, and anyone
                             without a live lab up.
"""
from __future__ import annotations
import json
import subprocess
from dataclasses import dataclass, field


@dataclass
class Event:
    id: str                 # stable if Wazuh gives one, else a fingerprint (see dedup.py)
    timestamp: str
    source: str              # "suricata" | "wazuh"
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    category: str | None
    rule_id: str | None
    severity: int | None
    description: str | None
    agent: str | None
    raw: dict = field(repr=False, default_factory=dict)  # original, never discarded

    def normalized(self) -> dict:
        """The compact shape actually sent to Gemini (spec item 5)."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source": self.source,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "category": self.category,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "description": self.description,
        }


def _classify_source(raw: dict) -> str:
    groups = raw.get("rule", {}).get("groups", []) or []
    if any("suricata" in g for g in groups) or "alert" in raw.get("data", {}):
        return "suricata"
    return "wazuh"


def _from_raw(raw: dict, idx: int) -> Event:
    data = raw.get("data", {}) or {}
    rule = raw.get("rule", {}) or {}
    alert = data.get("alert", {}) or {}  # Suricata sub-object, when present

    src_ip = data.get("srcip") or data.get("src_ip")
    dst_ip = data.get("dstip") or data.get("dest_ip")
    dst_port_raw = data.get("dstport") or data.get("dest_port")
    try:
        dst_port = int(dst_port_raw) if dst_port_raw not in (None, "") else None
    except (TypeError, ValueError):
        dst_port = None

    rule_id = str(alert.get("signature_id") or rule.get("id") or "")
    description = alert.get("signature") or rule.get("description")
    category = ",".join(rule.get("groups", [])) if rule.get("groups") else data.get("category")

    # Stable ID if Wazuh supplied one, else a positional placeholder —
    # dedup.py replaces this with a content fingerprint before Gemini sees it.
    stable_id = str(raw.get("id") or f"evt{idx}")

    return Event(
        id=stable_id,
        timestamp=str(raw.get("timestamp", "")),
        source=_classify_source(raw),
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        category=category,
        rule_id=rule_id or None,
        severity=rule.get("level"),
        description=description,
        agent=(raw.get("agent", {}) or {}).get("name"),
        raw=raw,
    )


def load_from_file(path: str) -> list[Event]:
    """Accepts either a JSON array of alert objects, or JSONL (one per line)."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read().strip()
    if not text:
        return []
    if text.lstrip().startswith("["):
        raw_alerts = json.loads(text)
    else:
        raw_alerts = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [_from_raw(r, i) for i, r in enumerate(raw_alerts)]


def fetch_live(hours: int = 2, since_epoch: int | None = None) -> list[Event]:
    """
    Pulls alerts.json from wazuh-server the same way hunt.sh does: over
    `vagrant ssh`, filtered on the manager's own clock so a skewed host
    clock can never affect which alerts are considered "in window".
    Requires the lab to be up. For anything else (tests, dry-run demos),
    use load_from_file() instead.
    """
    if since_epoch is None:
        since_cmd = f"date -d '-{hours} hours' +%s"
        since_epoch = int(_mgr(since_cmd).strip())

    jq_filter = (
        'select((.timestamp | sub("[.].*$";"") | strptime("%Y-%m-%dT%H:%M:%S") | mktime) '
        f'>= {since_epoch})'
    )
    cmd = (
        f"sudo tail -n 20000 /var/ossec/logs/alerts/alerts.json 2>/dev/null "
        f"| jq -c '{jq_filter}' 2>/dev/null"
    )
    output = _mgr(cmd)
    raw_alerts = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw_alerts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return [_from_raw(r, i) for i, r in enumerate(raw_alerts)]


def _mgr(cmd: str) -> str:
    result = subprocess.run(
        ["vagrant", "ssh", "wazuh-server", "-c", cmd],
        capture_output=True, text=True, timeout=60,
    )
    return (result.stdout or "").replace("\r", "")
