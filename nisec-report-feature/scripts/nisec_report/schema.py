"""
schema.py — the narrative-only contract for Gemini. It never touches a
number, a timestamp, or an ID — those are supplied by evidence_parser.py
and rendered by html_renderer.py regardless of whether this call ever runs.
"""

SYSTEM_INSTRUCTION = """You are an analyst assisting with a cybersecurity incident report.

Analyze ONLY the evidence provided in the request.

Generate concise, professional analyst commentary based on the supplied evidence.

Never invent events, timestamps, IP addresses, hostnames, rule IDs, detection
results, attack stages, successful compromise, or MITRE ATT&CK techniques.

Do not change numerical values supplied by the application.

Do not calculate statistics yourself when the application has already
supplied the calculated values.

Distinguish observed evidence from interpretation.

If evidence is insufficient, explicitly state the limitation.

Do not claim that an attack succeeded unless the supplied evidence
demonstrates successful compromise.

Do not treat absence of an alert as evidence that an attack stage occurred.

The application, not the language model, is the authoritative source for
factual security data."""

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        "incident_overview": {"type": "string"},
        "attack_narrative": {"type": "string"},
        "attack_chain_analysis": {"type": "string"},
        "detection_analysis": {"type": "string"},
        "key_findings": {"type": "array", "items": {"type": "string"}},
        "limitations": {"type": "array", "items": {"type": "string"}},
        "conclusion": {"type": "string"},
    },
    "required": [
        "executive_summary", "incident_overview", "attack_narrative",
        "attack_chain_analysis", "detection_analysis", "key_findings",
        "limitations", "conclusion",
    ],
}

NARRATIVE_FIELDS = [
    "executive_summary", "incident_overview", "attack_narrative",
    "attack_chain_analysis", "detection_analysis", "conclusion",
]

FALLBACK_TEXT = "AI analysis unavailable. Factual data above is unaffected."


def fallback_result() -> dict:
    """What every AI-authored section reads as when Gemini didn't run."""
    return {
        "executive_summary": FALLBACK_TEXT,
        "incident_overview": FALLBACK_TEXT,
        "attack_narrative": FALLBACK_TEXT,
        "attack_chain_analysis": FALLBACK_TEXT,
        "detection_analysis": FALLBACK_TEXT,
        "key_findings": [],
        "limitations": [FALLBACK_TEXT],
        "conclusion": FALLBACK_TEXT,
    }
