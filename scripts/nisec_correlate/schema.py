"""
schema.py — the structured-output contract for Gemini, and the system
instruction that constrains it to the supplied evidence only.

Kept deliberately small per-request: no project README, no raw Wazuh JSON,
just this instruction plus the normalized candidate events (see events.py).
"""

# Compact by design (item 7 of the spec) — this is sent on every request,
# so its size directly affects prompt cost.
SYSTEM_INSTRUCTION = """You are a cybersecurity event-correlation analyst.

Analyze ONLY the security events provided to you.

Your task is to determine whether the supplied events represent a coherent
attack sequence.

You must never invent events, timestamps, IP addresses, rule IDs, attack
stages, successful compromises, or MITRE ATT&CK techniques.

Every conclusion must be supported by one or more supplied events.

Distinguish observed facts from inferred relationships.

If evidence is insufficient, report uncertainty rather than guessing.

The absence of an alert must never be interpreted as evidence that an
attack stage occurred.

An attack chain may be incomplete.

Do not assume attacker intent when the supplied evidence only demonstrates
activity.

Return only the requested structured output."""

# Passed to the SDK as response_json_schema — a plain JSON Schema dict,
# not a "please return JSON" instruction. See gemini_client.py.
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "is_correlated": {"type": "boolean"},
        "confidence": {"type": "number"},
        "attack_chain": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "stage": {"type": "string"},
                    "event_ids": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "number"},
                },
                "required": ["stage", "event_ids", "confidence"],
            },
        },
        "relationships": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "from_event": {"type": "string"},
                    "to_event": {"type": "string"},
                    "relationship": {"type": "string"},
                    "confidence": {"type": "number"},
                    "reason": {"type": "string"},
                },
                "required": ["from_event", "to_event", "relationship", "confidence", "reason"],
            },
        },
        "mitre_attack": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique": {"type": "string"},
                    "event_ids": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "number"},
                },
                "required": ["technique", "event_ids", "confidence"],
            },
        },
        "uncertainties": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "is_correlated", "confidence", "attack_chain",
        "relationships", "mitre_attack", "uncertainties",
    ],
}


def all_event_ids_referenced_exist(result: dict, valid_ids: set[str]) -> list[str]:
    """
    Guard against a model inventing event IDs that weren't in the supplied
    candidate group. Returns a list of problems (empty = clean).
    This is separate from JSON-schema validation, which only checks *shape*,
    not whether referenced IDs are real.
    """
    problems = []

    def check(ids, where):
        for eid in ids:
            if eid not in valid_ids:
                problems.append(f"{where} references unknown event_id '{eid}'")

    for stage in result.get("attack_chain", []):
        check(stage.get("event_ids", []), "attack_chain")
    for rel in result.get("relationships", []):
        for key in ("from_event", "to_event"):
            eid = rel.get(key)
            if eid and eid not in valid_ids:
                problems.append(f"relationships.{key} references unknown event_id '{eid}'")
    for m in result.get("mitre_attack", []):
        check(m.get("event_ids", []), "mitre_attack")

    return problems
