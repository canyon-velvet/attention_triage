"""Built-in rules (SPEC.md §5), run on each newly stored event at capture time (ADR-0003).

Each rule module has `check(event, settings)`: the neutral event and the rule's settings from
policy.yaml in, the flag's reason, label and evidence out, or None when the event is fine.
"""

from datetime import UTC, datetime

from attention_triage.rules import sandbox_bypass

RULES = {
    "sandbox_bypass": sandbox_bypass.check,
}


def evaluate(event: dict, policy: dict, version: str, now: datetime | None = None) -> list[dict]:
    """Flag records for one event, one per enabled rule that fires."""
    ts = (now or datetime.now(UTC)).isoformat(timespec="milliseconds")
    flags = []
    for rule_id, check in RULES.items():
        settings = policy["rules"][rule_id]
        if settings["enabled"] and (found := check(event, settings)):
            flags.append(
                {
                    "event_key": event["dedup_key"],
                    "rule_id": rule_id,
                    "severity": settings["severity"],
                    **found,
                    "policy_version": version,
                    "status": "open",
                    "created_at": ts,
                    "updated_at": ts,
                }
            )
    return flags
