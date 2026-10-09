"""policy.yaml (SPEC.md §5): which rules run, and how severe their flags are.

The file is created with the defaults when missing. A rule it leaves out keeps its defaults. Unknown
keys are rejected rather than ignored, so a typo like `sandbox_bypas: {enabled: false}` is reported
instead of silently leaving the rule on.
"""

import hashlib
import json
import os

import yaml

from attention_triage import store

SEVERITIES = ("high", "review")
# Settings of each built-in rule when policy.yaml doesn't name it. Each rule's ticket adds its own.
DEFAULT_RULES = {
    "outside_project_write": {"enabled": True, "severity": "high", "allowed_paths": []},
    "sandbox_bypass": {"enabled": True, "severity": "high"},
}

DEFAULT_POLICY = """\
# Attention Triage policy. Flags record the policy_version (a hash of these settings) that made
# them. severity: high | review
version: 1
rules:
  outside_project_write:
    enabled: true
    severity: high
    allowed_paths: []  # dirs outside the project the agent may write to, e.g. ~/.cache/myapp
  sandbox_bypass:
    enabled: true
    severity: high
"""


class PolicyError(ValueError):
    pass


def path():
    return store.data_dir() / "policy.yaml"


def load() -> tuple[dict, str]:
    """The policy with defaults filled in, and its policy_version. Raises PolicyError if invalid."""
    if not path().exists():
        # Hooks run in parallel: write a temp file and rename it, so none reads a half-written one.
        path().parent.mkdir(parents=True, exist_ok=True)
        temp = path().with_name(f"policy.yaml.{os.getpid()}.tmp")
        temp.write_text(DEFAULT_POLICY)
        temp.replace(path())
    return parse(path().read_text())


def parse(text: str) -> tuple[dict, str]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyError(f"not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise PolicyError("expected a mapping with `version` and `rules`")
    # type() check: YAML `true` and `1.0` both equal 1 in Python.
    if type(data.get("version")) is not int or data["version"] != 1:
        raise PolicyError("`version` must be 1")
    check_keys("policy", data, {"version", "rules"})
    # Only an empty value means "defaults": `false` must not quietly leave the rules on.
    rules = {} if data.get("rules") is None else data["rules"]
    if not isinstance(rules, dict):
        raise PolicyError("`rules` must be a mapping of rule id to settings")
    check_keys("rules", rules, DEFAULT_RULES)
    normalized = {"version": 1, "rules": {}}
    for rule_id, default in DEFAULT_RULES.items():
        settings = rules.get(rule_id)
        if settings is None:  # left out, or `sandbox_bypass:` alone
            settings = {}
        if not isinstance(settings, dict):
            raise PolicyError(f"`{rule_id}` must be a mapping of settings")
        check_keys(rule_id, settings, default)
        settings = {**default, **settings}
        if not isinstance(settings["enabled"], bool):
            raise PolicyError(f"`{rule_id}.enabled` must be true or false")
        if settings["severity"] not in SEVERITIES:
            raise PolicyError(f"`{rule_id}.severity` must be one of: {', '.join(SEVERITIES)}")
        paths = settings.get("allowed_paths", [])
        if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
            raise PolicyError(f"`{rule_id}.allowed_paths` must be a list of paths")
        normalized["rules"][rule_id] = settings
    canonical = json.dumps(normalized, sort_keys=True)
    return normalized, hashlib.sha256(canonical.encode()).hexdigest()[:12]


def check_keys(where: str, found: dict, known) -> None:
    if unknown := [str(key) for key in found if key not in known]:
        raise PolicyError(f"unknown key in {where}: {', '.join(unknown)}")
