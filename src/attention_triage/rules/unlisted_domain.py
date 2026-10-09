"""R4 `unlisted_domain`: the agent reached a host that isn't in allowed_domains (SPEC.md §5).

WebFetch names its URL, so it is checked reliably.
"""

from urllib.parse import urlsplit


def check(event: dict, settings: dict) -> dict | None:
    if (
        event["event_type"] != "tool_call"
        or event["tool_name"] != "WebFetch"
        or not event["target"]
    ):
        return None
    name = host(event["target"])
    if not name or allowed(name, settings["allowed_domains"]):
        return None
    return {
        "reason": "The agent asked to fetch from a host that isn't in allowed_domains.",
        "label": "",
        "evidence": {"hosts": [name]},
    }


def host(url: str) -> str | None:
    try:
        name = urlsplit(url).hostname  # lowercased, without the port or `user:password@`
    except ValueError:  # e.g. an unclosed `[` IPv6 address, which can't be fetched either
        return None
    return name.rstrip(".") if name else None  # `github.com.` is github.com


def allowed(host: str, domains: list[str]) -> bool:
    """An entry matches its exact host; `*.example.com` matches any subdomain of example.com."""
    for domain in domains:
        domain = domain.lower().rstrip(".")
        if host.endswith(domain[1:]) if domain.startswith("*.") else host == domain:
            return True
    return False
