"""R4 `unlisted_domain`: the agent reached a host that isn't in allowed_domains (SPEC.md §5).

WebFetch names its URL, so it is checked reliably.
"""

import re


def check(event: dict, settings: dict) -> dict | None:
    if (
        event["event_type"] != "tool_call"
        or event["tool_name"] != "WebFetch"
        or not event["target"]
    ):
        return None
    unlisted = [h for h in hosts(event["target"]) if not allowed(h, settings["allowed_domains"])]
    if not unlisted:
        return None
    return {
        "reason": "The agent asked to fetch from a host that isn't in allowed_domains.",
        "label": "",
        "evidence": {"hosts": unlisted},
    }


def hosts(url: str) -> list[str]:
    """The hosts a URL may reach, read by hand rather than with urlsplit, which disagrees with
    browsers and curl on odd URLs and raises on some (a redacted `user:[REDACTED]@`). Browsers'
    URL rules (WebFetch) end the host at a `\\`; curl reads it as part of the user name. Either
    reading counts. The host follows the last `@`, without its port or a trailing dot. An empty
    host is kept, so it is reported rather than passing as allowed."""
    # Browsers skip any run of `/` and `\` after the scheme: `https:/evil` and `https:///evil` are evil.
    rest = re.sub(r"^\s*[a-z][a-z0-9+.-]*:[/\\]*", "", url, flags=re.IGNORECASE)
    found = []
    for ends in (r"[/?#\\]", r"[/?#]"):
        name = re.split(ends, rest, maxsplit=1)[0].rpartition("@")[2]
        name = name[1:].partition("]")[0] if name.startswith("[") else name.partition(":")[0]
        if (name := name.lower().rstrip(".")) not in found:
            found.append(name)
    return found


def allowed(host: str, domains: list[str]) -> bool:
    """An entry matches its exact host; `*.example.com` matches any subdomain of example.com."""
    for domain in domains:
        domain = domain.lower().rstrip(".")
        if host.endswith(domain[1:]) if domain.startswith("*.") else host == domain:
            return True
    return False
