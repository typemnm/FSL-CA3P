"""Capture hints: what the screenshot tool may need, pulled from the run itself.

The build-stage LLM decides what to screenshot, but it should not have to guess a
site's selectors or how to switch accounts. This collector reads the parser report
(the ``loop.observe`` event) and the attacker session (``setup.attacker_session``)
and records, when present:

- input forms: selector + field names, with the form that carries the attack
  parameter (the ``loop.act`` body keys) marked ``carries_attack_param``;
- the session-switch request the site exposes (method/path/body template), which is
  the ONLY state-changing request the capture sandbox may replay (§2.5);
- the attacker account id.

Everything is best-effort: when a signal is absent the field is simply omitted, and
the LLM falls back to reading the live page. Nothing here asserts a vulnerability.
"""

from __future__ import annotations

from .model import StoredEvent

HINTS_SCHEMA = "report-input-hints-1.0"


def _path_of(url: str) -> str:
    """Path portion of a URL, without a network import (string slicing only)."""
    rest = url.split("://", 1)[-1]
    rest = rest.split("/", 1)
    path = "/" + rest[1] if len(rest) == 2 else "/"
    for sep in ("?", "#"):
        path = path.split(sep, 1)[0]
    return path


def _event(events: list[StoredEvent], stage: str) -> StoredEvent | None:
    for event in events:
        if event.stage == stage:
            return event
    return None


def _parser_report(events: list[StoredEvent]) -> dict:
    observe = _event(events, "loop.observe")
    if observe is None:
        return {}
    payload = observe.response.get("payload")
    report = payload.get("report") if isinstance(payload, dict) else None
    return report if isinstance(report, dict) else {}


def _attack_body_keys(events: list[StoredEvent]) -> set[str]:
    act = _event(events, "loop.act")
    if act is None:
        return set()
    curl = act.request.get("payload", {}).get("curl") if isinstance(act.request, dict) else None
    body = curl.get("body") if isinstance(curl, dict) else None
    return set(body) if isinstance(body, dict) else set()


def _input_forms(report: dict, attack_keys: set[str]) -> list[dict]:
    forms: list[dict] = []
    seen: set[str] = set()
    for page in report.get("pages", []) if isinstance(report, dict) else []:
        for area in page.get("areas", []) if isinstance(page, dict) else []:
            for form in area.get("forms", []) if isinstance(area, dict) else []:
                selector = form.get("selector") if isinstance(form, dict) else None
                if not isinstance(selector, str) or selector in seen:
                    continue
                seen.add(selector)
                fields = [
                    f.get("name")
                    for f in form.get("fields", [])
                    if isinstance(f, dict) and isinstance(f.get("name"), str)
                ]
                forms.append(
                    {
                        "selector": selector,
                        "fields": fields,
                        # The form that holds the attack parameter is the input point.
                        "carries_attack_param": bool(attack_keys)
                        and attack_keys.issubset(set(fields)),
                    }
                )
    return forms


def _session_switch(report: dict) -> dict | None:
    """The site's own account-switch request, as the parser found it in the page JS."""
    for page in report.get("pages", []) if isinstance(report, dict) else []:
        for behavior in page.get("behaviors", []) if isinstance(page, dict) else []:
            for api in behavior.get("api", []) if isinstance(behavior, dict) else []:
                if not isinstance(api, dict):
                    continue
                url, method = api.get("url"), api.get("method")
                if not isinstance(url, str) or not isinstance(method, str):
                    continue
                path = _path_of(url)
                keys = api.get("bodyKeys")
                if path.endswith("/session") and method.upper() == "POST":
                    return {
                        "method": "POST",
                        "path": path,
                        "bodyKeys": [k for k in keys if isinstance(k, str)]
                        if isinstance(keys, list)
                        else [],
                    }
    return None


def _attacker_account(events: list[StoredEvent]) -> str | None:
    setup = _event(events, "setup.attacker_session")
    if setup is None:
        return None
    payload = setup.response.get("payload") if isinstance(setup.response, dict) else None
    body = payload.get("response", {}).get("bodyJson") if isinstance(payload, dict) else None
    user = body.get("user") if isinstance(body, dict) else None
    uid = user.get("id") if isinstance(user, dict) else None
    return uid if isinstance(uid, str) else None


def capture_hints(events: list[StoredEvent]) -> dict:
    """Best-effort hints for the capture tool. Absent signals are simply omitted."""
    report = _parser_report(events)
    hints: dict = {"schemaVersion": HINTS_SCHEMA}
    forms = _input_forms(report, _attack_body_keys(events))
    if forms:
        hints["inputForms"] = forms
    switch = _session_switch(report)
    if switch is not None:
        hints["sessionSwitch"] = switch
    attacker = _attacker_account(events)
    if attacker is not None:
        hints["attackerAccount"] = attacker
    return hints
