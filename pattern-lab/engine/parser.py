"""
Audit-log parser for the traffic pattern engine.

The engine consumes ModSecurity v3 (libmodsecurity) audit events. The OWASP
CRS nginx container can emit these as one JSON object per line
(``MODSEC_AUDIT_LOG_FORMAT=JSON``), which is the format we standardise on.

Each JSON line looks roughly like::

    {"transaction": {
        "client_ip": "10.0.0.7",
        "time_stamp": "...",
        "request":  {"method": "GET", "uri": "/oauth2/authorize?...", "headers": {...}},
        "response": {"http_code": 403},
        "messages": [
            {"message": "SQL Injection Attack Detected via libinjection",
             "details": {"ruleId": "942100", "data": "Matched Data: ...",
                         "severity": "2", "tags": ["attack-sqli", ...]}}
        ]
    }}

Real-world audit logs are messy: partial lines, missing keys, mixed formats.
The parser is deliberately tolerant — a line it cannot understand is skipped
(and counted) rather than blowing up the whole run.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable, Iterator
from urllib.parse import parse_qsl, urlsplit


@dataclass
class RuleHit:
    """One CRS rule that fired inside a single request."""

    rule_id: str
    message: str = ""
    severity: str = ""
    tags: list[str] = field(default_factory=list)
    # The literal argument/location + value CRS matched on, extracted from the
    # audit "data" string, e.g. "ARGS:redirect_uri". Empty when unknown.
    matched_location: str = ""
    matched_data: str = ""


@dataclass
class Event:
    """A single WAF-inspected request plus every rule that fired on it."""

    client_ip: str = ""
    method: str = "GET"
    path: str = "/"
    query_args: list[str] = field(default_factory=list)  # arg *names*
    user_agent: str = ""
    http_code: int = 0
    anomaly_score: int = 0
    hits: list[RuleHit] = field(default_factory=list)
    raw_uri: str = ""

    @property
    def blocked(self) -> bool:
        return self.http_code == 403


# "Matched Data: foo found within ARGS:redirect_uri: https://..."
_LOC_RE = re.compile(r"found within ([A-Z_]+(?::[^:]+)?)", re.IGNORECASE)
_MATCHED_RE = re.compile(r"Matched Data:\s*(.*?)\s+found within", re.IGNORECASE | re.DOTALL)
# CRS records the final inbound anomaly score in a 949110 message like
# "... Inbound Anomaly Score Exceeded (Total Score: 15)".
_SCORE_RE = re.compile(r"Total (?:Inbound )?Score:\s*(\d+)", re.IGNORECASE)


def _extract_location(data: str) -> tuple[str, str]:
    loc = ""
    matched = ""
    m = _LOC_RE.search(data or "")
    if m:
        loc = m.group(1).strip()
    m = _MATCHED_RE.search(data or "")
    if m:
        matched = m.group(1).strip()
    return loc, matched


def _arg_names(uri: str) -> tuple[str, list[str]]:
    parts = urlsplit(uri)
    args = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
    return parts.path or "/", args


def parse_event(obj: dict) -> Event | None:
    """Turn one decoded audit JSON object into an :class:`Event`."""
    txn = obj.get("transaction") or obj
    req = txn.get("request") or {}
    resp = txn.get("response") or {}
    uri = req.get("uri") or txn.get("uri") or "/"
    path, args = _arg_names(uri)

    headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
    ev = Event(
        client_ip=txn.get("client_ip") or txn.get("remote_address") or "",
        method=(req.get("method") or "GET").upper(),
        path=path,
        query_args=args,
        user_agent=headers.get("user-agent", ""),
        http_code=int(resp.get("http_code") or resp.get("status") or 0),
        raw_uri=uri,
    )

    score = 0
    for msg in txn.get("messages") or []:
        details = msg.get("details") or {}
        rule_id = str(details.get("ruleId") or details.get("id") or "").strip()
        text = msg.get("message") or details.get("match") or ""
        data = details.get("data") or ""
        loc, matched = _extract_location(data)

        sm = _SCORE_RE.search(text) or _SCORE_RE.search(data)
        if sm:
            score = max(score, int(sm.group(1)))

        if not rule_id:
            continue
        ev.hits.append(
            RuleHit(
                rule_id=rule_id,
                message=text,
                severity=str(details.get("severity") or ""),
                tags=list(details.get("tags") or []),
                matched_location=loc,
                matched_data=matched,
            )
        )
    ev.anomaly_score = score
    return ev


def parse_lines(lines: Iterable[str]) -> tuple[list[Event], int]:
    """Parse an iterable of JSON-audit lines. Returns (events, skipped)."""
    events: list[Event] = []
    skipped = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            skipped += 1
            continue
        ev = parse_event(obj)
        if ev is None:
            skipped += 1
            continue
        events.append(ev)
    return events, skipped


def parse_file(path: str) -> tuple[list[Event], int]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh)


def iter_file(path: str) -> Iterator[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        yield from fh
