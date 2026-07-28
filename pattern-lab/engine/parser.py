"""
Request-log parser for the behavioural baselining engine.

Positive security learns from **all** legitimate traffic, not just the requests
a signature flagged — so the engine consumes a *request log*, one JSON object
per line, describing every request the WAF saw:

    {"ts": "2026-07-28T09:00:01Z", "client_ip": "10.0.3.7",
     "method": "GET", "uri": "/oauth2/authorize?response_type=code&...",
     "headers": {"User-Agent": "Mozilla/5.0", "Content-Type": ""},
     "body_size": 0, "status": 302,
     "session_id": "sess-abc",          # optional; reconstructed if absent
     "label": "normal"}                 # optional; ONLY used for eval, never training

This is trivially produced by an nginx `log_format` in front of WSO2 IS (the
docker stack does exactly that), and the sample generator / traffic generator
emit it directly for offline runs. The parser is tolerant: an unparseable line
is skipped and counted rather than aborting the run.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import parse_qsl, urlsplit


@dataclass
class Request:
    """One observed HTTP request, pre-featurization."""

    client_ip: str = ""
    method: str = "GET"
    path: str = "/"
    args: dict[str, str] = field(default_factory=dict)  # name -> first value
    headers: dict[str, str] = field(default_factory=dict)  # lower-cased keys
    body_size: int = 0
    status: int = 0
    ts: str = ""
    session_id: str = ""
    label: str = ""  # "normal" | "abnormal" | "" (unknown) — never used in training
    raw_uri: str = ""

    @property
    def user_agent(self) -> str:
        return self.headers.get("user-agent", "")


def _split_uri(uri: str) -> tuple[str, dict[str, str]]:
    parts = urlsplit(uri)
    args: dict[str, str] = {}
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        args.setdefault(k, v)  # first value wins; multiplicity handled in features
    return parts.path or "/", args


def parse_obj(obj: dict) -> Request | None:
    uri = obj.get("uri") or obj.get("request_uri") or "/"
    path, args = _split_uri(uri)
    headers = {str(k).lower(): str(v) for k, v in (obj.get("headers") or {}).items()}
    # allow a flat user_agent field too (common nginx log_format)
    if "user-agent" not in headers and obj.get("user_agent"):
        headers["user-agent"] = str(obj["user_agent"])
    return Request(
        client_ip=obj.get("client_ip") or obj.get("remote_addr") or "",
        method=str(obj.get("method") or "GET").upper(),
        path=path,
        args=args,
        headers=headers,
        body_size=int(obj.get("body_size") or obj.get("request_length") or 0),
        status=int(obj.get("status") or 0),
        ts=str(obj.get("ts") or obj.get("time") or ""),
        session_id=str(obj.get("session_id") or ""),
        label=str(obj.get("label") or ""),
        raw_uri=uri,
    )


def parse_lines(lines: Iterable[str]) -> tuple[list[Request], int]:
    out: list[Request] = []
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
        req = parse_obj(obj)
        if req is None:
            skipped += 1
            continue
        out.append(req)
    return out, skipped


def parse_file(path: str) -> tuple[list[Request], int]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh)
