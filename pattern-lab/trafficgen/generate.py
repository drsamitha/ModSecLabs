"""
Traffic generator for the behavioural-baselining stack.

Drives realistic user sessions THROUGH the WAF at a real WSO2 Identity Server
and records every request it sent, in the engine's request-log schema, to
``/capture/<name>.jsonl`` (a shared volume). That client-side capture is the
authoritative record of what was sent; in production you would instead read the
WAF's own JSON access log (see docker-compose + README) — same schema.

Two modes:
  MODE=baseline  -> only well-formed sessions (the learning window)
  MODE=mixed     -> mostly normal + a labelled abnormal holdout (to score)

    TARGET=http://waf:8080 MODE=baseline OUT=/capture/baseline.jsonl python generate.py
"""
from __future__ import annotations

import base64
import json
import os
import random
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:  # pragma: no cover
    requests = None

TARGET = os.environ.get("TARGET", "http://localhost:8080")
MODE = os.environ.get("MODE", "baseline")
OUT = os.environ.get("OUT", f"/capture/{MODE}.jsonl")
N = int(os.environ.get("SESSIONS", "200"))

REDIRECTS = ["https://app.example.com/callback", "https://portal.example.com/oidc/cb"]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/17.5",
]


def _b64(n=16):
    return base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _send(rec, sink):
    """Record the request in our schema, and (best-effort) fire it at the WAF."""
    sink.write(json.dumps(rec) + "\n")
    if requests is None:
        return
    try:
        headers = {"X-Forwarded-For": rec["client_ip"],
                   "User-Agent": rec["headers"]["User-Agent"], "Host": "id.example.com"}
        requests.request(rec["method"], TARGET + rec["uri"], headers=headers,
                         timeout=6, verify=False, allow_redirects=False)
    except Exception:  # noqa: BLE001
        pass


def _rec(ip, method, uri, sess, ua, label="normal", status=200, body=0):
    return {"ts": _now(), "client_ip": ip, "method": method, "uri": uri,
            "headers": {"User-Agent": ua}, "body_size": body, "status": status,
            "session_id": sess, "label": label}


def oidc(ip, ua, sess):
    sdk = str(uuid.uuid4())
    return [
        _rec(ip, "GET", f"/oauth2/authorize?response_type=code&client_id=sample_spa&redirect_uri={quote(random.choice(REDIRECTS))}&scope=openid%20profile&state={_b64()}", sess, ua, status=302),
        _rec(ip, "GET", f"/authenticationendpoint/login.do?client_id=sample_spa&sessionDataKey={sdk}", sess, ua),
        _rec(ip, "POST", f"/commonauth?sessionDataKey={sdk}&type=oidc", sess, ua, status=302, body=120),
        _rec(ip, "POST", f"/oauth2/token?grant_type=authorization_code&code={_b64(32)}&client_id=sample_spa", sess, ua, body=180),
        _rec(ip, "GET", "/oauth2/userinfo", sess, ua),
    ]


def scim(ip, ua, sess):
    return [
        _rec(ip, "GET", f'/scim2/Users?filter=userName%20eq%20%22user{random.randint(1,999)}%22', sess, ua),
        _rec(ip, "GET", f"/scim2/Users/{uuid.uuid4()}", sess, ua),
    ]


def abnormal(ip, ua, sess, kind):
    if kind == "len":
        return [_rec(ip, "GET", "/oauth2/authorize?response_type=code&client_id=sample_spa&redirect_uri=https://evil.example/" + "A" * 400 + "&state=x", sess, ua, "abnormal", 302)]
    if kind == "param":
        return [_rec(ip, "GET", f"/oauth2/token?grant_type=authorization_code&code={_b64(32)}&client_id=sample_spa&debug=1&cmd=whoami", sess, ua, "abnormal")]
    if kind == "method":
        return [_rec(ip, "DELETE", "/oauth2/userinfo", sess, ua, "abnormal", 405)]
    if kind == "endpoint":
        return [_rec(ip, "GET", "/carbon/admin/login.jsp", sess, "curl/8.0", "abnormal")]
    return [  # out-of-order flow
        _rec(ip, "POST", f"/oauth2/token?grant_type=authorization_code&code={_b64(32)}&client_id=sample_spa", sess, ua, "abnormal", 400, 180),
        _rec(ip, "GET", "/oauth2/userinfo", sess, ua, "abnormal", 401),
    ]


def main():
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    sent = 0
    with open(OUT, "w", encoding="utf-8") as sink:
        for i in range(N):
            ip = f"10.0.{random.randint(0,40)}.{random.randint(1,254)}"
            ua = random.choice(UAS)
            sess = f"{MODE}-{i:04d}"
            roll = random.random()
            reqs = oidc(ip, ua, sess) if roll < 0.75 else scim(ip, ua, sess)
            for r in reqs:
                _send(r, sink); sent += 1
            if MODE == "mixed" and random.random() < 0.12:
                kind = random.choice(["len", "param", "method", "endpoint", "seq"])
                for r in abnormal("203.0.113." + str(random.randint(1, 50)), ua, f"ab-{i}", kind):
                    _send(r, sink); sent += 1
            if i % 25 == 0:
                print(f"  {i}/{N} sessions, {sent} requests")
            time.sleep(0.005)
    print(f"done: wrote {sent} requests to {OUT}")


if __name__ == "__main__":
    main()
