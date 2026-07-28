"""
Generate a realistic request log for a WSO2 Identity Server (IS 7.2) deployment,
in the JSON-lines format the engine consumes.

Writes two files so the baselining workflow is honest:

* ``baseline.jsonl`` — NORMAL traffic only. Many users each completing the full
  OIDC login flow (authorize -> login -> commonauth -> token -> userinfo) plus
  some SCIM and SAML. This is what the engine LEARNS from.
* ``mixed.jsonl``    — a fresh day of traffic: mostly normal, plus a labelled
  holdout of ABNORMAL-but-not-signature traffic (a param far longer than
  normal, an unexpected parameter, a wrong method, an out-of-order flow, a new
  endpoint). None of it is a classic "attack payload" — the whole point is that
  positive-security catches deviation from normal, not signatures.

Run: ``python sample-data/generate_sample.py``
"""
from __future__ import annotations

import base64
import json
import os
import random
import uuid
from datetime import datetime, timedelta

random.seed(7)
_HERE = os.path.dirname(os.path.abspath(__file__))
_T0 = datetime(2026, 7, 28, 8, 0, 0)

REDIRECTS = [
    "https://app.example.com/callback",
    "https://portal.example.com/oidc/cb",
    "https://spa.example.com/auth",
]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/17.5",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
]


def _b64(n=16):
    return base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=")


def req(ts, ip, method, uri, status, sess, ua, label="normal", body=0):
    return {
        "ts": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "client_ip": ip,
        "method": method,
        "uri": uri,
        "headers": {"User-Agent": ua, "Content-Type": "application/x-www-form-urlencoded" if method == "POST" else ""},
        "body_size": body,
        "status": status,
        "session_id": sess,
        "label": label,
    }


def normal_oidc_session(ip, ua, t, sess):
    """A full, well-formed OIDC login flow -> list of requests."""
    state = _b64(); code = _b64(32); rurl = random.choice(REDIRECTS)
    sdk = str(uuid.uuid4())
    out = [
        req(t, ip, "GET",
            f"/oauth2/authorize?response_type=code&client_id=sample_spa&redirect_uri={rurl}&scope=openid%20profile&state={state}",
            302, sess, ua),
        req(t + timedelta(seconds=2), ip, "GET",
            f"/authenticationendpoint/login.do?client_id=sample_spa&sessionDataKey={sdk}",
            200, sess, ua),
        req(t + timedelta(seconds=6), ip, "POST",
            f"/commonauth?sessionDataKey={sdk}&type=oidc", 302, sess, ua, body=120),
        req(t + timedelta(seconds=7), ip, "POST",
            "/oauth2/token?grant_type=authorization_code&code=" + code + "&client_id=sample_spa",
            200, sess, ua, body=180),
        req(t + timedelta(seconds=8), ip, "GET", "/oauth2/userinfo", 200, sess, ua),
    ]
    return out


def normal_saml_session(ip, ua, t, sess):
    blob = base64.b64encode(f"<samlp:AuthnRequest ID='{uuid.uuid4()}'/>".encode()).decode()
    return [
        req(t, ip, "GET", f"/samlsso?SAMLRequest={blob}&RelayState=/portal", 302, sess, ua),
        req(t + timedelta(seconds=4), ip, "POST", "/commonauth?type=samlsso", 302, sess, ua, body=140),
    ]


def normal_scim_session(ip, ua, t, sess):
    uid = uuid.uuid4()
    return [
        req(t, ip, "GET", f'/scim2/Users?filter=userName%20eq%20%22user{random.randint(1,999)}%22', 200, sess, ua),
        req(t + timedelta(seconds=1), ip, "GET", f"/scim2/Users/{uid}", 200, sess, ua),
    ]


def build_baseline(n_users=250):
    rows = []
    t = _T0
    for i in range(n_users):
        ip = f"10.0.{random.randint(0,40)}.{random.randint(1,254)}"
        ua = random.choice(UAS)
        sess = f"sess-{i:04d}"
        t += timedelta(seconds=random.randint(1, 20))
        roll = random.random()
        if roll < 0.7:
            rows += normal_oidc_session(ip, ua, t, sess)
        elif roll < 0.9:
            rows += normal_scim_session(ip, ua, t, sess)
        else:
            rows += normal_saml_session(ip, ua, t, sess)
    return rows


def build_mixed():
    rows = build_baseline(n_users=80)  # a fresh, smaller normal day
    t = _T0 + timedelta(hours=2)

    # --- ABNORMAL holdout (labelled), NOT signature attacks ---
    # 1. redirect_uri far longer than the learned normal (data exfil-ish / fuzz)
    for k in range(6):
        ip = "203.0.113.5"; sess = f"ab-len-{k}"
        long_uri = "https://evil.example/" + ("A" * 400)
        rows.append(req(t, ip, "GET",
            f"/oauth2/authorize?response_type=code&client_id=sample_spa&redirect_uri={long_uri}&scope=openid&state=x",
            302, sess, UAS[0], label="abnormal"))
    # 2. unexpected parameter never seen on the endpoint
    for k in range(5):
        ip = "203.0.113.9"; sess = f"ab-param-{k}"
        rows.append(req(t, ip, "GET",
            "/oauth2/token?grant_type=authorization_code&code=" + _b64(32) + "&client_id=sample_spa&debug=1&cmd=whoami",
            200, sess, UAS[1], label="abnormal"))
    # 3. wrong method on a known endpoint
    for k in range(5):
        ip = "203.0.113.11"; sess = f"ab-method-{k}"
        rows.append(req(t, ip, "DELETE", "/oauth2/userinfo", 405, sess, UAS[2], label="abnormal"))
    # 4. brand-new endpoint never in baseline (recon)
    for k in range(5):
        ip = "203.0.113.13"; sess = f"ab-ep-{k}"
        rows.append(req(t, ip, "GET", f"/carbon/admin/login.jsp?x={k}", 200, sess, "curl/8.0", label="abnormal"))
    # 5. out-of-order flow: token WITHOUT a preceding authorize
    for k in range(5):
        ip = "203.0.113.17"; sess = f"ab-seq-{k}"
        rows.append(req(t, ip, "POST",
            "/oauth2/token?grant_type=authorization_code&code=" + _b64(32) + "&client_id=sample_spa",
            400, sess, UAS[0], label="abnormal", body=180))
        rows.append(req(t + timedelta(seconds=1), ip, "GET", "/oauth2/userinfo", 401, sess, UAS[0], label="abnormal"))

    random.shuffle(rows)
    return rows


def _dump(name, rows):
    path = os.path.join(_HERE, name)
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return path, len(rows)


if __name__ == "__main__":
    b = _dump("baseline.jsonl", build_baseline())
    m = _dump("mixed.jsonl", build_mixed())
    print(f"wrote {b[0]} ({b[1]} requests)")
    print(f"wrote {m[0]} ({m[1]} requests)")
