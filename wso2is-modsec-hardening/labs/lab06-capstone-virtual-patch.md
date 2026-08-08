# Lab 06 (Capstone) — Virtual-Patching a Path-Normalization Bypass

> **Level:** Advanced
> **Goal:** Find and fix a real bypass of Lab 05's admin allow-list, then run
> a full regression pass confirming public endpoints (JWKS) are still open
> across every stage.

---

## 1. Theory — this is a real, disclosed vulnerability class

Recent disclosed WSO2 vulnerabilities (see references below) are, at a high
level, **auth bypasses via flawed regex/prefix-based access control combined
with a path-normalization mismatch** between the enforcement point and the
backend that actually serves the request. Rather than fabricate an unverified
proof-of-concept for a specific CVE, this lab reproduces and fixes the
underlying **vulnerability class** directly against Lab 05's own rule —
verified live, not assumed.

References (the vulnerability class, not the exact payload used below):
CVE-2025-9152, CVE-2025-10611, CVE-2025-9804, CVE-2025-5605, CVE-2024-4457.

---

## 2. Find the bypass

Using Lab 05's allow-list, from a source IP that is **not** on it:

```bash
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:8443/carbon/admin/login.jsp
# 403 -- blocked, as intended

curl -sk -o /dev/null -w "%{http_code}\n" "https://localhost:8443//carbon/admin/login.jsp"
# 401 -- BYPASSED
```

The double leading slash means `REQUEST_URI` literally starts with
`//carbon`, not `/carbon` — a naive `@beginsWith` check misses it. But
nginx/Tomcat normalize the path and route it to the real admin endpoint
anyway. Confirm the `401` is a genuine WSO2 response (not nginx's 403 page),
proving the request reached the backend unauthenticated:

```bash
curl -sk "https://localhost:8443//carbon/admin/login.jsp"
# {"traceId":"...","code":401,"description":"Authorization failure...","message":"Unauthorized"}
```

---

## 3. The fix — normalize before you match

```apache
SecRule REQUEST_URI "@beginsWith /carbon" \
    "id:1900401,phase:1,deny,status:403,log,t:normalizePath,\
     msg:'Admin console access denied: source IP not in the admin allow-list'"
```

`t:normalizePath` makes the rule see the **same normalized path** the backend
will act on — closing the gap generally, not just for this one payload.

---

## 4. Run it and verify

```bash
docker run -d --name lab06 \
  -v "$PWD/hardening/stage1-baseline:/hardening.d:ro" \
  -v "$PWD/rules/stage6-virtual-patch.conf:/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-STAGE6.conf:ro" \
  -p 8080:8080 -p 8443:8443 \
  wso2is-hardening:base
```

```bash
# The bypass is closed
curl -sk -o /dev/null -w "%{http_code}\n" "https://localhost:8443//carbon/admin/login.jsp"
# 403

# A second bypass variant (dot-segment traversal) is ALSO closed by the same fix
curl -sk -o /dev/null -w "%{http_code}\n" "https://localhost:8443/foo/../carbon/admin/login.jsp"
# 403

# The legitimate allowed path still works from the allow-listed IP
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:8443/carbon/admin/login.jsp
# 200 (from the allow-listed source)
```

---

## 5. Final regression pass — confirm public endpoints are never blocked

Run this against Lab 06's stack (or any later stage) to confirm nothing in
the whole hardening series accidentally over-blocked the public,
by-design-open endpoints:

```bash
for p in /oauth2/jwks /oauth2/token/.well-known/openid-configuration; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:8443$p")
  echo "$p -> $code"
done
# /oauth2/jwks -> 200
# /oauth2/token/.well-known/openid-configuration -> 200
```

If either of these is ever anything other than `200`, a hardening change went
too far — this is the check to run after every future rule change.

---

## 6. Recap — the whole series

| Stage | What it fixed | Where |
|---|---|---|
| 1 | (baseline — nothing) | — |
| 2 | Default creds, HSTS, Server header leak | `deployment.toml`, nginx edge |
| 3 | CRS false positives on realistic OAuth/SCIM traffic | Scoped ModSecurity exclusions |
| 4 | No rate limiting on auth endpoints | nginx `limit_req` (not ModSecurity — verified why) |
| 5 | Admin console open to any IP | ModSecurity allow-list (`skipAfter`, not `chain`) |
| 6 | Path-normalization bypass of the Lab 5 allow-list | `t:normalizePath` |

A WAF in front of an IdP is a volumetric and generic-signature control, not
a substitute for the IdP's own protocol-correctness (a lesson the beginner
course's SAML/XXE discussion covers in depth). This series adds the
IdP-specific layer on top: tuned for IAM traffic shapes, rate-limited on the
endpoints that matter, and with the admin surface locked down and
regression-tested.
