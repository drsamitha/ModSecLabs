# Lab 03 — Tuning CRS for IAM/OAuth Traffic

> **Level:** Advanced
> **Goal:** Reproduce a real CRS false positive against legitimate OAuth2/
> SCIM traffic, then fix it with the same narrow-exclusion discipline taught
> in the beginner course — scoped to the exact rule, argument, and path.

---

## 1. Theory — IAM traffic looks unusually "attack-shaped"

High-entropy secrets, JWTs, and SCIM filter syntax (`userName eq "alice" and
active eq true`) all resemble the kind of strings CRS's generic SQLi/XSS
rules are built to catch. This is not a hypothetical — it is reproducible
against this exact stack.

---

## 2. Reproduce the false positive

```bash
docker run -d --name lab03-fp \
  -v "$PWD/hardening/stage1-baseline:/hardening.d:ro" \
  -p 8080:8080 -p 8443:8443 \
  wso2is-hardening:base
# wait for boot...

curl -sk -o /dev/null -w "%{http_code}\n" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig" \
  --data-urlencode "client_id=my_client" \
  --data-urlencode "client_secret=SuperSecretValue123!@#" \
  https://localhost:8443/oauth2/token
# 403 -- a completely legitimate token refresh request, BLOCKED
```

Confirm the culprit from the audit log:

```bash
docker exec lab03-fp grep -o '"ruleId":"[0-9]*"[^}]*"data":"[^"]*"' \
  /var/log/modsecurity/audit/modsec_audit.log | tail -3
# "ruleId":"942100", ... "data":"Matched Data: novc found within ARGS:client_secret: SuperSecretValue123!@#"
```

Rule `942100` (libinjection SQLi) mistook the punctuation in a realistic
client secret for SQL injection.

---

## 3. Fix it — scoped, not global

```bash
docker rm -f lab03-fp

docker run -d --name lab03 \
  -v "$PWD/hardening/stage1-baseline:/hardening.d:ro" \
  -v "$PWD/rules/stage3-crs-iam-tuning.conf:/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-STAGE3.conf:ro" \
  -p 8080:8080 -p 8443:8443 \
  wso2is-hardening:base
```

Read `rules/stage3-crs-iam-tuning.conf` — it excludes rule `942100` (and
`942190`) for exactly `ARGS:client_secret`, `ARGS:refresh_token`,
`ARGS:code`, and `ARGS:filter`, and only on `/oauth2/token` and `/scim2`.
Nothing else changes.

---

## 4. Verify — false positive gone, real attacks still blocked

```bash
# 1. The false positive is gone (401 = auth rejected our fake creds, not a WAF block)
curl -sk -o /dev/null -w "%{http_code}\n" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig" \
  --data-urlencode "client_id=my_client" \
  --data-urlencode "client_secret=SuperSecretValue123!@#" \
  https://localhost:8443/oauth2/token
# 401

# 2. Legit SCIM2 filter also passes (401 = needs real auth, not a WAF block)
curl -sk -o /dev/null -w "%{http_code}\n" \
  -G "https://localhost:8443/scim2/Users" \
  --data-urlencode 'filter=userName eq "alice" and active eq true'
# 401

# 3. A REAL SQLi on the SAME parameter is STILL blocked
curl -sk -o /dev/null -w "%{http_code}\n" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "client_id=x" \
  --data-urlencode "client_secret=' UNION SELECT password FROM users--" \
  https://localhost:8443/oauth2/token
# 403

# 4. Real SQLi on a DIFFERENT, unscoped parameter is STILL blocked
curl -sk -o /dev/null -w "%{http_code}\n" \
  --data-urlencode "grant_type=' OR '1'='1" \
  https://localhost:8443/oauth2/token
# 403

# 5. JWKS -- never touched by this exclusion, confirm it is still open
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:8443/oauth2/jwks
# 200
```

> **Why the real attacks are still caught:** the `UNION SELECT` payload also
> trips other `942xxx` rules (`942190`, `942360`, ...), so the anomaly score
> still crosses the threshold even with `942100` excluded on this one
> argument. Removing one rule for one argument on one path barely dents real
> attack coverage, because real attacks trip many rules at once — the same
> lesson from the beginner course's tuning lab, now applied to IAM traffic
> specifically.

---

## 5. Recap

- Realistic OAuth2/SCIM payloads (secrets, JWTs, filter syntax) can trip
  generic CRS rules.
- Diagnose from the audit log, never guess the rule ID.
- Scope the exclusion to rule + argument + path — never disable a rule
  globally.
- Re-verify: the false positive is gone, real attacks on the same and other
  parameters are still blocked, and untouched endpoints (JWKS) are
  unaffected.

**Next:** Lab 04 rate-limits the auth endpoints — and finds that
ModSecurity itself cannot do this reliably in this engine build.
