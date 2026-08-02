# Lab 02 — WSO2's Own Hardening Guidance

> **Level:** Advanced
> **Goal:** Apply WSO2's own published production hardening guidance —
> rotate default credentials, enforce HSTS, stop leaking the product
> identity — before touching anything WAF-specific.

---

## 1. Theory — fix what the vendor tells you to fix first

WSO2 publishes hardening guidance (`security.docs.wso2.com`, and per-version
"Product-Level Security Guidelines" pages). Before adding WAF rules, close
the gaps the vendor itself calls out — they are free, vendor-endorsed, and
some of them a WAF cannot compensate for at all (a WAF cannot change your
super-admin password for you).

This lab applies three, each verified against WSO2 IS 7.3's real config
files (not assumed from the docs — the actual mechanism used, and one gap
that had to be found by inspecting the product, is documented in each
script):

1. **Rotate the default admin password** — `[super_admin]` in
   `deployment.toml`.
2. **Enforce HSTS** — done at the **WAF edge**, not per-webapp. WSO2 IS's
   legacy `/carbon` webapp has an `HttpHeaderSecurityFilter` (off by
   default), but the newer `/console` React app has **no such filter at
   all** (verified: zero `<filter>` definitions in its `web.xml`). Patching
   each webapp individually is a losing, incomplete game — real deployments
   enforce HSTS once, at the reverse-proxy edge, covering every path.
3. **Stop leaking the product/stack in the `Server` header** — the naive fix
   (sed-patching `catalina-server.xml`) does **not** stick: WSO2 IS
   regenerates that file from a Jinja2 template on every boot, driven by
   `deployment.toml`. The edit that survives a reboot is adding `server =
   "webserver"` to `[transport.http.properties]` /
   `[transport.https.properties]` in `deployment.toml` itself — found by
   reading the actual template.

---

## 2. Run it

```bash
docker run -d --name lab02 \
  -v "$PWD/hardening/stage2-vendor-hardening:/hardening.d:ro" \
  -p 8080:8080 -p 8443:8443 \
  wso2is-hardening:base

docker logs -f lab02 | grep "WSO2 Carbon started"
```

Read `hardening/stage2-vendor-hardening/*.sh` — three small, commented
scripts, each patching one real config file.

---

## 3. Verify each fix

```bash
# 1. Password rotated (config-level check; the full login flow needs a real
#    browser session -- WSO2 IS 7.3's login is a JS-driven SPA that needs a
#    sessionDataKey from a live OAuth2/SAML redirect, impractical to script)
docker exec lab02 grep -A2 "^\[super_admin\]" \
  /home/wso2carbon/wso2is-7.3.0/repository/conf/deployment.toml
# password = "ChangeMe!2026-Hardened"

# 2. HSTS present, at the edge, on every path
curl -sk -I https://localhost:8443/console | grep -i strict-transport
# strict-transport-security: max-age=31536000; includeSubDomains

# 3. Backend no longer leaks WSO2 -- checked directly (bypassing the WAF,
#    which already masks this for proxied traffic) to prove the FIX is real,
#    not just WAF-side masking
docker exec lab02 curl -sk -I https://127.0.0.1:9443/console | grep -i "^server:"
# Server: webserver
```

---

## 4. Recap

| Fix | Mechanism | Survives reboot |
|---|---|---|
| Admin password | `deployment.toml` `[super_admin]` | Yes (read at account creation) |
| HSTS | nginx `add_header`, edge-wide | Yes (WAF-side, not backend) |
| Server header | `deployment.toml` `[transport.*.properties]`, NOT the generated XML | Yes (verified against the Jinja2 template source) |

**Next:** Lab 03 puts real IAM/OAuth traffic through default CRS and finds
(and fixes) a genuine false positive.
