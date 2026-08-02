# Lab 01 — Baseline: A Naive WSO2 IS Deployment

> **Level:** Advanced (assumes the beginner ModSecLabs course)
> **Goal:** Stand up WSO2 IS 7.3 behind a barely-configured WAF and see
> exactly what is exposed by default, before any hardening.

---

## 1. Theory — why start from "naive"?

Every hardening curriculum needs an honest starting point. This lab boots
the combined WSO2 IS 7.3 + ModSecurity/CRS image with **zero** hardening
scripts applied — CRS runs at its out-of-the-box paranoia level, and WSO2 IS
keeps every default: default admin credentials, HSTS off, the legacy
`/carbon` console and management REST APIs reachable from anywhere.

This is not a strawman. It is what you get from `docker run` on day one,
and it is exactly the state real organizations are in before someone does
this hardening work.

---

## 2. Run it

```bash
docker build -t wso2is-hardening:base .
docker run -d --name lab01 \
  -v "$PWD/hardening/stage1-baseline:/hardening.d:ro" \
  -p 8080:8080 -p 8443:8443 \
  wso2is-hardening:base

# WSO2 IS takes ~30-60s to finish booting
docker logs -f lab01 | grep "WSO2 Carbon started"
```

`hardening/stage1-baseline/` is empty on purpose — no scripts run, so
nothing is patched.

---

## 3. See the exposure

```bash
# 1. Default admin/admin credentials are live
grep -A2 "^\[super_admin\]" \
  <(docker exec lab01 cat /home/wso2carbon/wso2is-7.3.0/repository/conf/deployment.toml)
# password = "admin"

# 2. No HSTS
curl -sk -I https://localhost:8443/console | grep -i strict-transport
# (nothing)

# 3. The admin console is reachable from any IP, no allow-list at all
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:8443/carbon/admin/login.jsp
# 200 -- reachable by anyone who can route to this host

# 4. The backend itself leaks its identity if ever reached directly
#    (the WAF happens to mask this for proxied traffic -- see Lab 02 for why
#    that is not something to rely on)
docker exec lab01 curl -sk -I https://127.0.0.1:9443/console | grep -i "^server:"
# Server: WSO2 Carbon Server
```

---

## 4. Recap

| Exposure | Status at baseline |
|---|---|
| Default admin credentials | Unrotated |
| HSTS | Off |
| Backend `Server` header | Leaks "WSO2 Carbon Server" |
| Admin console (`/carbon`, `/console`) | Reachable from any IP |
| CRS tuning for IAM traffic | None -- default CRS may false-positive on legitimate OAuth/SCIM traffic (Lab 03) |
| Rate limiting on auth endpoints | None |

**Next:** Lab 02 applies WSO2's own published hardening guidance to close the
first three rows.
