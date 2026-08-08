# Lab 04 — Rate-Limiting the Auth Endpoints

> **Level:** Advanced
> **Goal:** Rate-limit `/oauth2/token` and `/commonauth` against brute force
> and credential stuffing — and learn why ModSecurity itself is the wrong
> tool for this in this engine build.

---

## 1. Theory — rate limiting is not a WAF pattern-matching problem

Okta, Auth0, and PingIdentity all treat rate limiting on token/login
endpoints as a distinct control from attack-signature detection — implemented
at the reverse-proxy/API-gateway layer, not inside the WAF's rule-matching
engine. This lab found out why the hard way.

### What did not work

ModSecurity's classic v2 rate-limiting recipe uses a **persistent per-IP
collection** (`initcol` + `setvar` + `expirevar`), incrementing a counter
across requests and blocking once it crosses a threshold:

```apache
SecAction "id:1999001,phase:1,pass,nolog,initcol:ip=%{REMOTE_ADDR},setvar:ip.counter=+1,expirevar:ip.counter=60"
SecRule IP:counter "@gt 3" "id:1999002,phase:1,deny,status:429"
```

Loaded without error — but sending request after request **never** tripped
the block. This engine (`libmodsecurity3`, the nginx/Apache connector
rewrite, v3.0.16 here) silently no-ops persistent collections: the syntax
is accepted, but no state is actually kept across requests. This is a known
architectural difference from the old Apache-module ModSecurity v2.

### What does work

nginx's own `limit_req`, scoped to **only** the auth endpoints via a `map`
that produces an empty key (nginx's documented way to exempt a request from
limiting) for every other path — so the rest of the site is completely
unaffected by hammering the auth endpoints.

---

## 2. Run it

```bash
docker run -d --name lab04 \
  -v "$PWD/hardening/stage4-rate-limit:/hardening.d:ro" \
  -p 8080:8080 -p 8443:8443 \
  wso2is-hardening:base
```

Read `hardening/stage4-rate-limit/01-nginx-rate-limit-zone.sh` and
`02-nginx-rate-limit-apply.sh` — they inject `limit_req_zone` (keyed only for
`/oauth2/token` and `/commonauth`, 5 requests/minute) and `limit_req`
(`burst=3 nodelay`) directly into the rendered nginx config, before nginx's
first start.

---

## 3. Verify

```bash
# Hammer /oauth2/token
for i in $(seq 1 8); do
  curl -sk -o /dev/null -w "req $i: %{http_code}\n" https://localhost:8443/oauth2/token
done
# req 1-4: 405 (reached the backend -- GET isn't valid for this endpoint, but
#           that's a REAL app response, not a WAF block)
# req 5-8: 429 (Too Many Requests -- throttled)

# An unrelated path, hit just as fast, is completely unaffected
for i in 1 2 3; do
  curl -sk -o /dev/null -w "req $i: %{http_code}\n" https://localhost:8443/
done
# 302, 302, 302 -- never throttled
```

---

## 4. Recap

- ModSecurity's persistent-collection rate-limiting recipe is a **no-op** in
  this engine build (`libmodsecurity3`) — verified, not assumed.
- Real rate limiting here happens at the **reverse-proxy layer** (nginx
  `limit_req`), matching how Okta/Auth0/PingIdentity actually do it.
- Scope the rate limit to the auth endpoints specifically — a `map`-based key
  is a clean way to exempt everything else without duplicating location
  blocks.

**Next:** Lab 05 restricts the admin console to an IP allow-list — and
documents a real ModSecurity engine bug found along the way.
