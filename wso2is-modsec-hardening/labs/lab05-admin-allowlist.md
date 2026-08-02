# Lab 05 — Restrict the Admin Console to Allow-Listed IPs

> **Level:** Advanced
> **Goal:** Lock down `/carbon`, `/console`, and the management REST APIs to
> a trusted network — the one place a WAF operator should turn paranoia
> **up**, since it is low-traffic and high-value.

---

## 1. Theory — the admin surface deserves a stricter posture

Unlike the public IAM endpoints (Lab 03, where over-blocking hurts real
users), the admin console and management REST APIs are used by a small,
known set of operators. Deny-by-default, allow-list the rest, is the correct
default here.

---

## 2. A real engine bug found while building this

The natural way to write "deny this path unless the source IP is
allow-listed" is a **chained** rule:

```apache
SecRule REQUEST_URI "@beginsWith /carbon" "id:1900301,phase:1,deny,status:403,chain"
    SecRule REMOTE_ADDR "!@ipMatch 172.17.0.1,127.0.0.1"
```

A single such rule works fine. **Two** of them in the loaded rule set —
regardless of file, path, or content — reproducibly broke this engine's own
parsing of its bundled CRS files, with a confusing error blamed on an
unrelated file:

```
"modsecurity_rules_file" directive Rules error. File: .../REQUEST-901-INITIALIZATION.conf.
Line: 1. Column: 75. Expecting an action, got: # ------ ...
```

This was isolated with a minimal reproduction: two trivial `chain` rules,
unrelated ids/paths/messages, still broke it; splitting them into separate
files did not help; a single chain rule was reliably fine across repeated
fresh container starts.

### The fix: `skipAfter` / `SecMarker` instead of `chain`

Same allow-then-deny logic, a different (also standard) ModSecurity idiom,
verified stable:

```apache
SecRule REMOTE_ADDR "@ipMatch 172.17.0.1,127.0.0.1" \
    "id:1900300,phase:1,pass,nolog,skipAfter:END_ADMIN_ALLOWLIST"

SecRule REQUEST_URI "@beginsWith /carbon" \
    "id:1900301,phase:1,deny,status:403,log,msg:'...'"
SecRule REQUEST_URI "@beginsWith /console" \
    "id:1900302,phase:1,deny,status:403,log,msg:'...'"

SecMarker END_ADMIN_ALLOWLIST
```

An allow-listed source IP skips straight past the deny rules; anyone else
hits them.

---

## 3. Run it

```bash
docker run -d --name lab05 \
  -v "$PWD/hardening/stage1-baseline:/hardening.d:ro" \
  -v "$PWD/rules/stage5-admin-allowlist.conf:/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-STAGE5.conf:ro" \
  -p 8080:8080 -p 8443:8443 \
  wso2is-hardening:base
```

`172.17.0.1` (Docker's default bridge gateway) is allow-listed so `curl` on
the host demonstrates the allowed path without extra network setup — replace
it with your real admin network/VPN range for anything beyond this lab.

---

## 4. Verify

```bash
# From the allow-listed host:
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:8443/carbon/admin/login.jsp
# 200

curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:8443/console
# 200

# An unrelated path is completely unaffected
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:8443/
# 302
```

To see the deny side, edit the rule's IP list to an address you are not
using (e.g. `10.0.0.99`) and rerun — `/carbon` returns `403`.

---

## 5. Recap

- The admin surface gets a stricter, deny-by-default posture; public IAM
  endpoints do not.
- A real ModSecurity engine limitation was found and worked around: avoid
  more than one `chain` rule group in this engine build; use
  `skipAfter`/`SecMarker` for allow-then-deny logic instead.
- Always verify the allowed path still works and unrelated paths are
  unaffected, not just that the deny path blocks.

**Next:** Lab 06 (capstone) finds and virtual-patches a real bypass of this
very allow-list.
