# Lab 07 — ISO/IEC 27001 Mapping & the Official WSO2 Security Guidelines

> **Level:** Advanced
> **Goal:** Map every control from Labs 1-6 to ISO/IEC 27001 Annex A, cross
> the whole series against WSO2's own published security guidelines, and do
> the credential-rotation and console-restriction steps **by hand** at least
> once — not just via the `hardening.d` scripts.
> **Scope note:** items from the official guidelines that need real
> resources this lab environment does not have — HA/clustering, a separate
> database tier, multi-datacenter DR, Java Security Manager, FIPS mode — are
> called out as **out of scope** below, not silently skipped.

---

## 1. The official source

WSO2 publishes production hardening guidance at
[`is.docs.wso2.com/en/latest/deploy/security/security-guidelines/`](https://is.docs.wso2.com/en/latest/deploy/security/security-guidelines/).
It is a large index page linking to dozens of sub-pages (TLS, keystores,
session/cookie settings, CORS, logging, database security, user-store
security, brute-force mitigation, secure vault/cipher tool, and more).

Two things worth knowing about working with this doc set, found while
building this lab:

- Several sub-page URLs 404 or redirect unexpectedly even when linked from
  the index — if you hit that, verify the setting directly against the
  product's shipped config instead of guessing another URL.
- Not every setting the index describes is safely changeable from outside
  the product. One was found and is documented as a cautionary tale below.

---

## 2. Do it by hand: rotate the admin password

Labs 1-6 apply this via a `hardening.d` script for repeatability. Do it
yourself once, directly, the way an operator actually would:

```bash
docker run -d --name lab07 \
  -v "$PWD/hardening/stage1-baseline:/hardening.d:ro" \
  -p 8080:8080 -p 8443:8443 \
  wso2is-hardening:base
# wait for "WSO2 Carbon started" in the logs

docker exec -it lab07 vi /home/wso2carbon/wso2is-7.3.0/repository/conf/deployment.toml
# find [super_admin], change password = "admin" to something you control
```

This edit only takes effect on the **next boot** (the super-admin account is
created from this value at startup) — restart the container to pick it up,
the same way Lab 02's script does.

---

## 3. Do it by hand: verify the admin console restriction

Lab 05 applies the IP allow-list via a mounted ModSecurity rule file. Read it
yourself and understand exactly what it does before trusting it:

```bash
cat rules/stage5-admin-allowlist.conf
```

Then edit the IP list to your own values by hand (not the placeholder), and
re-test both the allowed and denied paths as Lab 05 describes.

---

## 4. A real finding: not every setting sticks from outside the product

While researching a fourth vendor-recommended control — account lockout
after repeated failed logins, WSO2's brute-force mitigation guidance — this
was found, verified directly against the shipped product (not assumed from
docs):

```bash
docker exec lab07 grep lock.on.max.failed \
  /home/wso2carbon/wso2is-7.3.0/repository/conf/identity/identity-event.properties
# account.lock.handler.lock.on.max.failed.attempts.enable=false   <- disabled by default
```

Editing this file directly — even before first boot, via the same
`hardening.d` mechanism used successfully elsewhere in this series — **does
not persist**: WSO2 IS's own startup process overwrites it back to `false`
during boot, confirmed by checking the file immediately after the edit
(showed `true`) and again after full startup (back to `false`). Unlike the
`Server` header fix in Lab 02, no equivalent `deployment.toml` property was
found that drives this specific setting.

**The honest conclusion:** this control needs to be enabled through WSO2 IS's
own Console UI or Management REST API at runtime, not by editing the file
underneath it — which is itself a useful lesson about IdP hardening:
**verify a fix survives a reboot before you trust it**, exactly as this
series did successfully for the credential and header fixes in Lab 02.

---

## 5. ISO/IEC 27001 Annex A mapping

| Lab | Control | Annex A area |
|---|---|---|
| 2 | Default credential rotation | A.9 Access Control |
| 2 | HSTS enforcement at the edge | A.13 Communications Security |
| 2 | Stop leaking product/stack identity (`Server` header) | A.12 Operations Security |
| 3 | CRS tuned for IAM traffic (false-positive fix) | A.14 System Acquisition, Development and Maintenance |
| 4 | Rate-limiting on auth endpoints | A.13 Communications Security |
| 5 | Admin console IP allow-listing | A.9 Access Control |
| 6 | Virtual-patch a path-normalization bypass | A.12 Operations Security |
| 6 | ModSecurity + WSO2 audit logging (see the earlier ELK project) | A.12 Operations Security (audit logging) |

## Explicitly out of scope for this lab environment

These are real, valid WSO2 recommendations for production — skipped here
because they need resources (extra nodes, a separate DB tier, dedicated
hardware) this single-container lab does not have:

- High availability / clustering, multi-data-center disaster recovery
- Separate production database (this lab uses the embedded H2 store)
- LDAP high availability
- Java Security Manager, FIPS 140-2 mode

If you are taking this series into a real deployment, revisit these against
the official guidelines linked above.
