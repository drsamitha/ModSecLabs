# WSO2 IS 7.3 — ModSecurity Hardening Series

An **advanced**, progressive lab series: start from a naive, default WSO2
Identity Server 7.3 deployment behind a barely-configured WAF, and harden it
stage by stage into a properly production-postured IdP — using
**ModSecurity/OWASP CRS** as the WAF, real vendor guidance, and real-world
IAM-specific WAF practices.

This project is **independent** of the rest of this repo (the beginner
ModSecLabs course, and the earlier WSO2 IS + ELK project) — its own branch,
its own stack, nothing shared. It assumes the beginner course as background.

---

## How this was built

Before writing a single rule, a cybersecurity-focused research pass answered:
*how do real organizations actually harden a WAF in front of an identity
provider?* Findings (Okta/Auth0/PingIdentity rate-limiting practices, the
OWASP API Security Top 10 applied to OAuth/SCIM/SAML endpoints, WSO2's own
published hardening guidance, and a set of real disclosed WSO2
vulnerabilities) shaped the 6-stage curriculum below. Every stage was then
**built and verified against the real running stack** — including finding and
working around a genuine engine bug (see Lab 04) and a genuine false
positive against realistic OAuth traffic (Lab 02), not assumed from the
research alone.

---

## Architecture

Same single-image pattern as the earlier WSO2 IS + ELK project: WSO2 IS 7.3
and nginx+ModSecurity/CRS run as supervised sibling processes in one
container, built from `owasp/modsecurity-crs:nginx` with WSO2 IS 7.3's JDK
and distribution copied in directly from the official `wso2/wso2is:7.3.0`
image.

**New for this series:** a `/hardening.d/*.sh` hook mechanism. Each lab
stage mounts a different directory of small, idempotent shell scripts that
patch WSO2 IS's real config files (`deployment.toml`, nginx's rendered
config) before the server starts. One image serves every stage — you see
exactly what changed by reading the mounted scripts, not by diffing two
pre-baked images.

```bash
docker build -t wso2is-hardening:base .
```

---

## The 6 stages

| # | Lab | What it does |
|---|-----|---------------|
| 1 | [Baseline](labs/lab01-baseline.md) | Naive WSO2 IS behind a barely-configured WAF — see the exposure |
| 2 | [CRS Tuned for IAM Traffic](labs/lab03-crs-iam-tuning.md) | Reproduce and fix a real CRS false positive on legitimate OAuth2/SCIM traffic |
| 3 | [Rate-Limit Auth Endpoints](labs/lab04-rate-limiting.md) | Rate-limit `/oauth2/token` and `/commonauth` — and why ModSecurity itself cannot do this reliably here |
| 4 | [Admin Console Allow-List](labs/lab05-admin-allowlist.md) | Lock `/carbon`, `/console`, management APIs to trusted IPs — and a real ModSecurity engine bug found along the way |
| 5 | [Capstone: Virtual Patch](labs/lab06-capstone-virtual-patch.md) | Find and fix a path-normalization bypass of Lab 4, plus a full regression pass |
| 6 | [ISO/IEC 27001 Mapping & Manual Hardening](labs/lab07-iso27001-mapping.md) | Map every control to Annex A, do the credential/console steps by hand, cross-check against WSO2's official security guidelines |

Run them in order — each stage assumes the previous one's fixes.

Note: lab page filenames keep their original numbers (`lab03`, `lab04`, ...)
even though the table above renumbers sequentially after retiring the old
WSO2-vendor-hardening stage — the table's `#` column is presentational, the
links are what to follow.

A project subagent, `.claude/agents/iam-security-reviewer.md`, reviews
hardening content in this repo against real IAM/WAF engineering practice and
ISO/IEC 27001 Annex A — invoke it (or let Claude Code invoke it automatically)
when adding or changing hardening claims.

---

## Quick start

```bash
docker build -t wso2is-hardening:base .

# Stage 1 (baseline, nothing hardened yet):
docker run -d --name lab \
  -v "$PWD/hardening/stage1-baseline:/hardening.d:ro" \
  -p 8080:8080 -p 8443:8443 \
  wso2is-hardening:base

docker logs -f lab | grep "WSO2 Carbon started"   # ~30-60s
```

Progress through stages by swapping the `hardening.d` mount (and, from Stage
2 onward, also mounting the matching file from `rules/`) — each lab's own
page has the exact command.

---

## Two real bugs found while building this (documented in-line where relevant)

1. **ModSecurity's persistent-collection rate limiting is a silent no-op** in
   this engine build (`libmodsecurity3` v3.0.16) — `initcol`/`setvar`/
   `expirevar` load without error but never actually block anything.
   Verified with a minimal test rule. Real fix: nginx's own `limit_req`
   (Lab 03) — which is also how real organizations actually do it.

2. **A rules file with more than one `chain`-based rule group breaks this
   engine's own parsing of its bundled CRS rules**, with a confusing error
   misattributed to an unrelated CRS file. Isolated via minimal reproduction
   (two trivial chain rules; content, ids, and file placement did not
   matter). Fix: `skipAfter`/`SecMarker` instead of `chain` for allow-list
   logic (Lab 04).

3. **CRS rule 930130 false-positives on `/console/deployment.config.json`**,
   a legitimate unauthenticated static asset the Console React SPA needs on
   every page load — the block crashes the SPA's init code and is the real,
   confirmed root cause of the "Console UI stuck behind the WAF" symptom.
   Found via controlled A/B testing across nginx/Apache and with/without
   ModSecurity, isolating this one rule/path pair. Fixed with a scoped
   exclusion, baked into the Dockerfile for every stage (not opt-in) since
   it's a correctness fix, not a hardening trade-off — see
   `rules/console-deployment-config-exclusion.conf`.

---

## Files

```
wso2is-modsec-hardening/
├── Dockerfile                          # WSO2 IS 7.3 + ModSecurity/CRS, one image
├── docker/
│   ├── start.sh                        # renders config, runs hardening.d, validates nginx config, then supervisord
│   ├── supervisord.conf                # runs nginx + wso2server.sh together
│   └── proxy_backend.conf.template     # baked-in reverse-proxy header/cookie fixes (every stage)
├── hardening/
│   ├── stage1-baseline/                # empty -- no hardening applied
│   └── stage4-rate-limit/              # 2 scripts: nginx limit_req zone + apply
├── rules/
│   ├── console-deployment-config-exclusion.conf  # baked-in CRS 930130 fix (every stage)
│   ├── stage3-crs-iam-tuning.conf      # scoped CRS exclusions for OAuth/SCIM
│   ├── stage5-admin-allowlist.conf     # admin IP allow-list (skipAfter, not chain)
│   └── stage6-virtual-patch.conf       # + t:normalizePath bypass fix
└── labs/                               # this course, one page per stage
```

## Security notes

This is a **lab** configuration. Before using any of this beyond the lab:

- Replace the placeholder admin IP allow-list (`172.17.0.1`) with your real
  admin network/VPN range.
- Rotate the admin password to something you control, not the value shown
  here.
- The rate-limit thresholds (Lab 03) are tuned for a fast lab demo, not
  production traffic patterns — tune `rate=`/`burst=` to your real usage.
