# pattern-lab — WAF traffic pattern recognition & CRS rule-tuning

**Watch real traffic, extract the patterns that keep tripping the WAF, tell
apart false positives from real attacks, and auto-draft the exact ModSecurity
tuning you'd otherwise write by hand — with a dashboard, a CSV, and a
Claude hand-off.**

This is a self-contained subsystem. It answers the question every team hits the
week after they put the OWASP Core Rule Set in front of a real app:

> "The WAF is blocking legitimate users. Which rules, on which parameters, and
> how do I fix it *without* punching holes in my protection?"

The worked example here is **WSO2 Identity Server 7.2 behind the CRS** — a
textbook case, because an IdP's normal OIDC/SAML traffic (`redirect_uri`,
`state`, `code`, `SAMLRequest`, `sessionDataKey`) structurally looks like
attacks to signature rules.

![dashboard](screenshots/dashboard.png)

---

## What it does (the pipeline)

```
 ModSecurity audit log (JSON)
        │
        ▼
 ┌──────────────┐   parse every flagged request → rule hits, matched arg, anomaly
 │  parser.py   │
 └──────┬───────┘
        ▼
 ┌──────────────┐   aggregate into PATTERNS keyed by (rule_id, path, location)
 │ patterns.py  │   measure: volume · distinct clients · value diversity ·
 └──────┬───────┘   anomaly · payload signatures  →  fp_score (0..1) + verdict
        ▼
 ┌──────────────┐   false positives → scoped ctl: exclusions
 │  tuning.py   │   attacks-not-blocked → hardening rule stubs
 └──────┬───────┘   everything → patterns.csv
        ▼
 ┌──────────────┐   dashboard (Flask + inline-SVG charts)  ── OR ──
 │  webapp/     │   claude_prompt.py → feed the CSV to Claude for custom rules
 └──────────────┘
```

### The classification algorithm (no black box)

Each pattern gets a transparent, weighted `fp_score`. Every input is shown in
the dashboard's **why** column and in the CSV, so you can audit any verdict.

| Evidence toward **false positive** | Evidence toward **attack** |
|---|---|
| many distinct legitimate clients trip it (broad) | concentrated in very few source IPs |
| high value diversity (unique tokens, not one payload) | matched data carries an attack signature (`<script>`, `UNION SELECT`, `../`, `${jndi:`) |
| location is a known IdP parameter (`redirect_uri`, `code`, …) | high average anomaly score |
| low anomaly contribution | one IP sweeping many endpoints (scanner) |
| no attack signature in the matched data | |

Intuition: **false positives are broad and boring; real attacks are narrow and
nasty.** That single heuristic drives the whole thing and matches how
experienced operators triage CRS logs.

---

## Quick start (no Docker, 10 seconds)

The engine is **pure Python stdlib — zero dependencies.** A realistic sample
WSO2 audit log ships in `sample-data/`.

```bash
cd pattern-lab
python analyze.py sample-data/sample_audit.jsonl --out out/
```

You get a terminal report plus, in `out/`:

| file | what it is |
|---|---|
| `patterns.csv` | the classified pattern table (the Claude hand-off) |
| `EXCLUSIONS-AUTO.conf` | scoped `ctl:ruleRemoveTargetById` for each false positive |
| `HARDENING-AUTO.conf` | custom-rule stubs for attacks not fully blocked |
| `claude_prompt.txt` | ready-to-paste prompt that turns the CSV into custom rules |

Example of what it generates for a false positive:

```apache
# FP: rule 921151 fires on ARGS:redirect_uri of /oauth2/authorize (120 distinct clients, fp_score=0.70)
#   120 distinct clients trip this (broad), 'redirect_uri' is an expected IdP parameter, no attack signatures
SecRule REQUEST_URI "@beginsWith /oauth2/authorize" \
    "id:1002000,phase:1,pass,nolog,\
     ctl:ruleRemoveTargetById=921151;ARGS:redirect_uri"
```

One target, one rule, one path. Never a global disable.

### The dashboard

```bash
pip install flask
LOGFILE=sample-data/sample_audit.jsonl python webapp/app.py
# → http://localhost:8050
```

KPI tiles, a top-patterns bar chart, the classified table with per-verdict
explanations, a scanner-IP list, and one-click downloads of every artifact.
Charts are inline SVG — **no CDN, works air-gapped.**

### Hand the CSV to Claude for custom rules

```bash
export ANTHROPIC_API_KEY=sk-...
python analyze.py sample-data/sample_audit.jsonl --claude --out out/
# → out/claude_rules.conf   (a full tuned .conf drafted from the CSV)
```

No key? `analyze.py` writes `claude_prompt.txt` instead — paste it into
claude.ai. The offline path always works.

---

## Full test environment (Docker) — real WSO2 IS 7.2 behind the WAF

Instead of the canned sample, drive **real IdP request shapes** through a live
WAF and analyze what it actually logs.

```bash
docker compose up -d                     # WSO2 IS 7.2 + CRS WAF + sample SPA  (~2 min to boot)
docker compose --profile gen run --rm trafficgen   # fire 600 realistic requests through the WAF
docker compose --profile dash up -d dashboard      # http://localhost:8050
# or, on the host:
python analyze.py audit/audit.jsonl --out out/
```

- `wso2is` — the real `wso2/wso2is:7.2.0` image (console on `https://localhost:9443`).
- `waf` — `owasp/modsecurity-crs:nginx`, proxying to IS, writing a **JSON audit
  log** to the shared `./audit/` volume (`MODSEC_AUDIT_LOG_FORMAT=JSON`).
- `sampleapp` — a tiny static SPA standing in for a WSO2 sample JS app (the
  `redirect_uri` origin).
- `trafficgen` — sends ~85% legitimate OIDC/SAML/SCIM traffic from 150 simulated
  client IPs (via `X-Forwarded-For`) + ~15% attacks from 3 IPs.

---

## Where this can fail (the honest part)

The task asked to "make this possible **or say why it failed**." Here's the
straight answer.

**What is proven and runs anywhere (tested):** the parser, the pattern
extraction, the FP-vs-attack classifier, the exclusion/hardening generators,
the CSV, the Claude prompt builder, and the dashboard — all verified against a
faithful WSO2-shaped audit log (`python tests/test_engine.py`, 7 passing). The
classifier correctly separates all 4 IdP false-positives from all 5 attack
families in the sample.

**What depends on your machine, and can fail:**

1. **WSO2 IS 7.2 is heavy.** It needs ~2 GB RAM and 90–120 s to boot. On a
   small host the `waf` container may start before IS is healthy — the compose
   file gates it with a healthcheck, but a RAM-starved IS can still crash-loop.
2. **Traffic ≠ completed logins.** `trafficgen` reproduces the *request shapes*
   a live IdP receives; it does **not** complete real OIDC logins. That needs a
   Service Provider registered in the IS console and real credentials. The WAF
   still inspects and logs every request, which is all the engine needs — but if
   you want end-to-end SSO you must register `sample_spa` yourself.
3. **`X-Forwarded-For` must be trusted for per-client stats to be real.** The
   "distinct clients" signal — the strongest FP indicator — assumes the WAF logs
   the true client IP. Behind a load balancer you must configure ModSecurity to
   read the forwarded header, or every request looks like it came from the LB.
4. **The classifier is a heuristic, not an oracle.** It is tuned for IdP
   traffic. A slow, low-volume, single-source attack that mimics a benign param
   (the `review` verdict exists for exactly this) will need a human. **Every
   generated `.conf` is a draft to review, never auto-applied.**
5. **Image availability.** `wso2/wso2is:7.2.0` and `owasp/modsecurity-crs:nginx`
   must be pullable; an air-gapped host needs them pre-loaded.

Net: the recognition/tuning solution is **real and works today** on any audit
log. The full live-WSO2 loop is **reproducible but resource-dependent** — the
failure modes above are environmental, not design flaws, and each has a stated
workaround.

> WSO2 IS **7.3** is also available and the same pipeline applies unchanged;
> 7.2 was used per the brief.

---

## Layout

```
pattern-lab/
├── analyze.py                 # end-to-end CLI
├── engine/                    # the algorithm (stdlib only)
│   ├── parser.py              #   audit-log → Event/RuleHit
│   ├── patterns.py            #   Event[] → classified Pattern[]  (the core)
│   ├── tuning.py              #   Pattern[] → exclusions / hardening / CSV
│   └── claude_prompt.py       #   CSV → Claude prompt (+ optional API call)
├── webapp/                    # Flask dashboard (inline-SVG charts)
├── trafficgen/                # realistic OIDC/SAML/SCIM + attack generator
├── wso2-sample-app/           # static stand-in SPA
├── sample-data/               # generator + committed sample WSO2 audit log
├── tests/                     # 7 engine tests (python tests/test_engine.py)
└── docker-compose.yml         # WSO2 IS 7.2 + WAF + SPA + trafficgen + dashboard
```
