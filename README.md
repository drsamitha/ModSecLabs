# ModSecLabs — A Hands-On ModSecurity + OWASP CRS Course

A practical, beginner-to-advanced course for learning **ModSecurity** and the
**OWASP Core Rule Set (CRS)** by doing. Every lab is a self-contained practical
sheet (also provided as a **PDF**) that pairs the **theory** with a **running
lab** you attack and defend yourself, using the official
`owasp/modsecurity-crs:nginx` Docker image.

The course is written for **web developers moving into the WAF-operator seat** —
it focuses on what internal engineers actually do in industry: standing up the
WAF, reading logs, tuning false positives, writing custom rules, and
virtual-patching a live CVE — and it's honest about where a WAF fails.

---

## The lab stack

```
  attacker/browser  ──►  :8080  nginx + ModSecurity + OWASP CRS  ──►  :5000  Flask target app
                              (the WAF: inspects every request)          (deliberately vulnerable)
```

- **`webapp/`** — a small, intentionally naive Flask app with endpoints that are
  vulnerable to XSS, SQLi, path traversal and Log4Shell-style payloads. It is
  the same target used across **all** labs. *(Lab target only — never expose it.)*
- **`waf`** — the `owasp/modsecurity-crs:nginx` container, configured per-lab.
- You attack `http://localhost:8080` (through the WAF) and compare with
  `http://localhost:5000` (the raw, unprotected app).

### Quick start

```bash
# 1. Bring up the stack (Flask target + WAF)
docker compose up -d --build

# 2. A clean request passes...
curl -i http://localhost:8080/

# 3. ...an attack is blocked
curl -i "http://localhost:8080/search?q=<script>alert(1)</script>"   # 403

# 4. See which rule fired
docker logs modseclabs-waf | tail -n 40
```

> **Note on the Docker build:** `docker compose` builds the Flask image from
> `webapp/`. If your network blocks PyPI, you can instead run the app with
> `python webapp/app.py` on the host and point the WAF's `BACKEND` at
> `http://host.docker.internal:5000` (the individual labs show this form).

---

## The labs

Work through them in order — each builds on the last. Every lab has a
Markdown source in [`labs/`](labs/) and a print-ready PDF in [`docs/`](docs/).

| # | Lab | You will learn | PDF |
|---|-----|----------------|-----|
| 01 | **Intro to ModSecurity & CRS** | What a WAF is; engine vs. rule set; first allowed vs. blocked request | [PDF](docs/Lab01-Intro-to-ModSecurity.pdf) |
| 02 | **Detection vs Prevention & Audit Logs** | `SecRuleEngine` modes; reading the audit log; anomaly scoring | [PDF](docs/Lab02-Detection-vs-Prevention.pdf) |
| 03 | **SQL Injection** | SQLi theory; the `942xxx` family; libinjection; safety-net vs. real fix | [PDF](docs/Lab03-SQL-Injection.pdf) |
| 04 | **Cross-Site Scripting** | XSS vectors; the `941xxx` family; why multiple rules stack | [PDF](docs/Lab04-XSS.pdf) |
| 05 | **Path Traversal, Paranoia & Threshold** | LFI (`930xxx`); the two operator dials — paranoia level & anomaly threshold | [PDF](docs/Lab05-PathTraversal-Paranoia.pdf) |
| 06 | **Writing Your Own Rules** | The `SecRule` language; variables/operators/actions/phases; chained rules; the phase-ordering bug | [PDF](docs/Lab06-Writing-Rules.pdf) |
| 07 | **False Positives & Surgical Tuning** | Diagnosing FPs from logs; scoped `ctl:` exclusions; the DetectionOnly→On go-live workflow | [PDF](docs/Lab07-False-Positives-Tuning.pdf) |
| 08 | **CVE Virtual Patching & Where It Fails** | Virtual-patching Log4Shell (CVE-2021-44228); WAF bypasses & honest limitations; defence in depth | [PDF](docs/Lab08-CVE-VirtualPatching.pdf) |

---

## What's in the repo

```
ModSecLabs/
├── docker-compose.yml         # the WAF + app stack
├── webapp/                    # Flask target app (shared by all labs)
│   ├── app.py
│   └── data/report.txt
├── labs/                      # lab practical sheets (Markdown source)
│   └── lab01.md … lab08.md
├── docs/                      # the same sheets as print-ready PDFs
│   └── Lab01 … Lab08 .pdf
├── rules/                     # custom rules authored during the labs
│   ├── LOCAL-999-CUSTOM.conf          # Lab 06 custom SecRules
│   ├── EXCLUSIONS-BEFORE-CRS.conf     # Lab 07 surgical exclusion
│   ├── VIRTUAL-PATCH-log4shell.conf   # Lab 08 CVE virtual patch
│   └── DISABLE-944.conf               # Lab 08 0-day-window simulation
├── scripts/
│   ├── shoot.py               # headless-Chromium screenshotter
│   └── md2pdf.py              # render a lab .md to a styled PDF
└── screenshots/               # images embedded in the sheets
```

## Regenerating the PDFs

```bash
pip install flask playwright markdown
python scripts/md2pdf.py labs/lab01.md docs/Lab01-Intro-to-ModSecurity.pdf
# ...repeat per lab
```

---

## Key concepts cheat-sheet

**Rule ID families:** `913` scanners · `920/921` protocol · `930` LFI ·
`931` RFI · `932` RCE · `941` XSS · `942` SQLi · `943` session ·
`944` Java/Log4j · `949` blocking evaluation · `1000000–1999999` **your** rules.

**The two operator dials:** *paranoia level* (1–4, how many rules run) and
*anomaly threshold* (how much accumulated suspicion blocks). Start at **PL1**,
threshold **5**, in `DetectionOnly`, then tune.

**Golden workflow:** DetectionOnly → collect logs → triage true/false positives
→ write narrow exclusions → flip to On → iterate forever.

**The honest truth (Lab 08):** a WAF blocks commodity attacks and buys you time
to patch. It does **not** replace secure code, and it can be bypassed. Run it as
**layer 2** of defence in depth.
