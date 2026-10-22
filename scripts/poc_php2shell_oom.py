#!/usr/bin/env python3
"""
PoC for the "OOM half" of PHP2Shell (CVE-2026-109618, unverified) and the
scored, request+response-correlated side of
rules/VIRTUAL-PATCH-php2shell.conf (ids 1000912-1000919).

Technique: a multipart/form-data POST with an abnormally large number of
fields, or an abnormally large body, pushes PHP's multipart parser into a
memory-exhaustion state. webapp/app.py's /api/php2shell endpoint simulates
that crash (500 + "Allowed memory size ... exhausted") without actually
executing anything, so the WAF's response-correlation rule has a real
signature to match against.

Demonstrates three distinct paths through the rule file:
  A. Composite score crosses the threshold from the REQUEST alone (excessive
     arg count + an oversized arg value) -> blocked at phase:2 (id:1000918),
     the backend is never touched.
  B. A single signal (oversized body) scores *below* threshold -> the WAF
     passes the request -> the backend genuinely "crashes" -> the phase:4
     rule (id:1000919) correlates RESPONSE_STATUS + RESPONSE_BODY and
     quarantines the source IP for 1 hour.
  C. A follow-up CLEAN request from the same IP is now hard-blocked at
     phase:1 (id:1000911) -- proving the escalation is IP-scoped, not
     content-scoped: confirmed bad behaviour buys cheap blocking of
     whatever that IP sends next.

Usage:
    python3 scripts/poc_php2shell_oom.py [base_url]
    (default base_url: http://localhost:8080)

Requires SecResponseBodyAccess On in the WAF container (needed for path B/C
to work) -- docker-compose.yml already sets ANOMALY_OUTBOUND, which implies
the CRS image has outbound/response-body inspection enabled.
"""
import os
import sys
import requests

BODY_LIMIT = 2_000_000  # must match tx.php2shell_body_limit in the rule file
MAX_ARGS = 255  # must match tx.php2shell_max_args
ARG_LENGTH = 400  # must match tx.php2shell_arg_length


def show(label, resp):
    snippet = resp.text.strip().replace("\n", " ")[:100]
    print(f"{label:55s} -> HTTP {resp.status_code}   {snippet}")


def demo_a_direct_score_block(url):
    # score = +4 (arg count > 255, rule 1000913) + +2 (oversized single arg,
    # rule 1000914) = 6, which is > threshold(5) -> blocked by 1000918
    # before the request reaches the backend at all.
    fields = {f"f{i}": (None, "x" * (ARG_LENGTH + 1)) for i in range(MAX_ARGS + 5)}
    r = requests.post(url, files=fields)
    show("A. high arg-count + oversized arg (direct score block)", r)


def demo_b_response_correlation(session, url):
    # score = +3 only (oversized multipart body, rule 1000915) -- below the
    # threshold(5), so the WAF passes it through. The backend then genuinely
    # returns a 500 with a PHP fatal-error signature, which rule 1000919
    # correlates against the already-flagged transaction.
    big_file = os.urandom(BODY_LIMIT + 50_000)
    r = session.post(url, files={"upload": ("big.bin", big_file, "application/octet-stream")})
    show("B. oversized body only (passes WAF, backend crashes)", r)


def demo_c_ip_quarantine(session, url):
    r = session.get(url)
    show("C. clean follow-up request, same IP (should now be blocked)", r)


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    url = f"{base}/upload.php"

    r = requests.get(url)
    show("0. clean baseline", r)

    demo_a_direct_score_block(url)

    # A single requests.Session reuses the same source IP for steps B and C
    # (both hit the WAF from this one process), which is what the IP
    # collection keys on.
    session = requests.Session()
    demo_b_response_correlation(session, url)
    demo_c_ip_quarantine(session, url)

    print(
        "\nExpected: (0) 200, (A) 403 'composite score ... exceeded "
        "threshold' with the backend never seeing the request, (B) 200 "
        "from the WAF but 500 from the app (visible if you curl :5000 "
        "directly) -- the WAF passed it, then (C) 403 'under active "
        "quarantine' even though this last request is perfectly clean, "
        "because the IP was confirmed bad by (B)'s response correlation."
    )


if __name__ == "__main__":
    main()
