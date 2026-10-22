#!/usr/bin/env python3
"""
PoC for the "RCE half" of PHP2Shell (CVE-2026-109619, unverified) and the
hard-block rule (id:1000917) in rules/VIRTUAL-PATCH-php2shell.conf.

Technique: a PHP tag smuggled into a request header (classically
User-Agent), relying on the header being written verbatim into a log file
that a vulnerable app later include()'s -> log poisoning -> LFI -> RCE.

Demonstrates:
  1. A clean baseline request passes.
  2. The PHP tag in User-Agent is blocked immediately (403) at phase:2,
     before the request ever reaches the backend -- rule 1000917 hard-blocks
     on sight, same scope CRS's own 933100 uses (any header except Cookie).
  3. The identical payload placed in a body *argument* instead of a header
     is NOT caught by 1000917 (its scope is headers only) -- illustrating
     that this virtual patch is deliberately narrow and still relies on
     CRS's own PHP-injection family (933xxx) for the body case.

Usage:
    python3 scripts/poc_php2shell_rce.py [base_url]
    (default base_url: http://localhost:8080)
"""
import sys
import requests

PAYLOAD = "<?php system($_GET['c']); ?>"


def show(label, resp):
    snippet = resp.text.strip().replace("\n", " ")[:100]
    print(f"{label:45s} -> HTTP {resp.status_code}   {snippet}")


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    url = f"{base}/upload.php"

    r = requests.get(url, headers={"User-Agent": "poc-clean-baseline/1.0"})
    show("1. clean baseline", r)

    r = requests.get(url, headers={"User-Agent": PAYLOAD})
    show("2. PHP tag in User-Agent header", r)

    r = requests.get(url, headers={"Referer": PAYLOAD})
    show("3. PHP tag in Referer header", r)

    r = requests.get(url, params={"data": PAYLOAD})
    show("4. same tag in a body/query argument", r)

    print(
        "\nExpected: (1) 200, (2)/(3) 403 'PHP2Shell: PHP tag in request "
        "header...' at the WAF (request never reaches the Flask app), "
        "(4) reaches the app (200) -- rule 1000917 only inspects headers; "
        "a body-based PHP tag is CRS 933xxx's job, not this patch's."
    )


if __name__ == "__main__":
    main()
