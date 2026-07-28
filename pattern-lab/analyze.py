#!/usr/bin/env python3
"""
pattern-lab CLI — analyze a ModSecurity audit log end to end.

    python analyze.py sample-data/sample_audit.jsonl --out out/

Produces in --out:
    patterns.csv                  the classified pattern table (feed to Claude)
    EXCLUSIONS-AUTO.conf          scoped CRS exclusions for false positives
    HARDENING-AUTO.conf           stubs for attacks not fully blocked
    claude_prompt.txt             ready-to-paste prompt (or API result)
And prints a summary + top patterns to the terminal.
"""
from __future__ import annotations

import argparse
import os
import sys

from engine import (
    build_prompt,
    extract_patterns,
    generate_rules,
    parse_file,
    scanner_ips,
    suggest_exclusions,
    suggest_hardening,
    summarize,
    to_csv,
)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ModSecurity traffic pattern analyzer")
    ap.add_argument("logfile", help="ModSecurity JSON audit log (one object per line)")
    ap.add_argument("--out", default="out", help="output directory (default: out/)")
    ap.add_argument("--claude", action="store_true",
                    help="call the Claude API (needs ANTHROPIC_API_KEY) to draft rules")
    ap.add_argument("--top", type=int, default=15, help="how many patterns to print")
    args = ap.parse_args(argv)

    events, skipped = parse_file(args.logfile)
    if not events:
        print(f"No parseable events in {args.logfile} (skipped {skipped} lines).",
              file=sys.stderr)
        return 1

    patterns = extract_patterns(events)
    summ = summarize(events, patterns)
    scanners = scanner_ips(events)

    os.makedirs(args.out, exist_ok=True)
    csv_text = to_csv(patterns)
    _write(os.path.join(args.out, "patterns.csv"), csv_text)
    _write(os.path.join(args.out, "EXCLUSIONS-AUTO.conf"), suggest_exclusions(patterns))
    _write(os.path.join(args.out, "HARDENING-AUTO.conf"), suggest_hardening(patterns))

    if args.claude:
        result = generate_rules(csv_text)
        if result["mode"] == "api":
            _write(os.path.join(args.out, "claude_rules.conf"), result["rules"])
            print("Claude API drafted rules -> claude_rules.conf")
        else:
            _write(os.path.join(args.out, "claude_prompt.txt"), result["prompt"])
            print("No API key/SDK — wrote prompt to claude_prompt.txt (paste into claude.ai)")
    else:
        _write(os.path.join(args.out, "claude_prompt.txt"), build_prompt(csv_text))

    # ---- terminal report ----
    print("\n=== traffic pattern summary ===")
    for k, v in summ.items():
        print(f"  {k:>24}: {v}")
    if skipped:
        print(f"  {'unparseable lines':>24}: {skipped}")

    print(f"\n=== top {args.top} patterns ===")
    hdr = f"{'verdict':<22} {'fp':>4} {'cnt':>5} {'IPs':>4}  rule    location"
    print(hdr)
    print("-" * len(hdr))
    for p in patterns[: args.top]:
        print(f"{p.verdict:<22} {p.fp_score:>4.2f} {p.count:>5} "
              f"{p.distinct_clients:>4}  {p.rule_id:<7} {p.path} {p.location}")

    if scanners:
        print("\n=== scanner-like source IPs (broad endpoint sweep) ===")
        for s in scanners[:10]:
            print(f"  {s.client_ip:<18} {s.distinct_paths} distinct paths, {s.hit_count} hits")

    print(f"\nWrote CSV + generated confs to {args.out}/")
    return 0


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


if __name__ == "__main__":
    raise SystemExit(main())
