#!/usr/bin/env python3
"""
pattern-lab CLI — behavioural baselining for positive-security WAF lockdown.

    # learn normal from a baseline log, then score a fresh log against it
    python analyze.py --baseline sample-data/baseline.jsonl \
                      --score    sample-data/mixed.jsonl --out out/

Produces in --out:
    profile.json        the learned behavioural baseline (endpoints, params, flow)
    profile.csv         flat per-(endpoint,param) envelope table
    anomalies.csv       requests in --score that fell outside the envelope
    claude_prompt.txt   ready-to-paste prompt: profile -> lockdown rules
                        (or claude_lockdown.conf if --claude and an API key)
And prints a report. The engine LEARNS and SCORES; it does not write rules.
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import sys

from engine import (
    BaselineModel,
    AutoencoderModel,
    EnvelopeChecker,
    build_matrix,
    build_prompt,
    evaluate,
    generate_lockdown,
    learn_profiles,
    parse_file,
    profile_summary,
    reconstruct_sessions,
    to_csv,
    to_json,
)
from engine.sessions import SequenceModel


def _anomaly_csv(verdicts) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["endpoint", "method", "ml_score", "ml_anomalous",
                "session_surprisal", "session_anomalous",
                "violations", "label", "uri"])
    for v in verdicts:
        if not v.outside_envelope:
            continue
        w.writerow([
            v.endpoint, v.request.method, f"{v.ml_score:.2f}", v.ml_anomalous,
            f"{v.session_surprisal:.2f}", v.session_anomalous,
            "; ".join(f"{x.kind}:{x.detail}" for x in v.violations),
            v.request.label, v.request.raw_uri[:160],
        ])
    return buf.getvalue()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Behavioural WAF baselining")
    ap.add_argument("--baseline", required=True, help="request log of NORMAL traffic to learn from")
    ap.add_argument("--score", help="request log to score against the baseline (default: reuse baseline)")
    ap.add_argument("--out", default="out")
    ap.add_argument("--autoencoder", action="store_true", help="use the torch autoencoder tier if available")
    ap.add_argument("--claude", action="store_true", help="call Claude to draft the lockdown (needs ANTHROPIC_API_KEY)")
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args(argv)

    base, skb = parse_file(args.baseline)
    if not base:
        print(f"No parseable requests in {args.baseline}", file=sys.stderr)
        return 1

    # ---- LEARN ----
    profiles = learn_profiles(base)
    seq = SequenceModel().fit(reconstruct_sessions(base))
    Model = AutoencoderModel if args.autoencoder else BaselineModel
    model = Model().fit(build_matrix(base))
    checker = EnvelopeChecker(profiles)

    # ---- SCORE ----
    score_reqs, sks = parse_file(args.score) if args.score else (base, 0)
    verdicts = evaluate(score_reqs, model, checker, seq=seq)

    os.makedirs(args.out, exist_ok=True)
    profile_json = to_json(profiles, seq)
    _w(os.path.join(args.out, "profile.json"), profile_json)
    _w(os.path.join(args.out, "profile.csv"), to_csv(profiles))
    anom_csv = _anomaly_csv(verdicts)
    _w(os.path.join(args.out, "anomalies.csv"), anom_csv)

    if args.claude:
        res = generate_lockdown(profile_json, anom_csv)
        if res["mode"] == "api":
            _w(os.path.join(args.out, "claude_lockdown.conf"), res["rules"])
            print("Claude drafted lockdown -> claude_lockdown.conf")
        else:
            _w(os.path.join(args.out, "claude_prompt.txt"), res["prompt"])
            print("No API key/SDK — wrote claude_prompt.txt (paste into claude.ai)")
    else:
        _w(os.path.join(args.out, "claude_prompt.txt"), build_prompt(profile_json, anom_csv))

    _report(profiles, model, verdicts, seq, args, skb + sks)
    print(f"\nWrote profile + anomalies to {args.out}/")
    return 0


def _report(profiles, model, verdicts, seq, args, skipped):
    summ = profile_summary(profiles)
    print("\n=== learned baseline ===")
    for k, v in summ.items():
        print(f"  {k:>28}: {v}")
    print(f"  {'ml block threshold (p99)':>28}: {model.threshold_:.2f}")
    print(f"  {'model':>28}: {type(model).__name__}")
    if skipped:
        print(f"  {'unparseable lines':>28}: {skipped}")

    outside = [v for v in verdicts if v.outside_envelope]
    print(f"\n=== scoring {len(verdicts)} requests ===")
    print(f"  outside envelope: {len(outside)}  "
          f"(ml={sum(v.ml_anomalous for v in verdicts)}, "
          f"envelope={sum(1 for v in verdicts if v.violations)}, "
          f"session={sum(v.session_anomalous for v in verdicts)})")
    labelled = [v for v in verdicts if v.request.label]
    if labelled:
        ab = [v for v in labelled if v.request.label == "abnormal"]
        caught = sum(1 for v in ab if v.outside_envelope)
        norm = [v for v in labelled if v.request.label == "normal"]
        fp = sum(1 for v in norm if v.outside_envelope)
        print(f"  labelled eval: caught {caught}/{len(ab)} abnormal, "
              f"{fp}/{len(norm)} normal false-flagged")

    print(f"\n=== top {args.top} anomalous requests ===")
    outside.sort(key=lambda v: (len(v.violations), v.ml_score), reverse=True)
    for v in outside[: args.top]:
        why = "; ".join(f"{x.kind}" for x in v.violations)
        if v.session_anomalous:
            why = (why + "; " if why else "") + f"session(surprisal={v.session_surprisal:.1f})"
        why = why or "ml-only"
        print(f"  [{v.request.label or '?':>8}] {v.endpoint:<28} ml={v.ml_score:5.2f} {why}")

    print("\n=== normal session flow (top transitions) ===")
    for a, b, p, c in seq.top_transitions(8):
        print(f"  {a:>22} -> {b:<26} p={p:.2f} ({c})")


def _w(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


if __name__ == "__main__":
    raise SystemExit(main())
