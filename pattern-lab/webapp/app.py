"""
pattern-lab dashboard — behavioural baseline + anomaly view.

Learns a profile from a baseline request log, scores a second log against it,
and renders: KPI tiles, the learned endpoint/parameter envelopes, the normal
session-flow transitions, the anomaly-score distribution with its threshold,
and the feed of requests that fell outside the envelope. Downloads expose the
profile JSON/CSV, the anomalies CSV, and the Claude lockdown prompt.

    BASELINE=../sample-data/baseline.jsonl SCORE=../sample-data/mixed.jsonl python app.py
    # → http://localhost:8050

Charts are inline SVG / CSS — no external JS, works air-gapped.
"""
from __future__ import annotations

import os
import sys

from flask import Flask, Response, render_template, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import (  # noqa: E402
    BaselineModel,
    EnvelopeChecker,
    build_matrix,
    build_prompt,
    evaluate,
    learn_profiles,
    parse_file,
    profile_summary,
    reconstruct_sessions,
    to_csv,
    to_json,
)
from engine.sessions import SequenceModel  # noqa: E402

app = Flask(__name__)
_D = os.path.dirname(__file__)
BASELINE = os.environ.get("BASELINE", os.path.join(_D, "..", "sample-data", "baseline.jsonl"))
SCORE = os.environ.get("SCORE", os.path.join(_D, "..", "sample-data", "mixed.jsonl"))


def _analyze(baseline_path, score_path):
    base, _ = parse_file(baseline_path)
    profiles = learn_profiles(base)
    seq = SequenceModel().fit(reconstruct_sessions(base))
    model = BaselineModel().fit(build_matrix(base))
    checker = EnvelopeChecker(profiles)
    score_reqs, _ = parse_file(score_path) if os.path.exists(score_path) else (base, 0)
    verdicts = evaluate(score_reqs, model, checker, seq=seq)
    return profiles, seq, model, verdicts


def _histogram(scores, threshold, bins=24):
    if not scores:
        return []
    lo, hi = min(scores), max(scores)
    hi = max(hi, threshold * 1.2, lo + 1e-6)
    width = (hi - lo) / bins
    counts = [0] * bins
    for s in scores:
        b = min(bins - 1, int((s - lo) / width))
        counts[b] += 1
    mx = max(counts) or 1
    thr_bin = min(bins - 1, int((threshold - lo) / width))
    return [
        {"h": round(100 * c / mx, 1), "over": i >= thr_bin, "x0": round(lo + i * width, 2)}
        for i, c in enumerate(counts)
    ]


@app.route("/")
def index():
    baseline = request.args.get("baseline", BASELINE)
    score = request.args.get("score", SCORE)
    if not os.path.exists(baseline):
        return f"Baseline log not found: {baseline}", 404
    profiles, seq, model, verdicts = _analyze(baseline, score)

    outside = [v for v in verdicts if v.outside_envelope]
    outside.sort(key=lambda v: (len(v.violations) + v.session_anomalous, v.ml_score), reverse=True)
    labelled = [v for v in verdicts if v.request.label]
    ab = [v for v in labelled if v.request.label == "abnormal"]
    norm = [v for v in labelled if v.request.label == "normal"]

    summ = profile_summary(profiles)
    summ.update({
        "sessions": seq.n_sessions,
        "scored": len(verdicts),
        "outside": len(outside),
        "caught": sum(1 for v in ab if v.outside_envelope) if ab else None,
        "abnormal_total": len(ab) if ab else None,
        "false_flags": sum(1 for v in norm if v.outside_envelope) if norm else None,
        "normal_total": len(norm) if norm else None,
    })

    endpoints = sorted(profiles.values(), key=lambda e: e.count, reverse=True)
    return render_template(
        "dashboard.html",
        baseline=baseline, score=score, summary=summ,
        endpoints=endpoints,
        transitions=seq.top_transitions(14),
        hist=_histogram([v.ml_score for v in verdicts], model.threshold_),
        threshold=round(model.threshold_, 2),
        anomalies=outside[:40],
    )


@app.route("/download/<kind>")
def download(kind):
    baseline = request.args.get("baseline", BASELINE)
    score = request.args.get("score", SCORE)
    profiles, seq, model, verdicts = _analyze(baseline, score)
    if kind == "profile-json":
        return Response(to_json(profiles, seq), mimetype="application/json")
    if kind == "profile-csv":
        return Response(to_csv(profiles), mimetype="text/csv")
    if kind == "prompt":
        return Response(build_prompt(to_json(profiles, seq)), mimetype="text/plain")
    return "unknown artifact", 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8050)))
