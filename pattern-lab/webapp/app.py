"""
pattern-lab dashboard.

A small Flask app that runs the engine over an audit log and renders the
results: KPI tiles, a verdict breakdown, a top-patterns bar chart, the scanner
list, the classified pattern table, and download links for the CSV + generated
.conf files. Charts are drawn with inline SVG (no external JS/CDN) so the whole
thing works air-gapped.

    LOGFILE=../sample-data/sample_audit.jsonl python app.py
    # then open http://localhost:8050
"""
from __future__ import annotations

import os
import sys

from flask import Flask, Response, render_template, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import (  # noqa: E402
    build_prompt,
    extract_patterns,
    parse_file,
    scanner_ips,
    suggest_exclusions,
    suggest_hardening,
    summarize,
    to_csv,
)

app = Flask(__name__)

DEFAULT_LOG = os.environ.get(
    "LOGFILE",
    os.path.join(os.path.dirname(__file__), "..", "sample-data", "sample_audit.jsonl"),
)


def _analyze(path: str):
    events, skipped = parse_file(path)
    patterns = extract_patterns(events)
    return {
        "events": events,
        "skipped": skipped,
        "patterns": patterns,
        "summary": summarize(events, patterns),
        "scanners": scanner_ips(events),
    }


def _bars(patterns, n=10):
    """(label, count, verdict) for the top-N bar chart."""
    top = patterns[:n]
    mx = max((p.count for p in top), default=1)
    return [
        {
            "label": f"{p.rule_id} {p.arg_name or p.path}",
            "count": p.count,
            "pct": round(100 * p.count / mx, 1),
            "verdict": p.verdict,
        }
        for p in top
    ]


@app.route("/")
def index():
    path = request.args.get("log", DEFAULT_LOG)
    if not os.path.exists(path):
        return f"Log file not found: {path}", 404
    data = _analyze(path)
    return render_template(
        "dashboard.html",
        log=path,
        summary=data["summary"],
        skipped=data["skipped"],
        patterns=data["patterns"],
        scanners=data["scanners"][:10],
        bars=_bars(data["patterns"]),
    )


@app.route("/download/<kind>")
def download(kind: str):
    path = request.args.get("log", DEFAULT_LOG)
    data = _analyze(path)
    patterns = data["patterns"]
    if kind == "csv":
        return Response(to_csv(patterns), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=patterns.csv"})
    if kind == "exclusions":
        return Response(suggest_exclusions(patterns), mimetype="text/plain")
    if kind == "hardening":
        return Response(suggest_hardening(patterns), mimetype="text/plain")
    if kind == "prompt":
        return Response(build_prompt(to_csv(patterns)), mimetype="text/plain")
    return "unknown artifact", 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8050)))
