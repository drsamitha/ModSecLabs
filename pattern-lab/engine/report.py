"""
Serialize the learned profile to the hand-off artifacts.

* ``profile.json`` — the full behavioural profile: per-endpoint methods,
  per-parameter envelopes (type/length/enum/charset), confidence, and the
  session transition model. This is the machine-readable baseline.
* ``profile.csv`` — one row per (endpoint, parameter) with the learned
  envelope, flat enough to paste into a spreadsheet or a Claude prompt.

Neither contains rules. They describe *normal*.
"""
from __future__ import annotations

import csv
import io
import json

from .profile import EndpointProfile
from .sessions import SequenceModel

CSV_FIELDS = [
    "endpoint", "endpoint_count", "endpoint_confidence", "allowed_methods",
    "param", "param_count", "required_ratio", "dominant_type",
    "len_min", "len_p50", "len_p99", "max_special", "is_enum", "enum_values",
    "param_confidence",
]


def profile_rows(profiles: dict[str, EndpointProfile]) -> list[dict]:
    rows: list[dict] = []
    for ep in sorted(profiles.values(), key=lambda e: e.count, reverse=True):
        methods = "|".join(ep.allowed_methods)
        if not ep.params:
            rows.append({
                "endpoint": ep.template, "endpoint_count": ep.count,
                "endpoint_confidence": ep.confidence, "allowed_methods": methods,
                "param": "", "param_count": "", "required_ratio": "",
                "dominant_type": "", "len_min": "", "len_p50": "", "len_p99": "",
                "max_special": "", "is_enum": "", "enum_values": "",
                "param_confidence": "",
            })
            continue
        for pp in sorted(ep.params.values(), key=lambda p: p.seen, reverse=True):
            rows.append({
                "endpoint": ep.template,
                "endpoint_count": ep.count,
                "endpoint_confidence": ep.confidence,
                "allowed_methods": methods,
                "param": pp.name,
                "param_count": pp.seen,
                "required_ratio": f"{pp.required_ratio:.2f}",
                "dominant_type": pp.dominant_type,
                "len_min": pp.len_min,
                "len_p50": pp.len_p50,
                "len_p99": pp.len_p99,
                "max_special": f"{pp.max_special:.2f}",
                "is_enum": pp.is_enum,
                "enum_values": "|".join(pp.enum_values),
                "param_confidence": pp.confidence,
            })
    return rows


def to_csv(profiles: dict[str, EndpointProfile]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS)
    w.writeheader()
    for row in profile_rows(profiles):
        w.writerow(row)
    return buf.getvalue()


def to_json(profiles: dict[str, EndpointProfile], seq: SequenceModel | None = None) -> str:
    obj: dict = {"endpoints": {}}
    for ep in profiles.values():
        obj["endpoints"][ep.template] = {
            "count": ep.count,
            "confidence": ep.confidence,
            "allowed_methods": ep.allowed_methods,
            "status_codes": dict(ep.status_codes),
            "params": {
                pp.name: {
                    "count": pp.seen,
                    "required_ratio": round(pp.required_ratio, 3),
                    "dominant_type": pp.dominant_type,
                    "len": {"min": pp.len_min, "p50": pp.len_p50, "p99": pp.len_p99},
                    "max_special": round(pp.max_special, 3),
                    "is_enum": pp.is_enum,
                    "enum_values": pp.enum_values,
                    "confidence": pp.confidence,
                }
                for pp in ep.params.values()
            },
        }
    if seq is not None:
        obj["sessions"] = {
            "n_sessions": seq.n_sessions,
            "top_transitions": [
                {"from": a, "to": b, "prob": round(p, 3), "count": c}
                for a, b, p, c in seq.top_transitions(30)
            ],
        }
    return json.dumps(obj, indent=2)


def write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
