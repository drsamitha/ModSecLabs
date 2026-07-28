"""
Turn classified patterns into concrete, copy-pasteable ModSecurity actions.

Two directions:

* **False positives** -> a *scoped* CRS exclusion. We never disable a rule
  globally. We emit exactly the surgical form the ModSecLabs course teaches:
  remove one target (one ARG) from one rule on one URI, via ``ctl:``. This is
  the industry-correct way to tune CRS without opening holes.

* **Likely attacks that slipped through** (detected but not blocked, or only
  weakly scored) -> a suggested hardening custom rule in the reserved
  ``1,000,000+`` ID space, plus advice to raise paranoia / lower threshold.

Also exports the pattern table as CSV, which is the hand-off artifact for the
Claude prompt builder in :mod:`engine.claude_prompt`.
"""
from __future__ import annotations

import csv
import io

from .patterns import Pattern

# Reserved local-rule ID range; we hand out sequential IDs from here.
_LOCAL_ID_BASE = 1_002_000


def _exclusion_rule(p: Pattern, rule_id: int) -> str:
    arg = p.arg_name
    fam = p.location_family or "ARGS"
    target = f"{fam}:{arg}" if arg else fam
    return (
        f"# FP: rule {p.rule_id} fires on {p.location} of {p.path} "
        f"({p.distinct_clients} distinct clients, fp_score={p.fp_score:.2f})\n"
        f"#   {', '.join(p.reasons)}\n"
        f'SecRule REQUEST_URI "@beginsWith {p.path}" \\\n'
        f'    "id:{rule_id},\\\n'
        f"     phase:1,\\\n"
        f"     pass,\\\n"
        f"     nolog,\\\n"
        f"     ctl:ruleRemoveTargetById={p.rule_id};{target}"
        f'"\n'
    )


def _hardening_hint(p: Pattern) -> str:
    return (
        f"# ATTACK not hard-blocked: rule {p.rule_id} on {p.location} of {p.path}\n"
        f"#   {p.blocked_count}/{p.count} requests were 403'd. "
        f"Consider raising PARANOIA or lowering ANOMALY_INBOUND for this path,\n"
        f"#   or add an explicit deny below.\n"
        f'SecRule REQUEST_URI "@beginsWith {p.path}" \\\n'
        f'    "id:__ASSIGN__,phase:2,pass,nolog,chain,'
        f"msg:'Harden {p.path} against {p.rule_id}'\"\n"
        f'    SecRule {p.location or "ARGS"} "@rx <ADD-A-TIGHT-PATTERN-HERE>" '
        f'"t:none,t:urlDecodeUni,t:lowercase,setvar:tx.inbound_anomaly_score_pl1=+5"\n'
    )


def suggest_exclusions(patterns: list[Pattern], max_rules: int = 50) -> str:
    """Generate a ready-to-load ``EXCLUSIONS`` conf for the FP patterns."""
    out = [
        "# ---------------------------------------------------------------------------",
        "# AUTO-GENERATED scoped CRS exclusions (pattern-lab)",
        "# Load BEFORE the CRS rules (e.g. as REQUEST-900-EXCLUSIONS-AUTO.conf).",
        "# Each block removes ONE target from ONE rule on ONE path. Review before use.",
        "# ---------------------------------------------------------------------------",
        "",
    ]
    rid = _LOCAL_ID_BASE
    emitted = 0
    for p in patterns:
        if p.verdict != "likely_false_positive":
            continue
        if not p.arg_name:
            continue  # cannot scope without a concrete target
        out.append(_exclusion_rule(p, rid))
        rid += 1
        emitted += 1
        if emitted >= max_rules:
            break
    if emitted == 0:
        out.append("# (no high-confidence false-positive patterns found)\n")
    return "\n".join(out)


def suggest_hardening(patterns: list[Pattern]) -> str:
    """Advisory custom-rule stubs for attack patterns that weren't blocked."""
    out = [
        "# ---------------------------------------------------------------------------",
        "# AUTO-GENERATED hardening suggestions (pattern-lab)",
        "# These are STUBS for attack-looking traffic that was detected but not",
        "# consistently blocked. Fill in the tight pattern and assign a 1,00x,xxx id.",
        "# ---------------------------------------------------------------------------",
        "",
    ]
    emitted = 0
    for p in patterns:
        # attack-looking but not reliably blocked
        if p.verdict == "likely_attack" and p.blocked_count < p.count:
            out.append(_hardening_hint(p))
            emitted += 1
    if emitted == 0:
        out.append("# (all attack patterns were already blocked — nothing to harden)\n")
    return "\n".join(out)


# CSV columns are the exact feature vector the classifier used, so a human (or
# Claude) can audit every verdict.
CSV_FIELDS = [
    "rule_id",
    "path",
    "location",
    "arg_name",
    "verdict",
    "fp_score",
    "count",
    "distinct_clients",
    "distinct_user_agents",
    "blocked_count",
    "avg_anomaly",
    "methods",
    "severity",
    "tags",
    "message",
    "sample_value",
    "reasons",
]


def _row(p: Pattern) -> dict:
    return {
        "rule_id": p.rule_id,
        "path": p.path,
        "location": p.location,
        "arg_name": p.arg_name,
        "verdict": p.verdict,
        "fp_score": f"{p.fp_score:.3f}",
        "count": p.count,
        "distinct_clients": p.distinct_clients,
        "distinct_user_agents": len(p.user_agents),
        "blocked_count": p.blocked_count,
        "avg_anomaly": f"{p.avg_anomaly:.1f}",
        "methods": "|".join(sorted(p.methods)),
        "severity": p.severity,
        "tags": "|".join(p.tags),
        "message": p.message,
        "sample_value": (p.sample_values[0] if p.sample_values else "")[:200],
        "reasons": "; ".join(p.reasons),
    }


def to_csv(patterns: list[Pattern]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for p in patterns:
        writer.writerow(_row(p))
    return buf.getvalue()


def write_csv(patterns: list[Pattern], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        fh.write(to_csv(patterns))
