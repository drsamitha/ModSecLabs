"""
Build the Claude hand-off.

The system deliberately does NOT write rules. It hands Claude the learned
behavioural profile (what normal looks like) plus, optionally, a sample of
requests that fell outside the envelope, and asks Claude to translate the
profile into a *positive-security lockdown*: constrain each endpoint to its
learned envelope, tighten scopes, and set anomaly-score contributions — on top
of the existing OWASP CRS, never replacing it.

If ANTHROPIC_API_KEY + the anthropic SDK are present, ``generate_lockdown``
calls the API; otherwise it returns the prompt to paste into claude.ai.
"""
from __future__ import annotations

import os

_SYSTEM = (
    "You are a senior WAF engineer applying a POSITIVE-SECURITY (allow-list) "
    "lockdown to a WSO2 Identity Server that already sits behind the OWASP CRS. "
    "You write correct, minimal ModSecurity SecLang."
)

_BRIEF = """\
Below is a learned behavioural PROFILE of NORMAL traffic to a WSO2 Identity
Server (endpoints, allowed methods, and for each parameter its learned type,
length p99, enum values and character envelope), plus the session flow model.
It was produced by observing legitimate traffic — it is NOT a list of attacks.

Turn this profile into a POSITIVE-SECURITY lockdown that runs alongside (never
instead of) the OWASP CRS. Produce a single ModSecurity .conf with:

1. PER-ENDPOINT method allow-listing: deny methods not in `allowed_methods`
   for high-confidence endpoints only.
2. PER-PARAMETER envelope enforcement for high-confidence params: flag (add to
   the inbound anomaly score, don't hard-deny) values that break the learned
   type, exceed len_p99 by a safe factor, fall outside an `is_enum` set, or
   exceed the character envelope. Prefer scoring (`setvar:tx.inbound_anomaly_
   score_pl1=+N`) so the CRS threshold makes the final call.
3. SCOPE REDUCTION notes: where the profile shows a parameter is a tight enum
   or fixed type, suggest tightening/relaxing the relevant CRS paranoia or
   anomaly threshold for that path.
4. A "DO NOT LOCK DOWN YET" section listing low-confidence endpoints/params
   (too little baseline data) that need more observation first.

Use local rule ids in 1,000,000-1,999,999. Never lock down a low-confidence
item. Output only the .conf with one-line comments explaining each block.

PROFILE (JSON):
"""


def build_prompt(profile_json: str, anomalies_csv: str = "") -> str:
    out = _BRIEF + "\n```json\n" + profile_json.strip() + "\n```\n"
    if anomalies_csv.strip():
        out += (
            "\nFor reference, a sample of requests that fell OUTSIDE the learned "
            "envelope (use only to sanity-check the lockdown, not as signatures):\n"
            "```csv\n" + anomalies_csv.strip() + "\n```\n"
        )
    return out


def generate_lockdown(profile_json: str, anomalies_csv: str = "",
                      model: str = "claude-opus-4-8") -> dict:
    prompt = build_prompt(profile_json, anomalies_csv)
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"mode": "offline", "prompt": prompt, "rules": None}
    try:
        import anthropic  # type: ignore
    except ImportError:
        return {"mode": "offline", "prompt": prompt, "rules": None}
    client = anthropic.Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=model, max_tokens=4000, system=_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    text = "".join(b.text for b in resp.content if b.type == "text")
    return {"mode": "api", "prompt": prompt, "rules": text}
