"""
Build a Claude prompt from the pattern CSV.

The task explicitly wants: "csv output that get from that pattern detection and
the calculations, to input to Claude and generate custom rules for them." This
module produces that prompt. It embeds the CSV verbatim (Claude reads CSV well)
and gives Claude a tight brief: keep IDs in the reserved local range, scope
exclusions to one target, and only propose deny rules for genuine attacks.

If an ANTHROPIC_API_KEY is present and the `anthropic` SDK is installed,
``generate_rules()`` will actually call the API. Otherwise it returns the
prompt text so you can paste it into claude.ai — the offline path always works.
"""
from __future__ import annotations

import os

_SYSTEM = (
    "You are a senior WAF engineer tuning the OWASP Core Rule Set (CRS) for a "
    "WSO2 Identity Server deployment behind ModSecurity. You write correct, "
    "minimal SecLang."
)

_BRIEF = """\
Below is a CSV of traffic *patterns* extracted from ModSecurity audit logs.
Each row is one (rule_id, path, location) that fired repeatedly, already
classified as likely_false_positive, likely_attack, or review, with the
evidence in `reasons` and `fp_score` (1.0 = almost certainly a false positive).

Produce a single ModSecurity .conf with three clearly commented sections:

1. SCOPED EXCLUSIONS for the likely_false_positive rows. Use the surgical form
   `ctl:ruleRemoveTargetById=<rule_id>;<location>` gated by
   `SecRule REQUEST_URI "@beginsWith <path>"`. NEVER disable a rule globally.
   Use ids starting at 1003000, phase:1, pass, nolog.

2. CUSTOM DENY / SCORING rules for the likely_attack rows that are NOT already
   fully blocked (blocked_count < count). Keep them tight (anchor the regex to
   the real payload shape), ids starting at 1004000.

3. A short "REVIEW THESE BY HAND" comment block listing the `review` rows and
   why they're ambiguous.

Do not invent rule ids outside 1,000,000-1,999,999. Explain each block in one
comment line. Output only the .conf.

CSV:
"""


def build_prompt(csv_text: str) -> str:
    return _BRIEF + "\n```csv\n" + csv_text.strip() + "\n```\n"


def generate_rules(csv_text: str, model: str = "claude-opus-4-8") -> dict:
    """Return {"mode": "api"|"offline", "prompt": str, "rules": str|None}."""
    prompt = build_prompt(csv_text)
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"mode": "offline", "prompt": prompt, "rules": None}
    try:
        import anthropic  # type: ignore
    except ImportError:
        return {"mode": "offline", "prompt": prompt, "rules": None}

    client = anthropic.Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=model,
        max_tokens=4000,
        system=_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    text = "".join(block.text for block in resp.content if block.type == "text")
    return {"mode": "api", "prompt": prompt, "rules": text}
