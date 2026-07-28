"""
Pattern extraction + classification.

This is the core "algorithm" the task asks for. It does what a WAF operator
does by hand when tuning an app behind the Core Rule Set, but automatically and
at scale:

1. **Aggregate** every rule hit into a *pattern* keyed by
   ``(rule_id, path, matched_location)`` — i.e. "rule 942100 keeps firing on
   ARGS:redirect_uri of /oauth2/authorize". That triple is the unit a real
   exclusion is written against, so it is the right unit to reason about.

2. **Measure** each pattern: how often it fires, how many *distinct clients*
   trip it, the value diversity CRS matched on, the anomaly it contributes,
   and how "attacky" the matched payload looks.

3. **Classify** each pattern on a continuous ``fp_score`` (0 = almost
   certainly a real attack, 1 = almost certainly a false positive) using a
   transparent, weighted heuristic — no black box, every input is inspectable
   in the dashboard and the CSV.

The intuition (well established in WAF tuning practice):

* A **false positive** is *broad and boring*: many different legitimate users
  trip the same rule on the same app parameter, with low anomaly, and the
  matched data looks like normal application data (a redirect URL, a base64
  token, a JWT).
* A **real attack** is *narrow and nasty*: a handful of source IPs, high
  anomaly, classic payload shapes (``<script>``, ``UNION SELECT``, ``../``,
  ``${jndi:``), often sprayed across many endpoints (scanning).
"""
from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field

from .parser import Event

# Payload shapes that strongly indicate a genuine attack rather than an app
# parameter that merely looks suspicious to a signature.
_ATTACK_SIGNATURES = [
    re.compile(r"<script", re.I),
    re.compile(r"javascript:", re.I),
    re.compile(r"on\w+\s*=", re.I),
    re.compile(r"union\s+select", re.I),
    re.compile(r"\bor\b\s+1\s*=\s*1", re.I),
    re.compile(r"' *(or|and) *'", re.I),
    re.compile(r"\.\./", re.I),
    re.compile(r"%2e%2e%2f", re.I),
    re.compile(r"\$\{jndi:", re.I),
    re.compile(r"/etc/passwd", re.I),
    re.compile(r"\b(sleep|benchmark|waitfor)\s*\(", re.I),
    re.compile(r"<\?php", re.I),
]

# Rule locations that, for an OIDC/SAML identity provider, are structurally
# expected to carry data that trips signatures (URLs, base64, JWTs). Hits here
# are FP-leaning unless the payload itself is clearly an attack.
_KNOWN_BENIGN_LOCATIONS = {
    "redirect_uri",
    "samlrequest",
    "samlresponse",
    "state",
    "code",
    "request",  # OIDC request object (a JWT)
    "id_token_hint",
    "session_data_key",
    "sessiondatakey",
    "commonauthcallerpath",
    "sp",
    "relaystate",
}


def _looks_like_attack(sample_values: list[str]) -> float:
    """Fraction of sampled matched-values that carry an attack signature."""
    if not sample_values:
        return 0.0
    hits = sum(
        1 for v in sample_values if any(rx.search(v) for rx in _ATTACK_SIGNATURES)
    )
    return hits / len(sample_values)


def _shannon_entropy(values: list[str]) -> float:
    """Normalised diversity of the *distinct* matched values (0..1).

    High diversity (many different tokens) is a false-positive signal for
    high-cardinality app params like ``state``/``code``; a single repeated
    exploit string is low diversity.
    """
    if not values:
        return 0.0
    n = len(values)
    if n == 1:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for v in values:
        counts[v] += 1
    total = sum(counts.values())
    ent = -sum((c / total) * math.log2(c / total) for c in counts.values())
    return ent / math.log2(n)  # normalise by max possible entropy


@dataclass
class Pattern:
    rule_id: str
    path: str
    location: str  # e.g. "ARGS:redirect_uri"

    count: int = 0
    client_ips: set[str] = field(default_factory=set)
    user_agents: set[str] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    paths_seen: set[str] = field(default_factory=set)  # for scan-breadth per IP
    sample_values: list[str] = field(default_factory=list)
    anomaly_scores: list[int] = field(default_factory=list)
    message: str = ""
    tags: list[str] = field(default_factory=list)
    severity: str = ""
    blocked_count: int = 0

    # --- derived metrics (filled by finalize) ---
    fp_score: float = 0.0
    verdict: str = ""  # "likely_false_positive" | "likely_attack" | "review"
    reasons: list[str] = field(default_factory=list)

    @property
    def arg_name(self) -> str:
        return self.location.split(":", 1)[1] if ":" in self.location else ""

    @property
    def location_family(self) -> str:
        return self.location.split(":", 1)[0] if self.location else ""

    @property
    def distinct_clients(self) -> int:
        return len(self.client_ips)

    @property
    def avg_anomaly(self) -> float:
        return sum(self.anomaly_scores) / len(self.anomaly_scores) if self.anomaly_scores else 0.0

    def finalize(self, total_events: int) -> None:
        attack_frac = _looks_like_attack(self.sample_values)
        entropy = _shannon_entropy(self.sample_values)
        clients = self.distinct_clients
        benign_loc = self.arg_name.lower() in _KNOWN_BENIGN_LOCATIONS

        # Weighted evidence toward "false positive" (each term in 0..1).
        score = 0.0
        reasons: list[str] = []

        # 1. Breadth of legitimate clients — the single strongest FP signal.
        if clients >= 10:
            score += 0.35
            reasons.append(f"{clients} distinct clients trip this (broad)")
        elif clients >= 4:
            score += 0.18
            reasons.append(f"{clients} distinct clients")

        # 2. Value diversity — many different benign tokens.
        if entropy >= 0.6:
            score += 0.20
            reasons.append("high value diversity (looks like unique tokens)")

        # 3. Location is a structurally-benign IdP parameter.
        if benign_loc:
            score += 0.20
            reasons.append(f"'{self.arg_name}' is an expected IdP parameter")

        # 4. Low average anomaly contribution.
        if self.avg_anomaly and self.avg_anomaly < 5:
            score += 0.10
            reasons.append(f"low avg anomaly ({self.avg_anomaly:.0f})")

        # 5. Payload does NOT look like an attack.
        if attack_frac == 0:
            score += 0.15
            reasons.append("no attack signatures in matched data")

        # Evidence toward "attack" — these push fp_score back down.
        if attack_frac > 0:
            penalty = 0.5 + 0.5 * attack_frac
            score -= penalty
            reasons.append(
                f"{attack_frac*100:.0f}% of samples carry attack signatures"
            )
        if clients <= 2 and self.count >= 3:
            score -= 0.15
            reasons.append("concentrated in very few source IPs")
        if self.avg_anomaly >= 15:
            score -= 0.15
            reasons.append(f"high avg anomaly ({self.avg_anomaly:.0f})")

        self.fp_score = max(0.0, min(1.0, score))
        self.reasons = reasons

        if attack_frac > 0 or self.fp_score < 0.35:
            self.verdict = "likely_attack"
        elif self.fp_score >= 0.6:
            self.verdict = "likely_false_positive"
        else:
            self.verdict = "review"


# Meta / evaluation rules you never write a target-exclusion against: the
# anomaly-scoring correlation rules (949xxx) and the reporting rules (980xxx).
# They fire on every blocked request, so they are noise for tuning purposes.
_META_RULE_PREFIXES = ("949", "980")


def _is_tunable(rule_id: str) -> bool:
    return not rule_id.startswith(_META_RULE_PREFIXES)


def extract_patterns(events: list[Event]) -> list[Pattern]:
    """Aggregate events into finalized, sorted patterns."""
    buckets: dict[tuple[str, str, str], Pattern] = {}
    # Track, per client IP, how many distinct paths it touched (scan breadth).
    ip_paths: dict[str, set[str]] = defaultdict(set)

    for ev in events:
        ip_paths[ev.client_ip].add(ev.path)
        for hit in ev.hits:
            if not _is_tunable(hit.rule_id):
                continue
            key = (hit.rule_id, ev.path, hit.matched_location)
            p = buckets.get(key)
            if p is None:
                p = Pattern(
                    rule_id=hit.rule_id,
                    path=ev.path,
                    location=hit.matched_location,
                    message=hit.message,
                    tags=hit.tags,
                    severity=hit.severity,
                )
                buckets[key] = p
            p.count += 1
            if ev.client_ip:
                p.client_ips.add(ev.client_ip)
            if ev.user_agent:
                p.user_agents.add(ev.user_agent)
            p.methods.add(ev.method)
            p.paths_seen.add(ev.path)
            if hit.matched_data:
                if len(p.sample_values) < 200:
                    p.sample_values.append(hit.matched_data)
            if ev.anomaly_score:
                p.anomaly_scores.append(ev.anomaly_score)
            if ev.blocked:
                p.blocked_count += 1

    patterns = list(buckets.values())
    for p in patterns:
        p.finalize(len(events))

    # Sort: most impactful first (highest volume, then FP-confidence).
    patterns.sort(key=lambda p: (p.count, p.fp_score), reverse=True)
    return patterns


@dataclass
class ScanProfile:
    """A source IP that touched an unusually broad set of endpoints."""

    client_ip: str
    distinct_paths: int
    hit_count: int


def scanner_ips(events: list[Event], min_paths: int = 8) -> list[ScanProfile]:
    ip_paths: dict[str, set[str]] = defaultdict(set)
    ip_hits: dict[str, int] = defaultdict(int)
    for ev in events:
        if not ev.client_ip:
            continue
        ip_paths[ev.client_ip].add(ev.path)
        ip_hits[ev.client_ip] += len(ev.hits)
    out = [
        ScanProfile(ip, len(paths), ip_hits[ip])
        for ip, paths in ip_paths.items()
        if len(paths) >= min_paths
    ]
    out.sort(key=lambda s: s.distinct_paths, reverse=True)
    return out


def summarize(events: list[Event], patterns: list[Pattern]) -> dict:
    total_hits = sum(len(e.hits) for e in events)
    blocked = sum(1 for e in events if e.blocked)
    return {
        "events": len(events),
        "blocked": blocked,
        "rule_hits": total_hits,
        "patterns": len(patterns),
        "likely_false_positive": sum(1 for p in patterns if p.verdict == "likely_false_positive"),
        "likely_attack": sum(1 for p in patterns if p.verdict == "likely_attack"),
        "review": sum(1 for p in patterns if p.verdict == "review"),
        "distinct_clients": len({e.client_ip for e in events if e.client_ip}),
    }
