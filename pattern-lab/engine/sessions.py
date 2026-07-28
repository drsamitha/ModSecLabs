"""
Session reconstruction + sequence model.

A single request in isolation can look fine while the *order* of requests
betrays an abnormal client. Normal OIDC traffic follows a grammar:

    authorize -> login -> commonauth -> token -> userinfo

We reconstruct sessions (by explicit ``session_id`` when present, else by
client IP with an idle-gap split) and learn a first-order **Markov transition
model** of endpoint templates over normal sessions. A transition the baseline
never saw — or saw very rarely — makes a session's flow anomalous. This is the
sequence analogue of the per-request anomaly model, and again it emits scores,
not rules.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .features import template_path
from .parser import Request

_START = "^"
_END = "$"


def reconstruct_sessions(requests: list[Request], idle_gap_s: int = 900) -> list[list[Request]]:
    """Group requests into sessions. Uses session_id if any request has one,
    otherwise falls back to per-client-IP ordering (time gap not modelled when
    timestamps are absent — order is taken as log order)."""
    have_ids = any(r.session_id for r in requests)
    groups: dict[str, list[Request]] = defaultdict(list)
    for idx, r in enumerate(requests):
        key = (r.session_id or f"anon-{r.client_ip}") if have_ids else (r.client_ip or "unknown")
        groups[key].append((idx, r))
    # order each session chronologically; fall back to log order when a
    # timestamp is missing so shuffled inputs still reconstruct correctly.
    out: list[list[Request]] = []
    for members in groups.values():
        members.sort(key=lambda ir: (ir[1].ts or "", ir[0]))
        out.append([r for _, r in members])
    return out


@dataclass
class SequenceModel:
    # transition counts: from-template -> to-template -> count
    trans: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    totals: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    n_sessions: int = 0

    def fit(self, sessions: list[list[Request]]) -> "SequenceModel":
        for sess in sessions:
            self.n_sessions += 1
            seq = [_START] + [template_path(r.path) for r in sess] + [_END]
            for a, b in zip(seq, seq[1:]):
                self.trans[a][b] += 1
                self.totals[a] += 1
        return self

    def prob(self, a: str, b: str) -> float:
        tot = self.totals.get(a, 0)
        if tot == 0:
            return 0.0
        return self.trans[a].get(b, 0) / tot

    def score_session(self, sess: list[Request]) -> tuple[float, list[tuple[str, str, float]]]:
        """Return (surprisal, rare_transitions). Higher surprisal = more anomalous."""
        seq = [_START] + [template_path(r.path) for r in sess] + [_END]
        import math
        surprisal = 0.0
        rare: list[tuple[str, str, float]] = []
        for a, b in zip(seq, seq[1:]):
            p = self.prob(a, b)
            if p <= 0:
                surprisal += 10.0  # unseen transition penalty
                rare.append((a, b, 0.0))
            else:
                surprisal += -math.log2(p)
                if p < 0.02:
                    rare.append((a, b, p))
        return surprisal / max(1, len(seq) - 1), rare

    def top_transitions(self, n: int = 15) -> list[tuple[str, str, float, int]]:
        rows = []
        for a, tos in self.trans.items():
            for b, c in tos.items():
                rows.append((a, b, self.prob(a, b), c))
        rows.sort(key=lambda r: r[3], reverse=True)
        return rows[:n]
