"""
Endpoint / parameter profile learning.

For each discovered endpoint template, learn the envelope of *normal* traffic:
which methods appear, which parameters are seen and how often (required vs
optional), and for each parameter its type mix, length distribution and
character profile. Also record **coverage/confidence** — how much data backs
each profile — so downstream lockdown never constrains an endpoint we barely
observed. Under-observed endpoints are reported, not locked.

The profile is the primary artifact: it is what gets serialized to JSON/CSV and
handed to Claude. This module makes *no* rules and passes *no* judgement on
individual requests — that is the anomaly model's job.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .features import char_classes, infer_type, shannon, template_path
from .parser import Request

# Below this many samples an endpoint/param profile is "low confidence".
MIN_SAMPLES = 30


def _pctl(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int(q * (len(sorted_vals) - 1)))
    return sorted_vals[idx]


@dataclass
class ParamProfile:
    name: str
    seen: int = 0
    present_in: int = 0          # requests to the endpoint where this arg appeared
    lengths: list[int] = field(default_factory=list)
    types: Counter = field(default_factory=Counter)
    values: set[str] = field(default_factory=set)  # capped, for enum detection
    entropies: list[float] = field(default_factory=list)
    specials: list[float] = field(default_factory=list)

    # derived
    required_ratio: float = 0.0
    len_min: int = 0
    len_p50: int = 0
    len_p99: int = 0
    dominant_type: str = ""
    is_enum: bool = False
    enum_values: list[str] = field(default_factory=list)
    max_special: float = 0.0
    confidence: str = "low"

    def observe(self, value: str) -> None:
        self.seen += 1
        self.lengths.append(len(value))
        self.types[infer_type(value)] += 1
        self.entropies.append(shannon(value))
        self.specials.append(char_classes(value)["p_special"])
        if len(self.values) < 64:
            self.values.add(value)

    def finalize(self, endpoint_count: int) -> None:
        self.present_in = self.seen
        self.required_ratio = self.seen / endpoint_count if endpoint_count else 0.0
        lens = sorted(self.lengths)
        self.len_min = lens[0] if lens else 0
        self.len_p50 = int(_pctl(lens, 0.50))
        self.len_p99 = int(_pctl(lens, 0.99))
        self.dominant_type = self.types.most_common(1)[0][0] if self.types else ""
        # enum if few distinct values relative to volume and we didn't cap out
        distinct = len(self.values)
        self.is_enum = distinct <= 12 and self.seen >= MIN_SAMPLES and distinct < self.seen * 0.5
        self.enum_values = sorted(self.values) if self.is_enum else []
        self.max_special = max(self.specials) if self.specials else 0.0
        self.confidence = "high" if self.seen >= MIN_SAMPLES else "low"


@dataclass
class EndpointProfile:
    template: str
    count: int = 0
    methods: Counter = field(default_factory=Counter)
    params: dict[str, ParamProfile] = field(default_factory=dict)
    body_sizes: list[int] = field(default_factory=list)
    status_codes: Counter = field(default_factory=Counter)
    confidence: str = "low"

    def observe(self, req: Request) -> None:
        self.count += 1
        self.methods[req.method] += 1
        self.body_sizes.append(req.body_size)
        if req.status:
            self.status_codes[req.status] += 1
        for name, val in req.args.items():
            pp = self.params.get(name)
            if pp is None:
                pp = ParamProfile(name)
                self.params[name] = pp
            pp.observe(val)

    def finalize(self) -> None:
        for pp in self.params.values():
            pp.finalize(self.count)
        self.confidence = "high" if self.count >= MIN_SAMPLES else "low"

    @property
    def allowed_methods(self) -> list[str]:
        return sorted(self.methods)


def learn_profiles(requests: list[Request]) -> dict[str, EndpointProfile]:
    """Build endpoint profiles from a corpus of (normal) requests."""
    buckets: dict[str, EndpointProfile] = {}
    for req in requests:
        tpl = template_path(req.path)
        ep = buckets.get(tpl)
        if ep is None:
            ep = EndpointProfile(tpl)
            buckets[tpl] = ep
        ep.observe(req)
    for ep in buckets.values():
        ep.finalize()
    return buckets


def profile_summary(profiles: dict[str, EndpointProfile]) -> dict:
    high = sum(1 for e in profiles.values() if e.confidence == "high")
    return {
        "endpoints": len(profiles),
        "high_confidence_endpoints": high,
        "low_confidence_endpoints": len(profiles) - high,
        "total_params": sum(len(e.params) for e in profiles.values()),
    }
