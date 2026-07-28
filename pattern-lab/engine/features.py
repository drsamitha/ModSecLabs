"""
Feature engineering.

Two jobs:

1. Turn a raw path into an **endpoint template** by collapsing high-cardinality
   segments (IDs, UUIDs) into ``{var}``. This is lightweight grammar discovery —
   ``/scim2/Users/9f8c...`` and ``/scim2/Users/1a2b...`` become the single
   endpoint ``/scim2/Users/{var}`` so their traffic is profiled together.

2. Turn a request into a fixed-length **numeric feature vector** the anomaly
   model can consume, plus per-parameter descriptors the profiler aggregates.

The per-value descriptors (length, character-class mix, entropy, inferred type)
are the vocabulary the whole system reasons in: an app parameter's "normal" is a
tight cluster in this space; anything outside it is anomalous by construction —
no attack signature required.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .parser import Request

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_INT_RE = re.compile(r"^-?\d+$")
_B64_RE = re.compile(r"^[A-Za-z0-9_\-+/]{16,}={0,2}$")
_URL_RE = re.compile(r"^https?://", re.I)
_JWT_RE = re.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$")


def infer_type(value: str) -> str:
    v = value.strip()
    if v == "":
        return "empty"
    if _INT_RE.match(v):
        return "int"
    if _UUID_RE.match(v):
        return "uuid"
    if _URL_RE.match(v):
        return "url"
    if _JWT_RE.match(v):
        return "jwt"
    if _HEX_RE.match(v):
        return "hex"
    if _B64_RE.match(v) and len(v) >= 20:
        return "base64"
    if re.match(r"^[A-Za-z0-9_.\- ]+$", v):
        return "token"
    return "freeform"


def char_classes(value: str) -> dict[str, float]:
    n = len(value) or 1
    digits = sum(c.isdigit() for c in value)
    alpha = sum(c.isalpha() for c in value)
    special = sum((not c.isalnum()) and (not c.isspace()) for c in value)
    return {
        "p_digit": digits / n,
        "p_alpha": alpha / n,
        "p_special": special / n,
    }


def shannon(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for c in value:
        counts[c] = counts.get(c, 0) + 1
    total = len(value)
    ent = -sum((c / total) * math.log2(c / total) for c in counts.values())
    # normalise to 0..1 against the max entropy for this length
    return ent / math.log2(total) if total > 1 else 0.0


def template_path(path: str) -> str:
    """Collapse variable path segments to {var}."""
    segs = path.split("/")
    out = []
    for s in segs:
        if not s:
            out.append(s)
            continue
        # Collapse only segments that look like *values*, not route names.
        # A long base64-ish token virtually always carries digits; a pure-alpha
        # segment like "authenticationendpoint" is a route, so require a digit.
        looks_like_token = len(s) >= 20 and _B64_RE.match(s) and any(c.isdigit() for c in s)
        if _UUID_RE.match(s) or _HEX_RE.match(s) or _INT_RE.match(s) or looks_like_token:
            out.append("{var}")
        else:
            out.append(s)
    return "/".join(out) or "/"


# The fixed request-level feature vector fed to the anomaly model. Keeping it
# small and interpretable is deliberate: every dimension has a plain meaning.
FEATURE_NAMES = [
    "n_args",            # number of query params
    "total_arg_len",     # summed length of all values
    "max_arg_len",       # longest single value
    "mean_entropy",      # mean normalised entropy across values
    "max_special",       # max special-char ratio across values
    "n_headers",         # header count
    "ua_len",            # user-agent length
    "body_size",         # request body size
    "is_post",           # method is POST/PUT/PATCH
]


@dataclass
class ArgFeature:
    name: str
    length: int
    vtype: str
    entropy: float
    p_special: float


def request_features(req: Request) -> tuple[list[float], list[ArgFeature]]:
    argfeats: list[ArgFeature] = []
    entropies: list[float] = []
    specials: list[float] = []
    total_len = 0
    max_len = 0
    for name, val in req.args.items():
        cc = char_classes(val)
        ent = shannon(val)
        argfeats.append(ArgFeature(name, len(val), infer_type(val), ent, cc["p_special"]))
        entropies.append(ent)
        specials.append(cc["p_special"])
        total_len += len(val)
        max_len = max(max_len, len(val))

    vec = [
        float(len(req.args)),
        float(total_len),
        float(max_len),
        float(sum(entropies) / len(entropies)) if entropies else 0.0,
        float(max(specials)) if specials else 0.0,
        float(len(req.headers)),
        float(len(req.user_agent)),
        float(req.body_size),
        1.0 if req.method in ("POST", "PUT", "PATCH") else 0.0,
    ]
    return vec, argfeats
