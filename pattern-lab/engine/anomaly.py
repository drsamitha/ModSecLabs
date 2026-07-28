"""
The behavioural anomaly core.

Two complementary detectors, both trained ONLY on normal traffic:

* :class:`BaselineModel` — an unsupervised, ML-style detector on the numeric
  request feature vectors. The default implementation learns the low-dimensional
  subspace that normal traffic lives in (PCA via SVD) and scores a request by
  how badly it *reconstructs* from that subspace — exactly the idea behind an
  autoencoder, done with numpy so it runs anywhere. If PyTorch is present, a
  small autoencoder can be swapped in behind the same ``fit``/``score`` API
  (:class:`AutoencoderModel`); the reconstruction-error semantics are identical,
  so the rest of the system is unchanged. The block threshold is the 99th
  percentile of the *normal* score distribution — "how unlike normal is unusual".

* :class:`EnvelopeChecker` — a deterministic positive-security check of a request
  against the learned :mod:`profile`: unknown endpoint, disallowed method,
  unexpected parameter, value length past the normal p99, type mismatch,
  special-char ratio past normal. No ML, no signatures — just "is this inside
  the envelope we learned?".

Neither emits rules. They score and explain; Claude turns the profile + scores
into the actual lockdown.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from .features import FEATURE_NAMES, infer_type, char_classes, template_path, request_features
from .parser import Request
from .profile import EndpointProfile


# --------------------------------------------------------------------------- #
#  ML detector: PCA-reconstruction (default) / autoencoder (optional)
# --------------------------------------------------------------------------- #
class BaselineModel:
    """PCA-reconstruction anomaly model. fit(normal) -> score(any)."""

    def __init__(self, n_components: int | None = None):
        self.n_components = n_components
        self.mean_: np.ndarray | None = None
        self.std_: np.ndarray | None = None
        self.components_: np.ndarray | None = None
        self.threshold_: float = 0.0
        self.normal_scores_: np.ndarray | None = None

    def _standardize(self, X: np.ndarray) -> np.ndarray:
        return (X - self.mean_) / self.std_

    def fit(self, X: np.ndarray) -> "BaselineModel":
        X = np.asarray(X, dtype=float)
        self.mean_ = X.mean(axis=0)
        self.std_ = X.std(axis=0)
        self.std_[self.std_ == 0] = 1.0
        Xs = self._standardize(X)
        # principal subspace of normal traffic
        k = self.n_components or max(1, min(Xs.shape[1] - 1, Xs.shape[1] // 2 + 1))
        # SVD: rows of Vt are principal directions
        _, _, Vt = np.linalg.svd(Xs, full_matrices=False)
        self.components_ = Vt[:k]
        self.normal_scores_ = self._recon_error(Xs)
        # robust threshold: 99th percentile of normal reconstruction error
        self.threshold_ = float(np.percentile(self.normal_scores_, 99))
        return self

    def _recon_error(self, Xs: np.ndarray) -> np.ndarray:
        proj = Xs @ self.components_.T @ self.components_  # reconstruct
        return np.sqrt(((Xs - proj) ** 2).sum(axis=1))

    def score(self, X: np.ndarray) -> np.ndarray:
        """Return anomaly scores (higher = more anomalous)."""
        Xs = self._standardize(np.asarray(X, dtype=float))
        return self._recon_error(Xs)

    def is_anomaly(self, X: np.ndarray) -> np.ndarray:
        return self.score(X) > self.threshold_


class AutoencoderModel(BaselineModel):
    """Optional PyTorch autoencoder with the same fit/score contract.

    Falls back to the PCA parent if torch is unavailable, so callers can always
    request it. Use when you have lots of data and want a non-linear normal
    manifold; otherwise the PCA default is faster and just as interpretable.
    """

    def __init__(self, hidden: int = 4, epochs: int = 200, lr: float = 0.01):
        super().__init__()
        self.hidden = hidden
        self.epochs = epochs
        self.lr = lr
        self._torch_ok = False
        self.net = None

    def fit(self, X: np.ndarray) -> "AutoencoderModel":
        try:
            import torch
            import torch.nn as nn
        except ImportError:
            # graceful degrade: behave exactly like the PCA model
            super().fit(X)
            return self

        self._torch_ok = True
        X = np.asarray(X, dtype=float)
        self.mean_ = X.mean(axis=0)
        self.std_ = X.std(axis=0)
        self.std_[self.std_ == 0] = 1.0
        Xs = torch.tensor(self._standardize(X), dtype=torch.float32)
        d = Xs.shape[1]
        self.net = nn.Sequential(
            nn.Linear(d, self.hidden), nn.ReLU(),
            nn.Linear(self.hidden, d),
        )
        opt = torch.optim.Adam(self.net.parameters(), lr=self.lr)
        loss_fn = nn.MSELoss()
        for _ in range(self.epochs):
            opt.zero_grad()
            out = self.net(Xs)
            loss = loss_fn(out, Xs)
            loss.backward()
            opt.step()
        with torch.no_grad():
            err = ((self.net(Xs) - Xs) ** 2).sum(dim=1).sqrt().numpy()
        self.normal_scores_ = err
        self.threshold_ = float(np.percentile(err, 99))
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        if not self._torch_ok:
            return super().score(X)
        import torch
        Xs = torch.tensor(self._standardize(np.asarray(X, dtype=float)), dtype=torch.float32)
        with torch.no_grad():
            return ((self.net(Xs) - Xs) ** 2).sum(dim=1).sqrt().numpy()


def build_matrix(requests: list[Request]) -> np.ndarray:
    return np.array([request_features(r)[0] for r in requests], dtype=float)


# --------------------------------------------------------------------------- #
#  Deterministic positive-security envelope check
# --------------------------------------------------------------------------- #
@dataclass
class Violation:
    kind: str
    detail: str


@dataclass
class RequestVerdict:
    request: Request
    endpoint: str
    ml_score: float = 0.0
    ml_anomalous: bool = False
    violations: list[Violation] = field(default_factory=list)
    session_surprisal: float = 0.0
    session_anomalous: bool = False

    @property
    def outside_envelope(self) -> bool:
        return bool(self.violations) or self.ml_anomalous or self.session_anomalous


class EnvelopeChecker:
    """Check requests against the learned profile (no ML, no signatures)."""

    def __init__(self, profiles: dict[str, EndpointProfile], len_factor: float = 1.5):
        self.profiles = profiles
        self.len_factor = len_factor

    def check(self, req: Request) -> list[Violation]:
        tpl = template_path(req.path)
        ep = self.profiles.get(tpl)
        out: list[Violation] = []
        if ep is None:
            out.append(Violation("unknown_endpoint", f"{tpl} not seen in baseline"))
            return out
        if ep.confidence == "low":
            # not enough data to constrain; report but don't over-claim
            out.append(Violation("low_confidence_endpoint",
                                  f"{tpl} observed only {ep.count}x in baseline"))
        if req.method not in ep.methods:
            out.append(Violation("method", f"{req.method} not seen on {tpl}"))
        for name, val in req.args.items():
            pp = ep.params.get(name)
            if pp is None:
                out.append(Violation("unexpected_param", f"{name} never seen on {tpl}"))
                continue
            if pp.confidence == "low":
                continue
            if len(val) > max(pp.len_p99 * self.len_factor, pp.len_p99 + 8):
                out.append(Violation("length",
                    f"{name}={len(val)}b exceeds normal p99={pp.len_p99}"))
            vt = infer_type(val)
            if pp.dominant_type and vt != pp.dominant_type and pp.types.get(vt, 0) == 0:
                out.append(Violation("type",
                    f"{name} is '{vt}', baseline is '{pp.dominant_type}'"))
            if pp.is_enum and val not in pp.enum_values:
                out.append(Violation("enum",
                    f"{name}='{val[:24]}' not in learned enum {pp.enum_values}"))
            sp = char_classes(val)["p_special"]
            if sp > max(pp.max_special + 0.15, 0.2):
                out.append(Violation("charset",
                    f"{name} special-ratio {sp:.2f} > normal {pp.max_special:.2f}"))
        return out


def evaluate(requests: list[Request], model: BaselineModel,
             checker: EnvelopeChecker, seq=None,
             session_threshold: float = 3.0) -> list[RequestVerdict]:
    """Score each request: per-request ML anomaly + envelope violations, and —
    when a fitted SequenceModel is supplied — flag every request belonging to a
    session whose endpoint-flow is anomalously surprising (catches individually-
    normal requests that only look wrong in sequence)."""
    if not requests:
        return []
    scores = model.score(build_matrix(requests))
    verdicts = []
    by_req: dict[int, RequestVerdict] = {}
    for req, s in zip(requests, scores):
        v = RequestVerdict(
            request=req,
            endpoint=template_path(req.path),
            ml_score=float(s),
            ml_anomalous=bool(s > model.threshold_),
            violations=checker.check(req),
        )
        verdicts.append(v)
        by_req[id(req)] = v

    if seq is not None:
        from .sessions import reconstruct_sessions
        for sess in reconstruct_sessions(requests):
            surprisal, rare = seq.score_session(sess)
            # anomalous if the flow is surprising overall, or contains any
            # transition the baseline never saw (a novel step in the flow).
            anomalous = surprisal > session_threshold or any(p == 0.0 for *_, p in rare)
            for r in sess:
                v = by_req.get(id(r))
                if v is not None:
                    v.session_surprisal = surprisal
                    v.session_anomalous = anomalous
    return verdicts
