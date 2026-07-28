"""
Tests for the behavioural baselining engine.
Run: python tests/test_engine.py   (or python -m pytest)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import (
    BaselineModel,
    EnvelopeChecker,
    build_matrix,
    evaluate,
    infer_type,
    learn_profiles,
    parse_lines,
    reconstruct_sessions,
    template_path,
)
from engine.sessions import SequenceModel


def _req(method, uri, ip="10.0.0.1", sess="", ts="", label="", status=200, body=0):
    return json.dumps({
        "method": method, "uri": uri, "client_ip": ip, "session_id": sess,
        "ts": ts, "label": label, "status": status, "body_size": body,
        "headers": {"User-Agent": "Mozilla/5.0"},
    })


def _oidc(ip, sess, t0=0):
    """A well-formed OIDC flow as 5 request lines."""
    return [
        _req("GET", "/oauth2/authorize?client_id=spa&redirect_uri=https://a.example/cb&state=abc", ip, sess, f"2026-07-28T00:00:{t0:02d}Z"),
        _req("GET", "/authenticationendpoint/login.do?sessionDataKey=%s" % sess, ip, sess, f"2026-07-28T00:00:{t0+1:02d}Z"),
        _req("POST", "/commonauth?type=oidc", ip, sess, f"2026-07-28T00:00:{t0+2:02d}Z"),
        _req("POST", "/oauth2/token?grant_type=authorization_code&code=abcdef123456&client_id=spa", ip, sess, f"2026-07-28T00:00:{t0+3:02d}Z"),
        _req("GET", "/oauth2/userinfo", ip, sess, f"2026-07-28T00:00:{t0+4:02d}Z"),
    ]


def _baseline(n=60):
    lines = []
    for i in range(n):
        lines += _oidc(f"10.0.0.{i}", f"s{i}")
    return parse_lines(lines)[0]


def test_infer_type():
    assert infer_type("12345") == "int"
    assert infer_type("9f8c1a2b-3d4e-5f60-7182-93a4b5c6d7e8") == "uuid"
    assert infer_type("https://app.example/cb") == "url"
    assert infer_type("") == "empty"


def test_template_collapses_values_not_routes():
    assert template_path("/scim2/Users/9f8c1a2b-3d4e-5f60-7182-93a4b5c6d7e8") == "/scim2/Users/{var}"
    assert template_path("/scim2/Users/42") == "/scim2/Users/{var}"
    # a pure-alpha route segment must NOT be collapsed
    assert template_path("/authenticationendpoint/login.do") == "/authenticationendpoint/login.do"


def test_profile_learns_endpoints_and_params():
    profiles = learn_profiles(_baseline())
    assert "/oauth2/authorize" in profiles
    ep = profiles["/oauth2/authorize"]
    assert ep.confidence == "high"
    assert "GET" in ep.allowed_methods
    assert "redirect_uri" in ep.params
    assert ep.params["redirect_uri"].dominant_type == "url"


def test_envelope_flags_unexpected_param_and_method():
    profiles = learn_profiles(_baseline())
    checker = EnvelopeChecker(profiles)
    reqs, _ = parse_lines([_req("GET", "/oauth2/token?grant_type=x&code=abcdef123456&debug=1&cmd=whoami")])
    kinds = {v.kind for v in checker.check(reqs[0])}
    assert "unexpected_param" in kinds
    reqs2, _ = parse_lines([_req("DELETE", "/oauth2/userinfo")])
    assert "method" in {v.kind for v in checker.check(reqs2[0])}


def test_unknown_endpoint_flagged():
    profiles = learn_profiles(_baseline())
    checker = EnvelopeChecker(profiles)
    reqs, _ = parse_lines([_req("GET", "/carbon/admin/login.jsp")])
    assert any(v.kind == "unknown_endpoint" for v in checker.check(reqs[0]))


def test_ml_model_scores_normal_low_and_outlier_high():
    base = _baseline()
    model = BaselineModel().fit(build_matrix(base))
    # a request with a wildly long param should score above the normal threshold
    outlier, _ = parse_lines([_req("GET", "/oauth2/authorize?redirect_uri=" + "A" * 500)])
    assert model.score(build_matrix(outlier))[0] > model.threshold_


def test_session_model_flags_out_of_order_flow():
    base = _baseline()
    seq = SequenceModel().fit(reconstruct_sessions(base))
    # token WITHOUT a preceding authorize — a never-seen start transition
    bad, _ = parse_lines([
        _req("POST", "/oauth2/token?grant_type=x&code=abcdef123456", "9.9.9.9", "bad", "2026-07-28T01:00:00Z"),
        _req("GET", "/oauth2/userinfo", "9.9.9.9", "bad", "2026-07-28T01:00:01Z"),
    ])
    surprisal, rare = seq.score_session(bad)
    assert any(p == 0.0 for *_, p in rare)  # contains an unseen transition


def test_end_to_end_catches_abnormal_not_normal():
    base = _baseline()
    profiles = learn_profiles(base)
    seq = SequenceModel().fit(reconstruct_sessions(base))
    model = BaselineModel().fit(build_matrix(base))
    checker = EnvelopeChecker(profiles)
    score = list(base)  # normal
    score += parse_lines([_req("GET", "/oauth2/token?grant_type=x&code=abcdef123456&cmd=whoami", "5.5.5.5", "ab", "2026-07-28T02:00:00Z", "abnormal")])[0]
    verdicts = evaluate(score, model, checker, seq=seq)
    ab = [v for v in verdicts if v.request.label == "abnormal"]
    assert all(v.outside_envelope for v in ab)
    fp = sum(1 for v in verdicts if not v.request.label and v.outside_envelope)
    assert fp <= 2  # normal false-flags stay near zero


def test_session_reconstruction_orders_by_timestamp():
    # shuffled input must still reconstruct in chronological order
    lines = _oidc("10.0.0.1", "s")
    reqs, _ = parse_lines(list(reversed(lines)))
    sessions = reconstruct_sessions(reqs)
    assert len(sessions) == 1
    assert sessions[0][0].path == "/oauth2/authorize"  # first chronologically


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
