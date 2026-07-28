"""Tests for the pattern engine. Run: python -m pytest (or python tests/test_engine.py)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import extract_patterns, parse_lines, suggest_exclusions, to_csv
from engine.parser import parse_event


def _audit(rule_id, uri, data, ip="1.2.3.4", code=403, score=5, ua="Mozilla"):
    return {
        "transaction": {
            "client_ip": ip,
            "request": {"method": "GET", "uri": uri, "headers": {"User-Agent": ua}},
            "response": {"http_code": code},
            "messages": [
                {"message": "m", "details": {"ruleId": str(rule_id), "data": data}},
                {"message": f"Inbound Anomaly Score Exceeded (Total Score: {score})",
                 "details": {"ruleId": "949110", "data": ""}},
            ],
        }
    }


def test_parser_extracts_location_and_args():
    ev = parse_event(_audit(
        "921151", "/oauth2/authorize?redirect_uri=https://a.b/cb&state=xyz",
        "Matched Data: https://a.b/cb found within ARGS:redirect_uri: https://a.b/cb"))
    assert ev.path == "/oauth2/authorize"
    assert "redirect_uri" in ev.query_args and "state" in ev.query_args
    assert ev.hits[0].matched_location == "ARGS:redirect_uri"
    assert ev.anomaly_score == 5
    assert ev.blocked


def test_parser_skips_garbage():
    events, skipped = parse_lines(["not json", "", "{bad", json.dumps(_audit(
        "942100", "/x?a=1", "Matched Data: x found within ARGS:a: x"))])
    assert len(events) == 1
    assert skipped == 2


def test_false_positive_is_broad_and_benign():
    # 40 distinct clients, benign redirect URLs, no attack signature.
    lines = []
    for i in range(40):
        url = f"https://app{i}.example.com/cb"
        lines.append(json.dumps(_audit(
            "921151", f"/oauth2/authorize?redirect_uri={url}",
            f"Matched Data: {url} found within ARGS:redirect_uri: {url}",
            ip=f"10.0.0.{i}")))
    events, _ = parse_lines(lines)
    patterns = extract_patterns(events)
    assert len(patterns) == 1
    assert patterns[0].verdict == "likely_false_positive"
    assert patterns[0].fp_score > 0.6


def test_real_attack_is_narrow_and_signatured():
    lines = []
    for i in range(12):
        p = "' UNION SELECT username,password FROM users--"
        lines.append(json.dumps(_audit(
            "942100", f"/login?user={p}",
            f"Matched Data: UNION found within ARGS:user: {p}",
            ip="45.9.148.3", score=15)))
    events, _ = parse_lines(lines)
    patterns = extract_patterns(events)
    assert patterns[0].verdict == "likely_attack"
    assert patterns[0].fp_score < 0.35


def test_meta_rules_are_filtered():
    events, _ = parse_lines([json.dumps(_audit(
        "942100", "/x?a=1", "Matched Data: x found within ARGS:a: x"))])
    patterns = extract_patterns(events)
    # 949110 present in the event must not become its own pattern.
    assert all(not p.rule_id.startswith("949") for p in patterns)


def test_exclusion_is_scoped_to_one_target():
    lines = [json.dumps(_audit(
        "921151", f"/oauth2/authorize?redirect_uri=https://a{i}.com/cb",
        f"Matched Data: https://a{i}.com found within ARGS:redirect_uri: https://a{i}.com/cb",
        ip=f"10.0.0.{i}")) for i in range(20)]
    events, _ = parse_lines(lines)
    conf = suggest_exclusions(extract_patterns(events))
    assert "ctl:ruleRemoveTargetById=921151;ARGS:redirect_uri" in conf
    assert "@beginsWith /oauth2/authorize" in conf


def test_csv_has_header_and_rows():
    events, _ = parse_lines([json.dumps(_audit(
        "942100", "/x?a=1", "Matched Data: x found within ARGS:a: x"))])
    csv_text = to_csv(extract_patterns(events))
    assert csv_text.startswith("rule_id,path,location")
    assert "942100" in csv_text


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
