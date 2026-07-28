"""
pattern-lab engine — behavioural traffic baselining for positive-security
WAF lockdown.

Pipeline: parse legitimate traffic -> learn per-endpoint/param profiles +
session model -> score new traffic against the learned normal (ML + envelope) ->
export the profile for Claude to turn into a lockdown. The engine never writes
rules itself.
"""
from .parser import Request, parse_file, parse_lines
from .features import request_features, template_path, infer_type
from .profile import EndpointProfile, ParamProfile, learn_profiles, profile_summary
from .anomaly import (
    BaselineModel,
    AutoencoderModel,
    EnvelopeChecker,
    RequestVerdict,
    build_matrix,
    evaluate,
)
from .sessions import SequenceModel, reconstruct_sessions
from .report import to_csv, to_json, profile_rows
from .claude_prompt import build_prompt, generate_lockdown

__all__ = [
    "Request", "parse_file", "parse_lines",
    "request_features", "template_path", "infer_type",
    "EndpointProfile", "ParamProfile", "learn_profiles", "profile_summary",
    "BaselineModel", "AutoencoderModel", "EnvelopeChecker", "RequestVerdict",
    "build_matrix", "evaluate",
    "SequenceModel", "reconstruct_sessions",
    "to_csv", "to_json", "profile_rows",
    "build_prompt", "generate_lockdown",
]
