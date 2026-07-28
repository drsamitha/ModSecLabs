"""Traffic pattern recognition + CRS rule-tuning engine."""
from .parser import Event, RuleHit, parse_file, parse_lines
from .patterns import Pattern, extract_patterns, scanner_ips, summarize
from .tuning import suggest_exclusions, suggest_hardening, to_csv, write_csv
from .claude_prompt import build_prompt, generate_rules

__all__ = [
    "Event",
    "RuleHit",
    "parse_file",
    "parse_lines",
    "Pattern",
    "extract_patterns",
    "scanner_ips",
    "summarize",
    "suggest_exclusions",
    "suggest_hardening",
    "to_csv",
    "write_csv",
    "build_prompt",
    "generate_rules",
]
