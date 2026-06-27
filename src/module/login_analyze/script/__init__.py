"""login_analyze script - 公开 API

复用 src.core.pcap_parser.parse_records 抽 records.
URI 拆分已剔除 query 干扰 (防题目把 /admin 塞 query 里诱导).
"""
from .aggregator import aggregate_login_paths, build_attacker_profiles
from .matcher import load_rules, match_login_path
from .report import analyze, print_summary

__all__ = [
    "load_rules", "match_login_path",
    "aggregate_login_paths", "build_attacker_profiles",
    "analyze", "print_summary",
]