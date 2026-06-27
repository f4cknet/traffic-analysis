"""webshell_analyze script - 公开 API

v0.5.0 模块. 复用 src.core.pcap_parser.parse_records (含 multipart body).

v0.5.0 范围:
  - multipart/form-data 上传检测 + filename 抽取
  - URI 路径匹配 webshell_paths.yaml (longest-match-first)
  - URL query 参数识别 (pass/pwd/cmd/key/code/x/0/1)
  - urlencoded body 参数识别
  - 上传 + 访问 时间线关联 (filename + 时间)
  - 攻击者画像 (按 IP)
  - 控制台报告

不在范围 (留 v0.6.0+):
  - webshell 内容 base64 解码
  - response body flag 扫描
  - 复杂 multipart 嵌套 (单层够用)
"""
from .aggregator import (
    build_attacker_profiles,
    collect_accesses,
    collect_uploads,
    find_orphan_accesses,
    link_uploads_to_accesses,
)
from .field_aliases import (
    CMD_FIELDS,
    DEFAULT_FIELDS,
    PASSWORD_FIELDS,
    extract_webshell_params,
    find_field,
    load_field_aliases,
)
from .matcher import (
    detect_access,
    detect_upload,
    extract_url_query,
    extract_urlencoded_params,
    is_multipart_upload,
    load_paths,
    match_webshell_path,
    parse_multipart_filename,
)
from .report import analyze, print_summary

# analyze.py dispatcher 通用入口 — 统一叫 load_rules (跨 module 一致)
load_rules = load_paths

__all__ = [
    # matcher
    "load_paths", "match_webshell_path",
    "is_multipart_upload", "parse_multipart_filename",
    "extract_url_query", "extract_urlencoded_params",
    "detect_upload", "detect_access",
    # aggregator
    "collect_uploads", "collect_accesses",
    "link_uploads_to_accesses", "find_orphan_accesses",
    "build_attacker_profiles",
    # field_aliases
    "DEFAULT_FIELDS", "PASSWORD_FIELDS", "CMD_FIELDS",
    "find_field", "extract_webshell_params", "load_field_aliases",
    # report
    "analyze", "print_summary",
    # dispatcher 通用入口 (alias of load_paths)
    "load_rules",
]