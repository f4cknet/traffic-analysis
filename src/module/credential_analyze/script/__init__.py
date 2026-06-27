"""credential_analyze script - 公开 API

v0.4.0 模块. 复用:
  - src.core.pcap_parser.parse_records (含 POST body)
  - src.module.login_analyze.matcher.match_login_path (路径匹配)
  - src.module.login_analyze.script.load_rules (login_paths.yaml)

v0.4.0 范围:
  - application/x-www-form-urlencoded body 解析
  - username/password 字段别名识别
  - 三重过滤: POST + 命中登录接口 + 响应 {200, 302, 303}
  - 控制台报告: 时间线 + 凭证聚合 + 攻击者画像

不在范围 (留 v0.5.0+):
  - multipart/form-data (webshell 上传也用 multipart, 统一处理)
  - JSON body (API 类登录)
  - GBK 等中文编码 (latin-1 fallback 已能兜底)
"""
from .aggregator import (
    aggregate_by_credential,
    build_attacker_profiles,
    collect_credential_attempts,
)
from .field_aliases import (
    DEFAULT_FIELDS,
    PASSWORD_FIELDS,
    USERNAME_FIELDS,
    extract_credentials,
    find_field,
    load_field_aliases,
)
from .matcher import (
    LOGIN_SUCCESS_RESPONSE_CODES_DEFAULT,
    SUSPICIOUS_LOGIN_RESPONSE_CODES,  # 向后兼容别名
    extract_credentials_from_request,
    is_suspicious_login_success,
    parse_urlencoded_body,
)
from .report import analyze, print_summary

# 复用 login-analyze 的 load_rules (同一套 login_paths.yaml)
# credential-analyze 不需要自己的 yaml 文件
from src.module.login_analyze.script import load_rules

__all__ = [
    # matcher
    "parse_urlencoded_body", "extract_credentials_from_request",
    "is_suspicious_login_success",
    "LOGIN_SUCCESS_RESPONSE_CODES_DEFAULT",
    "SUSPICIOUS_LOGIN_RESPONSE_CODES",  # 向后兼容别名
    # aggregator
    "collect_credential_attempts", "aggregate_by_credential",
    "build_attacker_profiles",
    # field_aliases
    "DEFAULT_FIELDS", "USERNAME_FIELDS", "PASSWORD_FIELDS",
    "find_field", "extract_credentials", "load_field_aliases",
    # report
    "analyze", "print_summary",
    # yaml loader (复用 login-analyze)
    "load_rules",
]