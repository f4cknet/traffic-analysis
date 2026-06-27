"""src/core - 跨 module 共享代码

供 src/module/* 所有模块使用. 不依赖具体业务 (scanner/webshell/login).

公开 API:
    utils:     split_uri, ts_to_str, classify_uri, is_browser_ua
    pcap_parser: parse_records, find_tshark
"""

from .pcap_parser import find_tshark, parse_records
from .utils import (
    STD_HEADERS,
    TSHARK_FIELDS,
    classify_uri,
    is_browser_ua,
    split_uri,
    ts_to_str,
)

__all__ = [
    "split_uri", "ts_to_str", "classify_uri", "is_browser_ua",
    "STD_HEADERS", "TSHARK_FIELDS",
    "parse_records", "find_tshark",
]