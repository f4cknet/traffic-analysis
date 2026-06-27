"""src/core/utils.py - 跨 module 共享的小工具

- split_uri:    URI path/query 拆分 (防 query 污染 payload 段)
- ts_to_str:    epoch -> 时间字符串
- classify_uri: URI 攻击类型分类 (SQLi/XSS/LFI/...)
- is_browser_ua: 判断是否正常浏览器 UA
- STD_HEADERS / TSHARK_FIELDS: 常量
"""
from __future__ import annotations

import re
from datetime import datetime


# ============== URI 拆分 (防 query 污染) ==============

def split_uri(uri: str) -> tuple[str, str]:
    """
    拆 URI 为 (path, query)
    - path: 不含 query string 的路径部分
    - query: query string 部分 (不含 '?')

    防 query 干扰 payload 段匹配 — query 参数里的扫描器关键字
    不应触发 payload_keywords (那是弱辅证, 容易被诱导).

    直接 partition '?' 而非 urlsplit: 后者把 '/api/users' 解读为
    scheme-relative URL 返回 path='//api/users', 有 leading slash 重复 bug.
    """
    if not uri:
        return "", ""
    if "?" in uri:
        path, _, query = uri.partition("?")
    else:
        path, query = uri, ""
    return path or "/", query


# ============== 时间格式化 ==============

def ts_to_str(epoch) -> str:
    """epoch (float) -> 'YYYY-MM-DD HH:MM:SS', 失败返回空串"""
    try:
        return datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return ""


# ============== URI 攻击类型分类 ==============

ATTACK_TYPE_PATTERNS = [
    ("SQL注入", re.compile(r"(union(\s|%20|\+)+select|or\s+1=1|and\s+1=1|sleep\(|benchmark\(|extractvalue|updatexml|information_schema)", re.I)),
    ("XSS", re.compile(r"(<script|javascript:|onerror=|onload=|<svg.*on|<iframe)", re.I)),
    ("LFI/路径遍历", re.compile(r"(\.\./|\.\.\\|%2e%2e/|%252e%252e|/etc/passwd|/proc/self|\.\.%2f)", re.I)),
    ("RCE/命令注入", re.compile(r"(;|\|)\s*(ls|cat|whoami|id|uname|wget|curl|bash|sh|cmd\.exe)\b|(`[^`]+`)|(\$\([^)]+\))", re.I)),
    ("XXE", re.compile(r"(<!ENTITY|SYSTEM\s*['\"]|file:///|expect://|php://filter)", re.I)),
    ("SSRF", re.compile(r"(https?://(127\.|10\.|192\.168\.|169\.254\.|localhost))", re.I)),
    ("Webshell访问", re.compile(r"\.(php|jsp|jspx|aspx|asp)(\?|$)", re.I)),
    ("文件上传", re.compile(r"(/upload|/uploads/|file=)", re.I)),
    ("管理后台", re.compile(r"(/admin|/manager|/login|/wp-login|/phpmyadmin|/console)", re.I)),
    ("备份文件探测", re.compile(r"(\.(bak|sql|zip|rar|tar\.gz|7z|swp|old|orig|save|backup|git/)|/backup|/db)", re.I)),
]


def classify_uri(uri: str) -> list[str]:
    """URI 攻击类型分类 (用完整 URI, 含 query - 攻击 payload 通常在 path 但也可能跨 query)"""
    if not uri:
        return []
    return [name for name, pat in ATTACK_TYPE_PATTERNS if pat.search(uri)]


# ============== 浏览器 UA 判断 ==============

_BROWSER_UA_KEYS = ("Chrome/", "Firefox/", "Safari/", "MSIE", "Trident/", "Edge/", "Opera/")


def is_browser_ua(ua: str) -> bool:
    """判断是否正常浏览器 UA (非扫描器/工具)"""
    if not ua:
        return False
    return any(k in ua for k in _BROWSER_UA_KEYS)


# ============== 标准 header 列表 ==============

STD_HEADERS = {
    "Host", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language",
    "Connection", "Cache-Control", "Pragma", "Cookie", "Content-Type",
    "Content-Length", "Referer", "Origin", "Upgrade-Insecure-Requests",
    "If-Modified-Since", "If-None-Match", "TE",
}

# tshark 一次性导出的 HTTP 字段
TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.user_agent",
    "http.request.line",
]