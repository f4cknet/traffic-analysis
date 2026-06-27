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


# ============== tshark hex body 解码 ==============

def hex_to_bytes(hex_str: str) -> bytes:
    """
    tshark -T fields 导出的 http.file_data 是 hex 编码字符串 (e.g. "757365726e616d65" for "username").

    安全 decode: 偶数长度则成对 unpack; 奇数/非 hex 字符/空串 -> b''.

    偶数长度校验: 截断末位避免 unhexlify ValueError.
    """
    if not hex_str:
        return b""
    s = hex_str.strip()
    if len(s) % 2 == 1:
        s = s[:-1]  # 偶数对齐, 丢最后一位 (罕见畸形)
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def decode_body_str(body_bytes: bytes, encoding_hint: str = "") -> str:
    """
    解码 POST body 字节为字符串. 优先 encoding_hint (e.g. "utf-8"), 失败 fallback 到 utf-8/latin-1.

    tshark 解码中文 Windows 站常遇 GBK, 不强制尝试 (避免误判); 后续 credential_analyze 走调用方传 hint.
    """
    if not body_bytes:
        return ""
    # 先按 hint (lowercase base name)
    hint = ""
    if encoding_hint:
        hint = encoding_hint.split(";")[0].strip().lower()
    for enc in [hint, "utf-8", "latin-1"]:
        if not enc:
            continue
        try:
            return body_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return body_bytes.decode("latin-1", errors="replace")

# tshark 一次性导出的 HTTP 字段
#
# 同时包含 request 和 response 字段, 不带 filter, 由 parse_records 按字段是否
# 为空分流 (request.method 非空 -> request 帧; response.code 非空 -> response 帧).
# tcp.stream 用于跨帧关联 (同一 TCP 连接所有包共享 stream id).
TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "tcp.stream",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.user_agent",
    "http.request.line",
    "http.response.code",
    "http.content_type",          # 用于区分 form-urlencoded / multipart / json
    "http.file_data",             # POST body 字节 (hex 编码, e.g. "75736572")
]

# HTTP 响应状态码 -> (是否"找到了" 的后台)
# 2xx (成功) 和 3xx (重定向到登录页 / 鉴权) 都视为"找到了"
# 4xx (未找到 / 鉴权拒绝) 和 5xx (服务错误) 视为"探测失败"
SUCCESS_RESPONSE_CODES = {200, 201, 202, 204,
                         301, 302, 303, 307, 308}