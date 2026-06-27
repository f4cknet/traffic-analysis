"""credential_analyze/script/matcher.py - 登录凭证提取

复用 login_analyze.matcher.match_login_path 找"哪个登录接口被访问", 然后从
POST body 提取 username/password 凭证.

**v0.4.0 范围**: application/x-www-form-urlencoded body. multipart/JSON 留 v0.5.0+.
"""
from __future__ import annotations

from urllib.parse import parse_qs, unquote_plus

from src.core import decode_body_str
from src.module.login_analyze.script.matcher import match_login_path

from .field_aliases import extract_credentials


# 判定为"可信度高的登录尝试响应码" (双重过滤之外再加一层)
# 302/303 是登录成功跳转到后台的金标准, 200 可能是回显登录页但仍算"高度可疑"
SUSPICIOUS_LOGIN_RESPONSE_CODES: frozenset[int] = frozenset({200, 302, 303})


def parse_urlencoded_body(body_bytes: bytes, content_type: str = "") -> dict[str, str]:
    """
    解析 urlencoded POST body (e.g. "username=admin&password=123").

    返回 {field_name: value}. 同名多字段取最后一个 (浏览器提交习惯).

    content_type 用来:
      - 判定是不是 form-urlencoded (没声明 / 不是这个就返回空 dict)
      - 取 charset (e.g. "application/x-www-form-urlencoded; charset=UTF-8")

    multipart / JSON / 空 body -> 返回 {} (留给 v0.5.0 处理).
    """
    if not body_bytes:
        return {}

    # 1. Content-Type 校验 (无要求时不强制, 兼容老 pcap)
    ct = (content_type or "").lower()
    if ct and "urlencoded" not in ct and "x-www-form-urlencoded" not in ct:
        # 非 urlencoded 不解析 (multipart/JSON 留给后续)
        return {}

    # 2. 取 charset (默认 utf-8)
    charset = "utf-8"
    if "charset=" in ct:
        charset = ct.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"

    # 3. decode + parse
    body_str = decode_body_str(body_bytes, encoding_hint=charset)
    if not body_str:
        return {}

    # parse_qs 保留所有出现, list 形式; 取 [-1] 收敛到最后一个值
    parsed = parse_qs(body_str, keep_blank_values=True, errors="replace")
    return {k: v[-1] for k, v in parsed.items() if v}


def extract_credentials_from_request(rec: dict, paths_data: dict) -> dict | None:
    """
    从一条 request 记录里提取登录凭证 (假设是 POST + 命中登录接口).

    返回:
      None - 不是登录请求 (没命中路径 / method 不是 POST / body 解析失败)
      {path_id, name, uri, ts_epoch, ip_src, status, username, password,
       content_type} - 提取成功

    注: status 需要 caller 关联 responses_by_stream 后填充. 这里只返回基础字段.
    """
    # 1. 路径匹配 (复用 login-analyze)
    hits = match_login_path(rec, paths_data)
    if not hits:
        return None

    rule = hits[0]["path_rule"]

    # 2. method 过滤
    allowed = [m.upper() for m in (rule.get("methods") or ["POST"])]
    if (rec.get("method") or "").upper() not in allowed:
        return None

    # 3. POST body 解析
    body_bytes = rec.get("post_body_bytes") or b""
    content_type = rec.get("content_type") or ""
    form = parse_urlencoded_body(body_bytes, content_type)
    if not form:
        return None

    # 4. 字段提取
    username, password = extract_credentials(form)

    # 5. 至少要有一个字段识别出来 (否则不算"登录凭证")
    if not username and not password:
        return None

    return {
        "path_id": rule["id"],
        "path_name": rule.get("name", "?"),
        "path_category": rule.get("category", "?"),
        "uri": rec.get("uri", ""),
        "host": rec.get("host", ""),
        "ts_epoch": rec.get("ts_epoch", 0),
        "ip_src": rec.get("ip_src", ""),
        "ua": rec.get("ua", ""),
        "method": rec.get("method", ""),
        "username": username,
        "password": password,
        "form_keys": sorted(form.keys()),
        "content_type": content_type,
    }


def is_suspicious_login_success(rec: dict, status: int | None) -> bool:
    """判定一条 (request, response.status) 是否构成"高度可疑的登录成功尝试".

    - 必须 POST
    - 状态码 ∈ {200, 302, 303}
    """
    if (rec.get("method") or "").upper() != "POST":
        return False
    if status is None:
        return False
    return status in SUSPICIOUS_LOGIN_RESPONSE_CODES