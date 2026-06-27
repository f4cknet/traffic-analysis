"""webshell_analyze/script/matcher.py - webshell 检测

核心功能:
  1. multipart 上传检测 + filename 抽取
  2. URI 路径匹配 webshell_paths.yaml (longest-match-first, 复用 login-analyze 套路)
  3. URL query 参数识别 (pass/pwd/cmd/...)
  4. urlencoded body 参数识别
"""
from __future__ import annotations

import re
import yaml
from urllib.parse import parse_qs


# ============== 规则加载 ==============

def load_paths(path) -> dict:
    """
    加载 webshell_paths.yaml. 返回 {'webshell_paths': [...], 'path_by_id': {id: rule}}.

    patterns 预编译为小写字面量, 匹配用 lower() 比较.
    """
    with open(path, "r", encoding="utf-8-sig") as f:
        data = yaml.safe_load(f)
    if not data or "webshell_paths" not in data:
        raise ValueError(f"规则文件 {path} 格式错误: 缺 webshell_paths 段")

    for wp in data["webshell_paths"]:
        wp["_patterns_lower"] = [p.lower() for p in wp.get("patterns", [])]

    path_by_id = {wp["id"]: wp for wp in data["webshell_paths"]}
    return {**data, "path_by_id": path_by_id}


def match_webshell_path(uri_path: str, paths_data: dict) -> list[dict]:
    """
    URI 路径匹配 webshell_paths.yaml. longest-match-first.

    返回 [{path_rule, hit_pattern}, ...] — 0 或 1 个元素 (longest-match 收敛).
    """
    uri_path_lower = (uri_path or "").lower()
    if not uri_path_lower:
        return []

    best_hit = None  # (path_rule, pattern, pattern_len)
    for wp in paths_data["webshell_paths"]:
        for pattern in wp["_patterns_lower"]:
            if pattern in uri_path_lower:
                if best_hit is None or len(pattern) > best_hit[2]:
                    best_hit = (wp, pattern, len(pattern))

    if best_hit is None:
        return []
    rule, pattern, _ = best_hit
    return [{"path_rule": rule, "hit_pattern": pattern}]


# ============== multipart 上传检测 ==============

def is_multipart_upload(rec: dict) -> bool:
    """Content-Type 是 multipart/form-data"""
    ct = (rec.get("content_type") or "").lower()
    return "multipart/form-data" in ct


def parse_multipart_filename(body_bytes: bytes, content_type: str) -> str | None:
    """
    从 multipart/form-data body 里抽 filename.

    实际 multipart body 格式:
        --boundary
        Content-Disposition: form-data; name="file"; filename="hello.html"
        Content-Type: text/html

        <binary content>
        --boundary--

    我们的策略: 用正则找 Content-Disposition 里的 filename="xxx" 或 filename=xxx.
    因为 binary content 可能跟 header 混在一起, 但 Content-Disposition 通常在
    每个 part 开头.

    返回: filename 字符串; 没找到返回 None.
    """
    if not body_bytes:
        return None

    # 1. 取 boundary
    boundary = _parse_boundary(content_type)
    if not boundary:
        return None

    # 2. body 按 boundary 分段
    body_str = body_bytes.decode("latin-1", errors="replace")
    parts = body_str.split(f"--{boundary}")
    if len(parts) < 2:
        return None

    # 3. 遍历每个 part, 找 Content-Disposition + filename
    for part in parts:
        # part 头部 (header) 和 body 之间用 \r\n\r\n 分隔
        header_end = part.find("\r\n\r\n")
        if header_end == -1:
            continue
        header = part[:header_end]

        # Content-Disposition: form-data; name="file"; filename="hello.html"
        # 兼容 filename 没引号的情况, 但**空 filename (filename="") 视为无效**
        m = re.search(r'filename\s*=\s*"([^"]*)"', header, re.IGNORECASE)
        if m:
            fn = m.group(1).strip()
            if fn:
                return fn
            continue  # filename="" 空 → 跳过这个 part, 继续找下一个
        # 无引号版本: filename=xxx (xxx 不能含引号/空白/分号)
        m = re.search(r'filename\s*=\s*([^"\s;]+)', header, re.IGNORECASE)
        if m:
            return m.group(1).strip()

    return None


def _parse_boundary(content_type: str) -> str | None:
    """从 'multipart/form-data; boundary=xxx' 抽 boundary."""
    if not content_type:
        return None
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("boundary="):
            # boundary 值可能有引号
            value = part.split("=", 1)[1].strip()
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            return value
    return None


# ============== 参数提取 (URL query / urlencoded body) ==============

def extract_url_query(uri: str) -> dict[str, str]:
    """
    从 URI 抽 query params. 返回 {key: value}, 多值取最后一个.

    URI 形如 '/foo.php?pass=xxx&cmd=id', 返回 {'pass': 'xxx', 'cmd': 'id'}.
    """
    if not uri or "?" not in uri:
        return {}
    _, _, query = uri.partition("?")
    parsed = parse_qs(query, keep_blank_values=True, errors="replace")
    return {k: v[-1] for k, v in parsed.items() if v}


def extract_urlencoded_params(body_bytes: bytes, content_type: str = "") -> dict[str, str]:
    """
    解析 urlencoded POST body (e.g. "pass=xxx&cmd=id").

    复用 credential_analyze 的逻辑, 但不导入 (避免循环依赖).
    """
    if not body_bytes:
        return {}
    ct = (content_type or "").lower()
    if ct and "urlencoded" not in ct and "x-www-form-urlencoded" not in ct:
        return {}

    charset = "utf-8"
    if "charset=" in ct:
        charset = ct.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"

    try:
        body_str = body_bytes.decode(charset, errors="replace")
    except LookupError:
        body_str = body_bytes.decode("utf-8", errors="replace")
    if not body_str:
        return {}

    parsed = parse_qs(body_str, keep_blank_values=True, errors="replace")
    return {k: v[-1] for k, v in parsed.items() if v}


# ============== 高层封装 ==============

def detect_upload(rec: dict) -> dict | None:
    """
    检测单条记录是否为 multipart 上传 + 抽 filename.

    返回:
      None - 不是 multipart 上传 (或解析失败)
      {filename, ts_epoch, ip_src, ua, content_type, uri, body_size} - 提取成功
    """
    if not is_multipart_upload(rec):
        return None
    body_bytes = rec.get("post_body_bytes") or b""
    content_type = rec.get("content_type") or ""
    filename = parse_multipart_filename(body_bytes, content_type)
    if not filename:
        return None
    return {
        "filename": filename,
        "ts_epoch": rec.get("ts_epoch", 0),
        "ip_src": rec.get("ip_src", ""),
        "ua": rec.get("ua", ""),
        "uri": rec.get("uri", ""),
        "host": rec.get("host", ""),
        "content_type": content_type,
        "body_size": len(body_bytes),
    }


def detect_access(rec: dict, paths_data: dict,
                  field_aliases: dict | None = None) -> dict | None:
    """
    检测单条记录是否为 webshell 访问 — 两种触发:

    1. URI 路径命中 webshell_paths.yaml
    2. URL query 参数 / urlencoded body 参数含 password 字段

    返回:
      None - 不是 webshell 访问
      {uri, ts_epoch, ip_src, ua, method, hit_pattern, path_id, password, cmd,
       source: 'path_match'|'url_param'|'body_param'} - 检测到

    field_aliases 不传则用 field_aliases.DEFAULT_FIELDS.

    注意: multipart 上传请求不算"访问" (由 detect_upload 单独处理). 这是
    为防止上传请求的 URI 命中 upload_dir rule 后被双重计数.
    """
    from .field_aliases import DEFAULT_FIELDS, extract_webshell_params

    # 0. multipart 上传不算访问 (避免重复处理)
    if is_multipart_upload(rec):
        return None

    aliases = field_aliases or DEFAULT_FIELDS
    uri = rec.get("uri") or ""
    uri_path = rec.get("uri_path") or ""

    # 1. 路径匹配
    hits = match_webshell_path(uri_path, paths_data)
    path_match = hits[0] if hits else None

    # 2. URL 参数识别
    url_params = extract_url_query(uri)
    pwd_url, cmd_url = extract_webshell_params(url_params, aliases)

    # 3. body 参数识别
    body_bytes = rec.get("post_body_bytes") or b""
    content_type = rec.get("content_type") or ""
    body_params = extract_urlencoded_params(body_bytes, content_type)
    pwd_body, cmd_body = extract_webshell_params(body_params, aliases)

    # 4. 合并
    pwd = pwd_url or pwd_body
    cmd_val = cmd_url or cmd_body

    # 5. 判定: 路径命中 OR (pwd 非空) → 是 webshell 访问
    if not path_match and not pwd:
        return None

    # source 字段 (debug 用)
    if path_match:
        source = "path_match"
    elif pwd_url:
        source = "url_param"
    else:
        source = "body_param"

    return {
        "uri": uri,
        "uri_path": uri_path,
        "method": rec.get("method", ""),
        "ts_epoch": rec.get("ts_epoch", 0),
        "ip_src": rec.get("ip_src", ""),
        "ua": rec.get("ua", ""),
        "hit_pattern": path_match["hit_pattern"] if path_match else "",
        "path_id": path_match["path_rule"]["id"] if path_match else "",
        "path_name": path_match["path_rule"].get("name", "") if path_match else "",
        "password": pwd,
        "cmd": cmd_val,
        "source": source,
        "url_params": url_params,
        "body_params": body_params,
    }