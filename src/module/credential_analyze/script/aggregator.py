"""credential_analyze/script/aggregator.py - 登录凭证聚合分析

双重过滤 (继承自 login-analyze):
  1. uri_path 命中 login_paths.yaml (复用 longest-match matcher)
  2. method == POST
  3. 响应状态码 ∈ SUSPICIOUS_LOGIN_RESPONSE_CODES ({200, 302, 303})

v0.4.0 加的一层:
  4. POST body 能解析成 urlencoded form
  5. form 里能识别出 username / password 至少一个
"""
from __future__ import annotations

from collections import Counter, defaultdict

from src.core import ts_to_str

from .matcher import (
    SUSPICIOUS_LOGIN_RESPONSE_CODES,
    extract_credentials_from_request,
    is_suspicious_login_success,
)


def _get_response_status(rec: dict, responses_by_stream: dict) -> int | None:
    stream_id = rec.get("stream_id", "")
    if not stream_id:
        return None
    return responses_by_stream.get(stream_id)


def collect_credential_attempts(http_data: dict, paths_data: dict,
                                field_aliases: dict | None = None) -> list[dict]:
    """
    收集所有"高度可疑登录尝试"的明细.

    返回 [{path_id, path_name, path_category, uri, ts_epoch, ts_str, ip_src, ua,
           status, username, password, form_keys}, ...]

    按 ts_epoch 升序 (时间线).

    field_aliases: 透传给 extract_credentials_from_request; 不传则用 DEFAULT.
    """
    requests = http_data["requests"]
    responses = http_data["responses_by_stream"]

    attempts: list[dict] = []
    for r in requests:
        cred = extract_credentials_from_request(r, paths_data, field_aliases)
        if cred is None:
            continue
        status = _get_response_status(r, responses)
        if not is_suspicious_login_success(r, status):
            continue
        cred["status"] = status
        cred["ts_str"] = ts_to_str(cred["ts_epoch"])
        attempts.append(cred)
    attempts.sort(key=lambda x: x["ts_epoch"])
    return attempts


def aggregate_by_credential(attempts: list[dict]) -> list[dict]:
    """
    按 (path_id, username, password) 聚合 — 同一组凭证重复用算 1 次.

    返回 [{path_id, path_name, username, password, count, ips, first_seen, last_seen,
           sample_uri}, ...] 按 count 降序.

    用途: 发现"哪些账号+密码组合被反复尝试" — 这是弱密码爆破的强证据.
    """
    bucket: dict = defaultdict(lambda: {
        "count": 0,
        "ips": set(),
        "first_seen": float("inf"),
        "last_seen": 0.0,
        "sample_uri": "",
        "sample_status": 0,
    })
    for a in attempts:
        key = (a["path_id"], a["username"], a["password"])
        b = bucket[key]
        b["count"] += 1
        ip = a.get("ip_src", "")
        if ip:
            b["ips"].add(ip)
        ts = a.get("ts_epoch", 0)
        if ts < b["first_seen"]:
            b["first_seen"] = ts
            b["sample_uri"] = a["uri"]
            b["sample_status"] = a.get("status", 0)
        b["last_seen"] = max(b["last_seen"], ts)

    rows = []
    for (pid, user, pwd), b in bucket.items():
        rows.append({
            "path_id": pid,
            "path_name": next((a["path_name"] for a in attempts if a["path_id"] == pid), "?"),
            "username": user,
            "password": pwd,
            "count": b["count"],
            "ips": sorted(b["ips"]),
            "ip_count": len(b["ips"]),
            "first_seen": b["first_seen"],
            "last_seen": b["last_seen"],
            "first_seen_str": ts_to_str(b["first_seen"]) if b["first_seen"] != float("inf") else "",
            "last_seen_str": ts_to_str(b["last_seen"]) if b["last_seen"] else "",
            "sample_uri": b["sample_uri"],
            "sample_status": b["sample_status"],
        })
    rows.sort(key=lambda x: x["count"], reverse=True)
    return rows


def build_attacker_profiles(attempts: list[dict], min_attempts: int = 1) -> list[dict]:
    """
    按 IP 聚合 — 每个攻击者用了哪些凭证.

    返回 [{ip, attempts, ips (放这里其实没意义, 兼容字段), unique_credentials,
           username_set, first_seen, last_seen}, ...] 按 attempts 降序.
    """
    bucket: dict = defaultdict(lambda: {
        "attempts": 0,
        "creds": set(),       # set of (path_id, username, password)
        "username_set": set(),
        "first_seen": float("inf"),
        "last_seen": 0.0,
        "sample_attempt": None,
    })
    for a in attempts:
        ip = a.get("ip_src", "")
        if not ip:
            continue
        b = bucket[ip]
        b["attempts"] += 1
        b["creds"].add((a["path_id"], a["username"], a["password"]))
        if a["username"]:
            b["username_set"].add(a["username"])
        ts = a.get("ts_epoch", 0)
        if ts < b["first_seen"]:
            b["first_seen"] = ts
            b["sample_attempt"] = a
        b["last_seen"] = max(b["last_seen"], ts)

    profiles = []
    for ip, b in bucket.items():
        if b["attempts"] < min_attempts:
            continue
        profiles.append({
            "ip": ip,
            "attempts": b["attempts"],
            "unique_credentials": len(b["creds"]),
            "username_set": sorted(b["username_set"]),
            "first_seen": b["first_seen"],
            "last_seen": b["last_seen"],
            "first_seen_str": ts_to_str(b["first_seen"]) if b["first_seen"] != float("inf") else "",
            "last_seen_str": ts_to_str(b["last_seen"]) if b["last_seen"] else "",
            "sample": b["sample_attempt"],
        })
    profiles.sort(key=lambda x: x["attempts"], reverse=True)
    return profiles