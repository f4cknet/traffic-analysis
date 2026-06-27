"""login_analyze/script/aggregator.py - 聚合分析

关键过滤:
  1. **HTTP 方法过滤**: 只算 rule.methods 命中的请求 (默认 POST).
     POST 是提交凭证的金标准 — 真正的"登录尝试"是 POST 请求.
  2. **响应状态过滤**: 只保留 2xx/3xx (成功找到的后台), 4xx/5xx 视为探测失败.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from src.core import SUCCESS_RESPONSE_CODES, ts_to_str

from .matcher import match_login_path


def _get_response_status(rec: dict, responses_by_stream: dict) -> int | None:
    """根据 stream_id 查响应状态码. 同一 stream 多次响应取最后一次 (keep-alive 长连接)."""
    stream_id = rec.get("stream_id", "")
    if not stream_id:
        return None
    return responses_by_stream.get(stream_id)


def _is_method_match(rec: dict, path_rule: dict) -> bool:
    """检查 rec 的 method 是否在该 rule 的允许列表中.

    rule.methods 缺省 = [POST] (POST 是登录提交凭证的金标准).
    """
    allowed = path_rule.get("methods") or ["POST"]
    method = (rec.get("method") or "").upper()
    return method in [m.upper() for m in allowed]


def aggregate_login_paths(http_data: dict, paths_data: dict) -> list[dict]:
    """
    按 path_rule 聚合访问统计.

    过滤顺序 (任一不满足则跳过):
      1. uri_path 命中至少一条 rule
      2. method 在 rule.methods 允许列表中
      3. 响应状态码在 SUCCESS_RESPONSE_CODES (2xx/3xx)

    返回 [{path_id, name, category, hits, ips, first_seen, last_seen, status_codes,
           sample_uri, methods}, ...]
    按 hits 降序排序.

    sample_uri: 该后台被首次发现的完整 URI (含 query), 用于报告输出.
    """
    requests = http_data["requests"]
    responses = http_data["responses_by_stream"]

    path_hits: Counter = Counter()
    path_ips: dict = defaultdict(set)
    path_first: dict = {}
    path_last: dict = {}
    path_statuses: dict = defaultdict(Counter)  # path_id -> {status: count}
    path_sample_uri: dict = {}  # path_id -> 第一个完整 URI (供报告)

    for r in requests:
        hits = match_login_path(r, paths_data)
        if not hits:
            continue

        # 关联响应: 只保留 2xx/3xx
        status = _get_response_status(r, responses)
        if status not in SUCCESS_RESPONSE_CODES:
            continue

        for hit in hits:
            rule = hit["path_rule"]

            # method 过滤: 不在 rule.methods 列表中 → 跳过
            if not _is_method_match(r, rule):
                continue

            pid = rule["id"]
            path_hits[pid] += 1
            ip = r.get("ip_src", "")
            if ip:
                path_ips[pid].add(ip)
            ts = r.get("ts_epoch", 0)
            if pid not in path_first:
                path_first[pid] = ts
                path_sample_uri[pid] = r.get("uri", "")  # 完整 URI 含 query
            path_last[pid] = ts
            path_statuses[pid][status] += 1

    rows = []
    for pid, total in path_hits.most_common():
        rule = paths_data["path_by_id"][pid]
        rows.append({
            "path_id": pid,
            "name": rule["name"],
            "category": rule.get("category", "?"),
            "hits": total,
            "ips": sorted(path_ips[pid]),
            "ip_count": len(path_ips[pid]),
            "first_seen": path_first.get(pid, 0),
            "last_seen": path_last.get(pid, 0),
            "status_codes": dict(path_statuses[pid]),
            "sample_uri": path_sample_uri.get(pid, ""),
            "methods": rule.get("methods") or ["POST"],
        })
    return rows


def build_attacker_profiles(http_data: dict, paths_data: dict,
                             min_hits: int = 3) -> list[dict]:
    """
    按 IP 聚合画像 — 只算 method + status 都满足的请求.
    """
    requests = http_data["requests"]
    responses = http_data["responses_by_stream"]

    ip_hits: Counter = Counter()
    ip_paths: dict = defaultdict(Counter)
    ip_first: dict = {}
    ip_last: dict = {}
    ip_sample: dict = defaultdict(dict)  # ip -> {path_id: sample_uri}

    for r in requests:
        hits = match_login_path(r, paths_data)
        if not hits:
            continue
        status = _get_response_status(r, responses)
        if status not in SUCCESS_RESPONSE_CODES:
            continue

        ip = r.get("ip_src", "")
        if not ip:
            continue

        for hit in hits:
            rule = hit["path_rule"]
            if not _is_method_match(r, rule):
                continue
            pid = rule["id"]
            ip_paths[ip][pid] += 1
            if pid not in ip_sample[ip]:
                ip_sample[ip][pid] = r.get("uri", "")

        # 只有至少一条 rule 真命中 (过 method) 才计入 IP 总数
        if not ip_paths[ip]:
            continue

        ip_hits[ip] += 1
        ts = r.get("ts_epoch", 0)
        if ip not in ip_first:
            ip_first[ip] = ts
        ip_last[ip] = ts

    profiles = []
    for ip, total in ip_hits.most_common():
        if total < min_hits:
            break
        path_details = []
        for pid, cnt in ip_paths[ip].most_common():
            rule = paths_data["path_by_id"][pid]
            path_details.append({
                "path_id": pid,
                "name": rule["name"],
                "category": rule.get("category", "?"),
                "hits": cnt,
                "sample_uri": ip_sample[ip].get(pid, ""),
            })
        profiles.append({
            "ip": ip,
            "total_hits": total,
            "paths": path_details,
            "first_seen": ip_first[ip],
            "last_seen": ip_last[ip],
        })
    return profiles
