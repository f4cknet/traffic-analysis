"""login_analyze/script/aggregator.py - 聚合分析

- aggregate_login_paths: 按 path_rule 聚合访问统计 (哪些后台被访问最多)
- build_attacker_profiles: 按 IP 聚合画像 (每个攻击者访问了哪些后台)
"""
from __future__ import annotations

from collections import Counter, defaultdict

from src.core import ts_to_str

from .matcher import match_login_path


def aggregate_login_paths(records: list[dict], paths_data: dict) -> list[dict]:
    """
    按 path_rule 聚合访问统计

    返回 [{path_id, name, category, hits, ips, first_seen, last_seen}, ...]
    按 hits 降序排序.
    """
    path_hits: Counter = Counter()      # path_id -> total visits
    path_ips: dict = defaultdict(set)    # path_id -> {ip, ...}
    path_first: dict = {}                # path_id -> earliest ts
    path_last: dict = {}                 # path_id -> latest ts

    for r in records:
        hits = match_login_path(r, paths_data)
        for hit in hits:
            pid = hit["path_rule"]["id"]
            path_hits[pid] += 1
            ip = r.get("ip_src", "")
            if ip:
                path_ips[pid].add(ip)
            ts = r.get("ts_epoch", 0)
            if pid not in path_first:
                path_first[pid] = ts
            path_last[pid] = ts

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
        })
    return rows


def build_attacker_profiles(records: list[dict], paths_data: dict,
                             min_hits: int = 5) -> list[dict]:
    """
    按 IP 聚合画像 (每个攻击者访问了哪些后台)

    min_hits: 该 IP 总访问次数低于此值的跳过 (过滤掉正常浏览器误报)
    """
    ip_hits: Counter = Counter()       # ip -> total login-path visits
    ip_paths: dict = defaultdict(Counter)  # ip -> {path_id: count}
    ip_first: dict = {}
    ip_last: dict = {}

    for r in records:
        hits = match_login_path(r, paths_data)
        if not hits:
            continue
        ip = r.get("ip_src", "")
        if not ip:
            continue
        ip_hits[ip] += 1
        for hit in hits:
            ip_paths[ip][hit["path_rule"]["id"]] += 1
        ts = r.get("ts_epoch", 0)
        if ip not in ip_first:
            ip_first[ip] = ts
        ip_last[ip] = ts

    # 过滤 + 排序
    profiles = []
    for ip, total in ip_hits.most_common():
        if total < min_hits:
            break  # 已经按降序, 后面的更小
        path_details = []
        for pid, cnt in ip_paths[ip].most_common():
            rule = paths_data["path_by_id"][pid]
            path_details.append({
                "path_id": pid,
                "name": rule["name"],
                "category": rule.get("category", "?"),
                "hits": cnt,
            })
        profiles.append({
            "ip": ip,
            "total_hits": total,
            "paths": path_details,
            "first_seen": ip_first[ip],
            "last_seen": ip_last[ip],
        })
    return profiles