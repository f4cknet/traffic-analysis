"""scanner-analyze/script/aggregator.py - 全量聚合 + 攻击者评分

输入 records list, 输出 stats dict (含 scanner_hits / scanner_per_ip / suspects 等)
外加 aggregate_per_ip_scanners() 把 stats 转成更易读的 [per-IP 扫描器列表]
"""
from __future__ import annotations

from collections import Counter, defaultdict

from src.core import classify_uri, is_browser_ua

from .matcher import match_scanner


def analyze(records: list[dict], rules: dict) -> dict:
    """聚合扫描器命中 + 攻击者评分"""
    total = len(records)

    scanner_hits: Counter = Counter()
    scanner_ua_hits: Counter = Counter()
    scanner_hdr_hits: Counter = Counter()
    scanner_pl_hits: Counter = Counter()
    scanner_first_seen: dict = {}
    scanner_per_ip: dict = defaultdict(Counter)

    src_count: Counter = Counter()
    src_ua: dict = defaultdict(set)
    src_uri: dict = defaultdict(set)
    src_method_c: dict = defaultdict(Counter)
    src_method_s: dict = defaultdict(set)
    src_attack_types: dict = defaultdict(Counter)

    for r in records:
        src = r["ip_src"]
        if not src:
            continue
        src_count[src] += 1

        ua = r["ua"]
        uri = r["uri"]
        m = r["method"]

        if ua:
            src_ua[src].add(ua)
        if uri:
            src_uri[src].add(uri)
            for t in classify_uri(uri):
                src_attack_types[src][t] += 1
        if m:
            src_method_c[src][m] += 1
            src_method_s[src].add(m)

        hits = match_scanner(r, rules)
        for sc, segs, w in hits:
            sid = sc["id"]
            scanner_hits[sid] += 1
            scanner_per_ip[src][sid] += 1
            if "ua" in segs:
                scanner_ua_hits[sid] += 1
            if "header" in segs:
                scanner_hdr_hits[sid] += 1
            if "payload" in segs:
                scanner_pl_hits[sid] += 1
            if sid not in scanner_first_seen:
                scanner_first_seen[sid] = r["ts_epoch"]

    suspects = []
    for ip, cnt in src_count.most_common(30):
        ua_count = len(src_ua[ip])
        uri_count = len(src_uri[ip])
        normal_browser = sum(1 for u in src_ua[ip] if is_browser_ua(u))

        score = 0
        score += uri_count * 1
        score += max(0, uri_count - 50) * 2
        if ua_count > 5:
            score += 30
        elif ua_count > 1:
            score += 10
        if "OPTIONS" in src_method_s[ip] or "PROPFIND" in src_method_s[ip]:
            score += 10
        if "HEAD" in src_method_s[ip]:
            score += 5
        score += len(src_attack_types[ip]) * 15

        suspects.append({
            "ip": ip, "requests": cnt, "unique_ua": ua_count, "unique_uri": uri_count,
            "normal_browser_ua": normal_browser, "methods": dict(src_method_c[ip]),
            "attack_types": dict(src_attack_types[ip]), "score": score,
        })
    suspects.sort(key=lambda x: (-x["score"], -x["requests"]))

    return {
        "total": total,
        "scanner_hits": scanner_hits,
        "scanner_ua_hits": scanner_ua_hits,
        "scanner_hdr_hits": scanner_hdr_hits,
        "scanner_pl_hits": scanner_pl_hits,
        "scanner_first_seen": scanner_first_seen,
        "scanner_per_ip": scanner_per_ip,
        "suspects": suspects,
    }


def aggregate_per_ip_scanners(stats: dict, rules: dict) -> list[dict]:
    """
    聚合每个攻击者 IP 用到的扫描器, 按命中总数降序

    返回:
      [
        {
          "ip": "192.168.94.59",
          "total": 22050,
          "scanners": [
            {"id": "...", "name": "...", "total": N, "ua": N, "hdr": N, "payload": N, "strong": bool},
            ...
          ],
        },
        ...
      ]
    """
    sc_name = {sc["id"]: sc["name"] for sc in rules["scanners"]}

    rows = []
    for ip, counter in stats["scanner_per_ip"].items():
        scanners = []
        for sid, cnt in counter.most_common():
            ua_n = stats["scanner_ua_hits"].get(sid, 0)
            hdr_n = stats["scanner_hdr_hits"].get(sid, 0)
            pl_n = stats["scanner_pl_hits"].get(sid, 0)
            scanners.append({
                "id": sid,
                "name": sc_name.get(sid, sid),
                "total": cnt,
                "ua": ua_n,
                "hdr": hdr_n,
                "payload": pl_n,
                "strong": (ua_n > 0 or hdr_n > 0),
            })
        rows.append({"ip": ip, "total": sum(counter.values()), "scanners": scanners})
    rows.sort(key=lambda x: -x["total"])
    return rows