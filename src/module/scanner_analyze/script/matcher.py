"""scanner-analyze/script/matcher.py - 三段式匹配核心

三段语义:
  - ua:      正则匹配 User-Agent 字段 (强证据)
  - header:  正则匹配任意 header 名或值 (强证据, 自定义 header 是金标准)
  - payload: 字面量匹配 payload_str (URI path + UA + host + method)
             **不**包含 URI query string — 防 query 参数诱导
"""
from __future__ import annotations

import re

import yaml


def load_rules(path) -> dict:
    """读 scanners.yaml, 预编译正则, 设默认 weight"""
    with open(path, "r", encoding="utf-8-sig") as f:
        data = yaml.safe_load(f)
    if not data or "scanners" not in data:
        raise ValueError(f"规则文件 {path} 格式错误: 缺 scanners 段")

    for sc in data["scanners"]:
        sc["_ua_re"] = [re.compile(p, re.IGNORECASE) for p in sc["match"].get("ua", [])]
        sc["_header_re"] = [re.compile(p, re.IGNORECASE) for p in sc["match"].get("header", [])]
        sc["_payload_re"] = [
            re.compile(re.escape(p), re.IGNORECASE)
            for p in sc["match"].get("payload_keywords", [])
        ]
        sc.setdefault("weight", {})
        sc["weight"].setdefault("ua", 5)
        sc["weight"].setdefault("header", 5)
        sc["weight"].setdefault("payload", 1)
    return data


def match_scanner(rec: dict, rules: dict) -> list[tuple[dict, list[str], int]]:
    """
    对单条记录跑所有扫描器规则
    返回 [(scanner_rule, hit_segments, weight), ...]
    """
    ua = rec["ua"]
    headers = rec["headers"]
    payload = rec["payload_str"]

    # 任意 header 搜索串: "Name=Value Name=Value ..."
    headers_search = " ".join(f"{k}={v}" for k, v in headers.items())

    hits = []
    for sc in rules["scanners"]:
        hit_segs: list[str] = []
        w = 0

        # 1. UA 匹配 (强证据)
        for pat in sc["_ua_re"]:
            if pat.search(ua):
                hit_segs.append("ua")
                w += sc["weight"]["ua"]
                break

        # 2. Header 匹配 (强证据) - 任意 header 名或值
        for pat in sc["_header_re"]:
            if pat.search(headers_search):
                hit_segs.append("header")
                w += sc["weight"]["header"]
                break

        # 3. Payload 匹配 (弱辅证) - URI path + UA + host + method
        #    **不含** URI query string (防 query 参数诱导)
        for pat in sc["_payload_re"]:
            if pat.search(payload):
                hit_segs.append("payload")
                w += sc["weight"]["payload"]
                break

        if hit_segs:
            hits.append((sc, hit_segs, w))
    return hits