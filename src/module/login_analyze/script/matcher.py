"""login_analyze/script/matcher.py - 登录后台路径匹配

基于 uri_path (不含 query) 字面量子串匹配 (大小写不敏感).

匹配策略: **最长匹配优先** (longest-match-first).
  在所有命中的 pattern 中, 取最长的作为唯一命中.
  这样避免 /console/login 既触发 login_generic (/login) 又触发 weblogic (/console/login)
  时的 overlap — 最具体的规则胜出.

命中即视为该后台被访问过. 不区分攻击者/正常用户 — 由 aggregator 后续按 IP
高频访问判断是否扫描.
"""
from __future__ import annotations

import yaml


def load_rules(path) -> dict:
    """
    加载 login_paths.yaml, 预编译 patterns 为小写字面量.
    返回 {'login_paths': [...], 'path_by_id': {id: path_rule}}
    """
    with open(path, "r", encoding="utf-8-sig") as f:
        data = yaml.safe_load(f)
    if not data or "login_paths" not in data:
        raise ValueError(f"规则文件 {path} 格式错误: 缺 login_paths 段")

    # 预编译 patterns 为小写, 匹配时也用 lower() 比较
    for lp in data["login_paths"]:
        lp["_patterns_lower"] = [p.lower() for p in lp.get("patterns", [])]

    path_by_id = {lp["id"]: lp for lp in data["login_paths"]}
    return {**data, "path_by_id": path_by_id}


def match_login_path(rec: dict, paths_data: dict) -> list[dict]:
    """
    对单条记录检测其 uri_path 命中哪些登录后台规则.

    **最长匹配优先**: 在所有命中的 pattern 中, 取最长的作为唯一命中.

    返回 [{path_rule, hit_pattern}, ...] — 通常 0 或 1 个元素.
    """
    uri_path = (rec.get("uri_path") or "").lower()
    if not uri_path:
        return []

    best_hit = None  # (path_rule, pattern, pattern_len)
    for lp in paths_data["login_paths"]:
        for pattern in lp["_patterns_lower"]:
            if pattern in uri_path:
                if best_hit is None or len(pattern) > best_hit[2]:
                    best_hit = (lp, pattern, len(pattern))

    if best_hit is None:
        return []
    rule, pattern, _ = best_hit
    return [{"path_rule": rule, "hit_pattern": pattern}]
