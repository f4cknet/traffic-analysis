"""login_analyze/script/matcher.py - 登录后台路径匹配

基于 uri_path (不含 query) 字面量子串匹配 (大小写不敏感).

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

    按 yaml 顺序逐条 path_rule 检查, 一旦命中即停 (精确优先).
    这样避免 /admin/login 同时触发 admin_generic + login_generic + ruoyi
    这种 overlap (yaml 顺序越靠前越精确).

    返回 [{path_rule, hit_pattern}, ...] — 通常 0 或 1 个元素.
    """
    uri_path = (rec.get("uri_path") or "").lower()
    if not uri_path:
        return []

    hits = []
    for lp in paths_data["login_paths"]:
        for pattern in lp["_patterns_lower"]:
            if pattern in uri_path:
                hits.append({"path_rule": lp, "hit_pattern": pattern})
                return hits  # 第一条命中即返回 (精确优先, 避免 overlap)
    return hits