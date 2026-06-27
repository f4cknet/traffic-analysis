"""login_analyze/script/report.py - 控制台输出

回答"黑客扫描到哪些登录后台":
[1] 黑客访问过的登录后台 (按访问次数排序)
[2] 攻击者画像 (按 IP, 每个 IP 访问了哪些后台)
[3] 关键结论 (直接给答案)
"""
from __future__ import annotations

from src.core import ts_to_str

from .aggregator import aggregate_login_paths, build_attacker_profiles


def analyze(records: list[dict], paths_data: dict) -> dict:
    """聚合分析 — dispatcher 调用入口"""
    return {
        "path_summary": aggregate_login_paths(records, paths_data),
        "attacker_profiles": build_attacker_profiles(records, paths_data, min_hits=5),
    }


def print_summary(pcap_path, records_count: int, parse_ms: float,
                  stats: dict, rules: dict):
    """打印高可疑登录后台访问摘要

    签名与 scanner-analyze 统一: (pcap_path, count, ms, stats, rules)
    """

    bar = "=" * 70
    print(f"\n{bar}")
    print(f"  CTF 流量登录后台检测 — {pcap_path.name}")
    print(f"{bar}")
    print(f"  HTTP 请求数: {records_count}, 解析: {parse_ms / 1000:.1f} s")

    path_summary = stats["path_summary"]
    attacker_profiles = stats["attacker_profiles"]
    rules_data = rules  # 当前未直接用, 留给未来

    # 一、登录后台访问排行
    print(f"\n[1] 黑客访问过的登录后台 (按访问次数排序)")
    print(f"  {'路径规则':<35} {'类别':<10} {'访问次数':>8}  {'探测 IP 数':>10}  时间范围")
    print(f"  {'-'*35} {'-'*10} {'-'*8}  {'-'*10}  {'-'*25}")
    for row in path_summary:
        t_range = f"{ts_to_str(row['first_seen'])} ~ {ts_to_str(row['last_seen'])}"
        if t_range == " ~ ":
            t_range = "-"
        print(f"  {row['name']:<35} {row['category']:<10} {row['hits']:>8}  "
              f"{row['ip_count']:>10}  {t_range}")

    # 二、攻击者画像
    print(f"\n[2] 攻击者画像 (按 IP 聚合, 仅展示总访问 >= 5 次的 IP)")
    print(f"  {'IP':<20} {'总访问':>8}  访问过的登录后台")
    print(f"  {'-'*20} {'-'*8}  {'-'*50}")
    for prof in attacker_profiles[:10]:
        paths_str = ", ".join(
            f"{p['name']}({p['hits']})" for p in prof["paths"][:5]
        )
        if len(prof["paths"]) > 5:
            paths_str += f" ... +{len(prof['paths']) - 5} 个"
        print(f"  {prof['ip']:<20} {prof['total_hits']:>8}  {paths_str}")

    # 三、关键结论
    print(f"\n[3] 关键结论 — 黑客扫描到的登录后台:")
    if path_summary:
        for i, row in enumerate(path_summary[:10], 1):
            top_ips = ", ".join(row["ips"][:3])
            print(f"  {i}. {row['name']} [{row['category']}] — {row['hits']} 次访问, "
                  f"主要 IP: {top_ips}")
    else:
        print(f"  未检测到登录后台访问 (规则可能不足, 加 login_paths.yaml)")

    print(f"\n{bar}")
    print(f"  完成。{len(path_summary)} 个后台被访问, {len(attacker_profiles)} 个 IP 是高可疑攻击者。")
    print(f"{bar}\n")