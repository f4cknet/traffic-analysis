"""login_analyze/script/report.py - 控制台输出

回答"黑客扫描到哪些登录后台":
[1] 黑客真正找到的登录后台 (响应 2xx/3xx, 按访问次数排序)
[2] 攻击者画像 (按 IP)
[3] 关键结论 - 输出完整 URL (含 query) + 状态码

关键设计:
  - 过滤 4xx/5xx: 攻击者扫描会大量产生 404, 只有真存在的后台才计
  - 完整 URL: ThinkPHP 类 (?m=admin) 等带参数的真实 URL 保留输出
"""
from __future__ import annotations

from src.core import ts_to_str

from .aggregator import aggregate_login_paths, build_attacker_profiles


def analyze(http_data: dict, paths_data: dict) -> dict:
    """聚合分析 — dispatcher 调用入口"""
    return {
        "path_summary": aggregate_login_paths(http_data, paths_data),
        "attacker_profiles": build_attacker_profiles(http_data, paths_data, min_hits=3),
    }


def print_summary(pcap_path, records_count: int, parse_ms: float,
                  stats: dict, rules: dict):
    """打印高可疑登录后台访问摘要 (仅响应 2xx/3xx)

    签名与 scanner-analyze 统一: (pcap_path, count, ms, stats, rules)
    """

    bar = "=" * 70
    print(f"\n{bar}")
    print(f"  CTF 流量登录后台检测 — {pcap_path.name}")
    print(f"{bar}")
    print(f"  HTTP 请求数: {records_count}, 解析: {parse_ms / 1000:.1f} s")
    print(f"  过滤: 仅响应 2xx/3xx (4xx 视为探测失败, 不计)")

    path_summary = stats["path_summary"]
    attacker_profiles = stats["attacker_profiles"]

    # 一、登录后台访问排行
    print(f"\n[1] 黑客真正找到的登录后台 (响应 2xx/3xx, 按访问次数排序)")
    print(f"  {'路径规则':<28} {'类别':<10} {'次数':>5}  {'IP数':>4}  {'状态':<10}  示例完整 URL")
    print(f"  {'-'*28} {'-'*10} {'-'*5}  {'-'*4}  {'-'*10}  {'-'*40}")
    for row in path_summary:
        # 状态码显示: "200×12,302×3"
        sc_str = ",".join(f"{k}×{v}" for k, v in sorted(row["status_codes"].items()))
        sample = row["sample_uri"]
        if len(sample) > 50:
            sample = sample[:47] + "..."
        print(f"  {row['name']:<28} {row['category']:<10} {row['hits']:>5}  "
              f"{row['ip_count']:>4}  {sc_str:<10}  {sample}")

    # 二、攻击者画像 (含每个 IP 找到的完整 URL)
    print(f"\n[2] 攻击者画像 (按 IP 聚合, 仅展示总访问 >= 3 次的 IP)")
    print(f"  {'IP':<20} {'总访问':>7}  找到的登录后台 (含完整 URL)")
    print(f"  {'-'*20} {'-'*7}  {'-'*60}")
    for prof in attacker_profiles[:10]:
        paths_str = ", ".join(
            f"{p['name']}({p['hits']}, {p['sample_uri']})" for p in prof["paths"][:3]
        )
        if len(prof["paths"]) > 3:
            paths_str += f" ... +{len(prof['paths']) - 3} 个"
        print(f"  {prof['ip']:<20} {prof['total_hits']:>7}  {paths_str}")

    # 三、关键结论 (直接给完整 URL 列表)
    print(f"\n[3] 关键结论 — 黑客真正找到的登录后台完整 URL:")
    if path_summary:
        for i, row in enumerate(path_summary[:10], 1):
            top_ips = ", ".join(row["ips"][:3])
            print(f"  {i}. {row['sample_uri']}")
            print(f"      类别: {row['name']} [{row['category']}], "
                  f"访问 {row['hits']} 次 (主要 IP: {top_ips})")
    else:
        print(f"  未检测到登录后台访问 (响应 2xx/3xx 都被过滤)")
        print(f"  提示: 检查 login_paths.yaml 是否覆盖目标; 或降低 SUCCESS_RESPONSE_CODES 阈值")

    print(f"\n{bar}")
    print(f"  完成。{len(path_summary)} 个真存在的后台被找到, {len(attacker_profiles)} 个 IP 是高可疑攻击者。")
    print(f"{bar}\n")