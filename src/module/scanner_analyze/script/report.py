"""scanner-analyze/script/report.py - 控制台高可疑结果摘要输出

不渲染 Markdown, 只打控制台表格 (TOP 攻击者 + 扫描器列表 + 关键结论).
"""
from __future__ import annotations

from src.core import ts_to_str

from .aggregator import aggregate_per_ip_scanners


def print_summary(pcap_path, records_count: int, parse_ms: float,
                  stats: dict, rules: dict):
    """打印高可疑结果 (TOP 攻击者 + 扫描器列表 + 关键结论)"""

    bar = "=" * 70
    print(f"\n{bar}")
    print(f"  CTF 流量扫描器检测 — {pcap_path.name}")
    print(f"{bar}")
    print(f"  HTTP 请求数: {records_count}, 解析: {parse_ms / 1000:.1f} s")
    if records_count:
        # records 不在 stats 里 — 时间戳从 scanner_first_seen 推断 (近似)
        all_ts = [t for t in stats.get("scanner_first_seen", {}).values() if t]
        if all_ts:
            print(f"  攻击时间起点: {ts_to_str(min(all_ts))}")

    per_ip = aggregate_per_ip_scanners(stats, rules)

    # 一、TOP 攻击者
    print(f"\n[1] 高可疑攻击者 (TOP 10, 按扫描器命中数排序)")
    print(f"  {'IP':<20} {'总命中':>8} {'强命中':>8} {'评分':>6}  用到的扫描器")
    print(f"  {'-'*20} {'-'*8} {'-'*8} {'-'*6}  {'-'*40}")
    suspects_by_ip = {s["ip"]: s for s in stats["suspects"]}
    for row in per_ip[:10]:
        ip = row["ip"]
        total = row["total"]
        strong = sum(s["total"] for s in row["scanners"] if s["strong"])
        score = suspects_by_ip.get(ip, {}).get("score", 0)
        scanner_names = ", ".join(s["name"] for s in row["scanners"])
        print(f"  {ip:<20} {total:>8} {strong:>8} {score:>6}  {scanner_names}")

    # 二、扫描器命中 (按段)
    print(f"\n[2] 扫描器命中 (按段)")
    print(f"  {'扫描器':<35} {'总命中':>7} {'UA':>5} {'Hdr':>6} {'Payload':>8}  {'强度'}")
    print(f"  {'-'*35} {'-'*7} {'-'*5} {'-'*6} {'-'*8}  {'-'*4}")
    for sid, total in stats["scanner_hits"].most_common():
        sc_name = next((s["name"] for s in rules["scanners"] if s["id"] == sid), sid)
        ua_n = stats["scanner_ua_hits"].get(sid, 0)
        hdr_n = stats["scanner_hdr_hits"].get(sid, 0)
        pl_n = stats["scanner_pl_hits"].get(sid, 0)
        strong = "强" if (ua_n > 0 or hdr_n > 0) else "弱"
        display_name = sc_name if len(sc_name) <= 35 else sc_name[:32] + "..."
        print(f"  {display_name:<35} {total:>7} {ua_n:>5} {hdr_n:>6} {pl_n:>8}  {strong}")

    # 三、关键结论
    print(f"\n[3] 关键结论")
    if per_ip:
        top = per_ip[0]
        ip = top["ip"]
        top_scanners = [s for s in top["scanners"] if s["strong"]]
        if top_scanners:
            sc_str = " + ".join(
                f"{s['name']} ({'UA' if s['ua'] else 'Hdr'} {s['ua'] or s['hdr']})"
                for s in top_scanners[:3]
            )
            print(f"  TOP 1 攻击者: {ip}")
            print(f"    用到: {sc_str}")
        else:
            print(f"  TOP 1 攻击者: {ip} (仅 payload 弱命中, 需人工确认)")
    print(f"\n{bar}")
    print(f"  完成。详细 payload 样例见各 IP 段分类。")
    print(f"{bar}\n")