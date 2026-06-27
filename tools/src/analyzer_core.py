#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyzer_core.py - 共享分析逻辑

供 scapy 版 (mvp_v3.py) 和 tshark 版 (mvp_v3_tshark.py) 共用。

不依赖 scapy / tshark，纯 Python 逻辑：
  - load_rules: 加载 YAML 规则库
  - match_scanner: 单条记录三段式匹配
  - analyze: 全量聚合 + 攻击者评分
  - render_md: Markdown 报告渲染
  - 攻击类型分类 + 浏览器 UA 判断

输入 records 字段契约（两实现必须满足）:
    ts_epoch:   float
    ip_src:     str
    method:     str
    host:       str
    uri:        str
    ua:         str
    headers:    dict[str, str]   # 全部 header，含标准 + 自定义
    payload_str: str              # URI + UA + host + method 拼接（用于 payload_keywords 匹配）
"""
from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import yaml


# ============== 工具函数 ==============

def ts_to_str(epoch) -> str:
    """epoch (float) -> 'YYYY-MM-DD HH:MM:SS'，失败返回空串"""
    try:
        return datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return ""


# ============== 规则加载 ==============

def load_rules(path: Path) -> dict:
    """读 YAML，预编译正则"""
    with path.open("r", encoding="utf-8-sig") as f:
        data = yaml.safe_load(f)
    if not data or "scanners" not in data:
        raise ValueError(f"规则文件 {path} 格式错误：缺 scanners 段")

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


# ============== 三段式匹配 ==============

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

        # 3. Payload 匹配 (弱辅证) - URI / 请求 body 字面量
        for pat in sc["_payload_re"]:
            if pat.search(payload):
                hit_segs.append("payload")
                w += sc["weight"]["payload"]
                break

        if hit_segs:
            hits.append((sc, hit_segs, w))
    return hits


# ============== 攻击类型分类（URI 特征） ==============

ATTACK_TYPE_PATTERNS = [
    ("SQL注入", re.compile(r"(union(\s|%20|\+)+select|or\s+1=1|and\s+1=1|sleep\(|benchmark\(|extractvalue|updatexml|information_schema)", re.I)),
    ("XSS", re.compile(r"(<script|javascript:|onerror=|onload=|<svg.*on|<iframe)", re.I)),
    ("LFI/路径遍历", re.compile(r"(\.\./|\.\.\\|%2e%2e/|%252e%252e|/etc/passwd|/proc/self|\.\.%2f)", re.I)),
    ("RCE/命令注入", re.compile(r"(;|\|)\s*(ls|cat|whoami|id|uname|wget|curl|bash|sh|cmd\.exe)\b|(`[^`]+`)|(\$\([^)]+\))", re.I)),
    ("XXE", re.compile(r"(<!ENTITY|SYSTEM\s*['\"]|file:///|expect://|php://filter)", re.I)),
    ("SSRF", re.compile(r"(https?://(127\.|10\.|192\.168\.|169\.254\.|localhost))", re.I)),
    ("Webshell访问", re.compile(r"\.(php|jsp|jspx|aspx|asp)(\?|$)", re.I)),
    ("文件上传", re.compile(r"(/upload|/uploads/|file=)", re.I)),
    ("管理后台", re.compile(r"(/admin|/manager|/login|/wp-login|/phpmyadmin|/console)", re.I)),
    ("备份文件探测", re.compile(r"(\.(bak|sql|zip|rar|tar\.gz|7z|swp|old|orig|save|backup|git/)|/backup|/db)", re.I)),
]


def classify_uri(uri: str) -> list[str]:
    if not uri:
        return []
    return [name for name, pat in ATTACK_TYPE_PATTERNS if pat.search(uri)]


def is_normal_browser_ua(ua: str) -> bool:
    if not ua:
        return False
    return any(k in ua for k in ("Chrome/", "Firefox/", "Safari/", "MSIE", "Trident/", "Edge/", "Opera/"))


# ============== 主分析 ==============

def analyze(records: list[dict], rules: dict) -> dict:
    """聚合扫描器命中 + 攻击者评分"""
    total = len(records)

    scanner_hits: Counter = Counter()
    scanner_ua_hits: Counter = Counter()
    scanner_hdr_hits: Counter = Counter()
    scanner_pl_hits: Counter = Counter()
    scanner_first_seen: dict = {}
    scanner_sample: dict = defaultdict(list)
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
            if len(scanner_sample[sid]) < 6:
                hit_headers = [
                    k for k, v in r["headers"].items()
                    if any(p.search(f"{k}={v}") for p in sc["_header_re"])
                ]
                scanner_sample[sid].append({
                    "ts": ts_to_str(r["ts_epoch"]),
                    "method": m,
                    "host": r["host"],
                    "uri": uri[:200],
                    "ua": ua[:100],
                    "segs": segs,
                    "hit_headers": hit_headers[:3],
                })

    suspects = []
    for ip, cnt in src_count.most_common(30):
        ua_count = len(src_ua[ip])
        uri_count = len(src_uri[ip])
        normal_browser = sum(1 for u in src_ua[ip] if is_normal_browser_ua(u))

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
        "scanner_sample": scanner_sample,
        "scanner_per_ip": scanner_per_ip,
        "suspects": suspects,
    }


# ============== Markdown 报告渲染 ==============

def render_md(stats: dict, rules: dict, pcap_path: Path, out_path: Path) -> str:
    lines: list[str] = []
    lines.append("# CTF 流量分析报告 v3\n")
    lines.append(f"- 生成时间: {datetime.now():%Y-%m-%d %H:%M:%S}")
    lines.append(f"- 流量文件: `{pcap_path.name}`")
    lines.append(f"- 总 HTTP 请求数: **{stats['total']}**")
    lines.append("- 匹配策略: 三段式 (UA 强 / header 强 / payload 弱)")

    lines.append("\n## 一、扫描器识别结果（三段分类）\n")
    lines.append("| 扫描器 | 强度 | 总命中 | UA 命中 | Header 命中 | Payload 命中 | 首次时间 |")
    lines.append("|---|---|---:|---:|---:|---:|---|---|")
    for sc in rules["scanners"]:
        sid = sc["id"]
        total = stats["scanner_hits"].get(sid, 0)
        if total == 0:
            continue
        ua_cnt = stats["scanner_ua_hits"].get(sid, 0)
        hdr_cnt = stats["scanner_hdr_hits"].get(sid, 0)
        pl_cnt = stats["scanner_pl_hits"].get(sid, 0)
        ts = ts_to_str(stats["scanner_first_seen"].get(sid, 0)) or "-"
        strong = "**强**" if (ua_cnt > 0 or hdr_cnt > 0) else "弱"
        lines.append(f"| {sc['name']} | {strong} | {total} | {ua_cnt} | {hdr_cnt} | {pl_cnt} | {ts} |")

    lines.append("\n## 二、判定强度说明\n")
    lines.append("- **强特征**：UA 字段匹配 或 自定义 Header 匹配（仅凭单一字段即可判定扫描器身份）")
    lines.append("- **弱辅证**：仅 payload / URI 中含工具相关字符串，需结合其它特征（请求频率、URI 多样性等）")
    lines.append("- 自定义 header 含金量最高（如 `Acunetix-Aspect: enabled` 是 AWVS 自报家门）")

    lines.append("\n## 三、疑似攻击者 IP 排行\n")
    lines.append("| 排名 | IP | 请求数 | 不同UA | 不同URI | 浏览器UA | 触发的攻击类型 | 评分 |")
    lines.append("|---:|---|---:|---:|---:|---:|---|---:|")
    for i, s in enumerate(stats["suspects"][:15], 1):
        attacks = "、".join(
            f"{k}({v})" for k, v in sorted(s["attack_types"].items(), key=lambda x: -x[1])[:6]
        ) or "—"
        lines.append(f"| {i} | `{s['ip']}` | {s['requests']} | {s['unique_ua']} | {s['unique_uri']} | {s['normal_browser_ua']} | {attacks} | {s['score']} |")

    lines.append("\n## 四、各 IP 上的扫描器命中详情\n")
    all_ips = [ip for ip, hits in stats["scanner_per_ip"].items() if hits]
    for ip in sorted(all_ips, key=lambda x: sum(stats["scanner_per_ip"][x].values()), reverse=True)[:10]:
        lines.append(f"\n### `{ip}`")
        lines.append("| 扫描器 | 总命中 | UA | Header | Payload |")
        lines.append("|---|---:|---:|---:|---:|")
        for sid, cnt in stats["scanner_per_ip"][ip].most_common():
            sc_name = next((s["name"] for s in rules["scanners"] if s["id"] == sid), sid)
            lines.append(f"| {sc_name} | {cnt} | {stats['scanner_ua_hits'].get(sid, 0)} | {stats['scanner_hdr_hits'].get(sid, 0)} | {stats['scanner_pl_hits'].get(sid, 0)} |")

    lines.append("\n## 五、典型 Payload 样例（按段）\n")
    for sc in rules["scanners"]:
        sid = sc["id"]
        if sid not in stats["scanner_sample"]:
            continue
        lines.append(f"\n### {sc['name']}")
        lines.append("| 时间 | 方法 | URI | UA (前100) | 命中段 | 命中的Header |")
        lines.append("|---|---|---|---|---|---|")
        for s in stats["scanner_sample"][sid]:
            lines.append(f"| {s['ts']} | `{s['method']}` | `{s['uri']}` | {s['ua']} | {','.join(s['segs'])} | {','.join(s['hit_headers']) or '—'} |")

    lines.append("\n## 六、关键结论\n")
    top = stats["suspects"][:3]
    for i, s in enumerate(top, 1):
        flags = []
        if s["unique_ua"] > 5:
            flags.append(f"UA 多样性高({s['unique_ua']})")
        if s["unique_uri"] > 50:
            flags.append(f"URI 多样性高({s['unique_uri']})")
        if s["attack_types"]:
            top_attacks = sorted(s["attack_types"].items(), key=lambda x: -x[1])[:3]
            flags.append("攻击类型: " + "、".join(f"{k}({v})" for k, v in top_attacks))
        lines.append(f"{i}. `{s['ip']}` - 请求 {s['requests']} 次, 不同 URI {s['unique_uri']} 个, 评分 **{s['score']}** ({'; '.join(flags) or '特征不明显'})")

    lines.append("\n\n---\n*本报告由 analyzer 自动生成*\n")
    text = "\n".join(lines)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    return text