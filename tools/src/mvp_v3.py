#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MVP v3: CTF 流量分析 - 扫描器识别模块

数据流:
    pcap
      │ scapy.rdpcap
      ▼
    pkts (frame list)
      │ filter haslayer(HTTPRequest)
      ▼
    HTTP 请求记录 (list[dict])
      │ 三段式匹配 (UA / header / payload)
      ▼
    命中统计 (Counter × 段)
      │ 聚合 by IP × scanner
      ▼
    攻击者评分 + Markdown 报告

匹配逻辑:
- ua: 正则匹配 User-Agent 字段 (强证据)
- header: 正则匹配任意 header 名或值 (强证据，自定义 header 是金标准)
- payload_keywords: 字面量匹配 URI / 请求 body (弱辅证)

依赖:
    pip install -r tools/requirements.txt

使用:
    python tools/src/mvp_v3.py --pcap <file.pcap>
    python tools/src/mvp_v3.py --pcap <file.pcap> --rules custom.yaml --out my_report.md
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import yaml
from scapy.all import IPv6, rdpcap
from scapy.layers.http import HTTPRequest


# ============== 工具函数 ==============

def ts_to_str(epoch) -> str:
    """epoch (float) -> 'YYYY-MM-DD HH:MM:SS'，失败返回空串"""
    try:
        return datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return ""


def _decode(b) -> str:
    """scapy 字段可能是 bytes / str，统一转 str（latin-1 容错）"""
    if b is None:
        return ""
    if isinstance(b, bytes):
        return b.decode("latin-1", errors="replace")
    return str(b)


def _b(s: str) -> bytes:
    return s.encode("latin-1", errors="replace")


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


# ============== pcap 解析 ==============

# 标准 header 列表（用于自定 header 统计）
STD_HEADERS = {
    "Host", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language",
    "Connection", "Cache-Control", "Pragma", "Cookie", "Content-Type",
    "Content-Length", "Referer", "Origin", "Upgrade-Insecure-Requests",
    "If-Modified-Since", "If-None-Match", "TE",
}


def parse_pcap(pcap_path: Path) -> list[dict]:
    """
    用 scapy 读 pcap，提取所有 HTTPRequest 层帧
    返回 list[dict]，每条 dict 字段:
        ts_epoch, ip_src, method, host, uri, ua, headers (dict), payload (str)
    """
    t0 = time.perf_counter()
    pkts = rdpcap(str(pcap_path))
    dt_load = (time.perf_counter() - t0) * 1000
    print(f"  scapy.rdpcap 加载 {len(pkts)} 帧, 耗时 {dt_load:.0f} ms")

    records = []
    for pkt in pkts:
        if not pkt.haslayer(HTTPRequest):
            continue
        req = pkt[HTTPRequest]

        # 源 IP (v4 / v6)
        if pkt.haslayer("IP"):
            ip_src = _decode(pkt["IP"].src)
        elif pkt.haslayer(IPv6):
            ip_src = _decode(pkt[IPv6].src)
        else:
            ip_src = ""

        # 标准字段
        method = _decode(req.Method).strip()
        path = _decode(req.Path).strip()
        http_version = _decode(req.Http_Version).strip()
        host = _decode(req.Host).strip()
        ua = _decode(req.User_Agent).strip()

        # 自定义 header 字典 (全部 + 标准都进 headers，但匹配时按"任意 header"处理)
        headers: dict[str, str] = {}
        # 标准字段也并入（用下划线转连字符的形式）
        std_map = {
            "Host": host,
            "User-Agent": ua,
            "Accept": _decode(req.Accept),
            "Accept-Encoding": _decode(req.Accept_Encoding),
            "Accept-Language": _decode(req.Accept_Language),
            "Cookie": _decode(req.Cookie),
            "Content-Type": _decode(req.Content_Type),
            "Content-Length": _decode(req.Content_Length),
            "Referer": _decode(req.Referer),
            "Connection": _decode(req.Connection),
            "Origin": _decode(req.Origin),
        }
        for k, v in std_map.items():
            if v:
                headers[k] = v

        # 自定义 header（scapy 放进 req.Headers 列表）
        # 形式: list[ (RawVal_None_b, name_bytes, value_bytes) ] 或类似
        # scapy 2.5+ 用 HeaderFieldSet 风格
        try:
            extra_headers = list(req.Headers) if req.Headers else []
        except Exception:
            extra_headers = []

        for h in extra_headers:
            # h 可能是不同结构: (name, value), [name, value], HeaderField 对象
            try:
                if isinstance(h, (list, tuple)):
                    if len(h) >= 2:
                        name = _decode(h[0]).strip()
                        value = _decode(h[1]).strip()
                    else:
                        continue
                else:
                    # scapy Packet-like: 尝试访问字段
                    name = _decode(getattr(h, "name", b"") or b"").strip()
                    value = _decode(getattr(h, "value", b"") or b"").strip()
            except Exception:
                continue
            if name:
                headers[name] = value

        # URI: Path 可能是相对路径，绝对 URI 拼 host
        if path.startswith("/"):
            uri = path
        elif path.startswith("http://") or path.startswith("https://"):
            uri = path
        elif path:
            # 绝对路径但没 scheme
            uri = f"http://{host}{path if path.startswith('/') else '/' + path}"
        else:
            uri = "/"

        # payload 字符串：用于 payload_keywords 字面量匹配
        # 含 URI + 标准 header 全集（避免漏 payload 里的特征）
        payload_str = " ".join([uri, ua, host, method, http_version])

        records.append({
            "ts_epoch": float(pkt.time) if pkt.time else 0.0,
            "ip_src": ip_src,
            "method": method,
            "host": host,
            "uri": uri,
            "ua": ua,
            "headers": headers,
            "payload_str": payload_str,
        })
    return records


# ============== 三段式匹配 ==============

def match_scanner(rec: dict, rules: dict) -> list[tuple[dict, list[str], int]]:
    """
    对单条记录跑所有扫描器规则
    返回 [(scanner_rule, hit_segments, weight), ...]
    """
    ua = rec["ua"]
    headers = rec["headers"]
    payload = rec["payload_str"]

    # 构造"任意 header"搜索串: "Name=Value Name=Value ..."
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

        # 扫描器匹配
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

    # 攻击者评分
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

    # 一、扫描器识别
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

    # 二、判定强度说明
    lines.append("\n## 二、判定强度说明\n")
    lines.append("- **强特征**：UA 字段匹配 或 自定义 Header 匹配（仅凭单一字段即可判定扫描器身份）")
    lines.append("- **弱辅证**：仅 payload / URI 中含工具相关字符串，需结合其它特征（请求频率、URI 多样性等）")
    lines.append("- 自定义 header 含金量最高（如 `Acunetix-Aspect: enabled` 是 AWVS 自报家门）")

    # 三、攻击者 IP 排行
    lines.append("\n## 三、疑似攻击者 IP 排行\n")
    lines.append("| 排名 | IP | 请求数 | 不同UA | 不同URI | 浏览器UA | 触发的攻击类型 | 评分 |")
    lines.append("|---:|---|---:|---:|---:|---:|---|---:|")
    for i, s in enumerate(stats["suspects"][:15], 1):
        attacks = "、".join(
            f"{k}({v})" for k, v in sorted(s["attack_types"].items(), key=lambda x: -x[1])[:6]
        ) or "—"
        lines.append(f"| {i} | `{s['ip']}` | {s['requests']} | {s['unique_ua']} | {s['unique_uri']} | {s['normal_browser_ua']} | {attacks} | {s['score']} |")

    # 四、各 IP 扫描器命中详情
    lines.append("\n## 四、各 IP 上的扫描器命中详情\n")
    all_ips = [ip for ip, hits in stats["scanner_per_ip"].items() if hits]
    for ip in sorted(all_ips, key=lambda x: sum(stats["scanner_per_ip"][x].values()), reverse=True)[:10]:
        lines.append(f"\n### `{ip}`")
        lines.append("| 扫描器 | 总命中 | UA | Header | Payload |")
        lines.append("|---|---:|---:|---:|---:|")
        for sid, cnt in stats["scanner_per_ip"][ip].most_common():
            sc_name = next((s["name"] for s in rules["scanners"] if s["id"] == sid), sid)
            lines.append(f"| {sc_name} | {cnt} | {stats['scanner_ua_hits'].get(sid, 0)} | {stats['scanner_hdr_hits'].get(sid, 0)} | {stats['scanner_pl_hits'].get(sid, 0)} |")

    # 五、典型 payload 样例
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

    # 六、关键结论
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

    lines.append("\n\n---\n*本报告由 mvp_v3.py 自动生成*\n")
    text = "\n".join(lines)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    return text


# ============== CLI 入口 ==============

def main():
    parser = argparse.ArgumentParser(
        description="CTF 应急流量分析 - 扫描器识别模块 (scapy + YAML 规则)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python tools/src/mvp_v3.py --pcap web_attack.pcap
  python tools/src/mvp_v3.py --pcap web_attack.pcap --rules custom.yaml --out my_report.md
        """,
    )
    parser.add_argument("--pcap", required=True, type=Path, help="pcap/pcapng 文件路径")
    parser.add_argument("--rules", type=Path, default=None, help="YAML 规则库路径（默认 tools/rules/scanners.yaml）")
    parser.add_argument("--out", type=Path, default=None, help="Markdown 报告输出路径（默认 out/report_v3_<timestamp>.md）")
    args = parser.parse_args()

    # 路径默认值：相对项目根
    project_root = Path(__file__).resolve().parents[2]
    if args.rules is None:
        args.rules = project_root / "tools" / "rules" / "scanners.yaml"
    if args.out is None:
        out_dir = project_root / "out"
        args.out = out_dir / f"report_v3_{datetime.now():%Y%m%d_%H%M%S}.md"

    if not args.pcap.exists():
        print(f"[错误] pcap 不存在: {args.pcap}", file=sys.stderr)
        sys.exit(1)
    if not args.rules.exists():
        print(f"[错误] 规则库不存在: {args.rules}", file=sys.stderr)
        sys.exit(1)

    print(f"[1/4] 加载规则库...")
    rules = load_rules(args.rules)
    print(f"  规则数: {len(rules['scanners'])}")

    print(f"[2/4] 解析 pcap (scapy frame 级)...")
    records = parse_pcap(args.pcap)
    print(f"  HTTP 请求数: {len(records)}")
    if records:
        print(f"  时间: {ts_to_str(records[0]['ts_epoch'])} ~ {ts_to_str(records[-1]['ts_epoch'])}")
        custom_h: Counter = Counter()
        for r in records:
            for k in r["headers"].keys():
                if k not in STD_HEADERS:
                    custom_h[k] += 1
        print(f"  自定义 header 种类: {len(custom_h)}")
        for k, v in custom_h.most_common(10):
            print(f"    {v:>6}  {k}")

    print(f"[3/4] 三段式匹配分析中...")
    stats = analyze(records, rules)

    print(f"[4/4] 输出报告: {args.out}")
    render_md(stats, rules, args.pcap, args.out)

    # 摘要打印
    print("\n" + "=" * 60)
    print("TOP 3 疑似攻击者:")
    for s in stats["suspects"][:3]:
        attacks = "、".join(s["attack_types"].keys()) or "—"
        print(f"  {s['ip']:<20} 请求 {s['requests']:>6}  URI {s['unique_uri']:>6}  UA {s['unique_ua']:>4}  攻击: {attacks[:60]}")

    print("\n扫描器命中 (按段):")
    for sid, total in stats["scanner_hits"].most_common(10):
        sc_name = next((s["name"] for s in rules["scanners"] if s["id"] == sid), sid)
        ua = stats["scanner_ua_hits"].get(sid, 0)
        hd = stats["scanner_hdr_hits"].get(sid, 0)
        pl = stats["scanner_pl_hits"].get(sid, 0)
        print(f"  {sc_name:<45} 总:{total:>5}  UA:{ua:>5}  Hdr:{hd:>5}  Payload:{pl:>5}")


if __name__ == "__main__":
    main()