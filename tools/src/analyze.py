#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze.py: CTF 应急流量分析 - 扫描器识别

数据流:
    pcap -> [parse backend] -> records -> analyze -> Markdown 报告

后端 (按优先级):
    tshark  默认 - libpcap 原生 C 解析，~9 秒/174MB pcap
    scapy   fallback - Python 包解析，~110 秒/174MB pcap，仅在 tshark 不可用时使用

后端选择:
    --backend tshark  (默认)
    --backend scapy   (便携优先，无 extend-tools 时使用)
    --backend auto    (tshark 可用就用 tshark，否则降级 scapy)

共享逻辑见 analyzer_core.py:
  - load_rules / analyze / render_md / match_scanner

依赖 (tshark 后端):
    仅 PyYAML (tshark.exe 自带在 extend-tools/tshark/)
依赖 (scapy 后端):
    pip install -r tools/requirements.txt

使用:
    python tools/src/analyze.py --pcap web_attack.pcap
    python tools/src/analyze.py --pcap web_attack.pcap --backend scapy
    python tools/src/analyze.py --pcap web_attack.pcap --rules custom.yaml --out my_report.md
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# 共享分析逻辑
sys.path.insert(0, str(Path(__file__).parent))
from analyzer_core import analyze, load_rules, render_md, ts_to_str


# ============================================================================
# tshark 后端
# ============================================================================

TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.user_agent",
    "http.request.line",
]

# 标准 header 列表（用于自定义 header 统计）
STD_HEADERS = {
    "Host", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language",
    "Connection", "Cache-Control", "Pragma", "Cookie", "Content-Type",
    "Content-Length", "Referer", "Origin", "Upgrade-Insecure-Requests",
    "If-Modified-Since", "If-None-Match", "TE",
}


def _parse_request_line(req_line: str) -> dict[str, str]:
    """
    拆 'GET /xxx HTTP/1.1\\r\\nHost: x\\r\\nUser-Agent: y' 成 {header_name: header_value}
    tshark 把 \\r\\n 序列转义成字面 '\\r\\n' (反斜杠 r 反斜杠 n)，不是真换行。
    """
    if not req_line:
        return {}
    headers: dict[str, str] = {}
    for part in req_line.split("\\r\\n")[1:]:
        if not part or ":" not in part:
            continue
        name, _, value = part.partition(":")
        name = name.strip()
        if name:
            headers[name] = value.strip()
    return headers


def find_tshark(explicit: Path | None) -> Path:
    """找 tshark.exe: --tshark > extend-tools 内置 > 系统 PATH"""
    if explicit is not None:
        if not explicit.exists():
            raise FileNotFoundError(f"--tshark 指定的文件不存在: {explicit}")
        return explicit

    project_root = Path(__file__).resolve().parents[2]
    bundled = project_root / "tools" / "src" / "extend-tools" / "tshark" / "tshark.exe"
    if bundled.exists():
        return bundled

    which = shutil.which("tshark")
    if which:
        return Path(which)

    raise FileNotFoundError(
        "找不到 tshark.exe。请检查:\n"
        f"  - {bundled} 是否存在\n"
        "  - 或 --tshark 显式指定路径\n"
        "  - 或 tshark 是否在系统 PATH\n"
        "  - 或用 --backend scapy 走纯 Python 解析"
    )


def parse_pcap_tshark(pcap_path: Path, tshark_path: Path) -> tuple[list[dict], dict]:
    """tshark 一次性导出字段，TSV 解析为 records。"""
    cmd = [str(tshark_path), "-r", str(pcap_path), "-Y", "http.request",
           "-T", "fields", "-E", "separator=|"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]

    t0 = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       encoding="utf-8", errors="replace")
    dt_ms = (time.perf_counter() - t0) * 1000

    if r.returncode != 0:
        raise RuntimeError(f"tshark 退出码 {r.returncode}\nstderr: {r.stderr[:500]}")

    records = []
    for line in r.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < len(TSHARK_FIELDS):
            parts += [""] * (len(TSHARK_FIELDS) - len(parts))
        f = dict(zip(TSHARK_FIELDS, parts))

        ip_src = f.get("ip.src") or f.get("ipv6.src") or ""
        method = f.get("http.request.method") or ""
        host = f.get("http.host") or ""
        uri = f.get("http.request.uri") or "/"
        ua = f.get("http.user_agent") or ""

        headers = _parse_request_line(f.get("http.request.line") or "")
        for k, v in (("Host", host), ("User-Agent", ua)):
            if v and k not in headers:
                headers[k] = v

        payload_str = " ".join([uri, ua, host, method])

        try:
            ts_epoch = float(f.get("frame.time_epoch") or 0)
        except (TypeError, ValueError):
            ts_epoch = 0.0

        records.append({
            "ts_epoch": ts_epoch, "ip_src": ip_src,
            "method": method, "host": host, "uri": uri, "ua": ua,
            "headers": headers, "payload_str": payload_str,
        })

    return records, {"run_ms": dt_ms, "n_rows": len(records)}


# ============================================================================
# scapy 后端 (fallback，便携优先场景)
# ============================================================================

def _decode(b) -> str:
    """scapy 字段可能是 bytes / str，统一转 str（latin-1 容错）"""
    if b is None:
        return ""
    if isinstance(b, bytes):
        return b.decode("latin-1", errors="replace")
    return str(b)


def parse_pcap_scapy(pcap_path: Path) -> tuple[list[dict], dict]:
    """scapy frame 级解析。慢于 tshark 但无需外部二进制。"""
    # 按需 import scapy (没装时给清晰错误)
    try:
        from scapy.all import IPv6, rdpcap
        from scapy.layers.http import HTTPRequest
    except ImportError as e:
        raise RuntimeError(
            "scapy 后端需要先 `pip install scapy`\n"
            f"  原始错误: {e}"
        )

    t0 = time.perf_counter()
    pkts = rdpcap(str(pcap_path))
    dt_load_ms = (time.perf_counter() - t0) * 1000

    records = []
    for pkt in pkts:
        if not pkt.haslayer(HTTPRequest):
            continue
        req = pkt[HTTPRequest]

        # 源 IP
        if pkt.haslayer("IP"):
            ip_src = _decode(pkt["IP"].src)
        elif pkt.haslayer(IPv6):
            ip_src = _decode(pkt[IPv6].src)
        else:
            ip_src = ""

        method = _decode(req.Method).strip()
        path = _decode(req.Path).strip()
        host = _decode(req.Host).strip()
        ua = _decode(req.User_Agent).strip()

        headers: dict[str, str] = {}
        std_map = {
            "Host": host, "User-Agent": ua,
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

        # 自定义 header (scapy 放进 req.Headers 列表)
        try:
            extra = list(req.Headers) if req.Headers else []
        except Exception:
            extra = []
        for h in extra:
            try:
                if isinstance(h, (list, tuple)):
                    if len(h) >= 2:
                        name = _decode(h[0]).strip()
                        value = _decode(h[1]).strip()
                    else:
                        continue
                else:
                    name = _decode(getattr(h, "name", b"") or b"").strip()
                    value = _decode(getattr(h, "value", b"") or b"").strip()
            except Exception:
                continue
            if name:
                headers[name] = value

        if path.startswith("/") or path.startswith("http://") or path.startswith("https://"):
            uri = path
        elif path:
            uri = f"http://{host}{path if path.startswith('/') else '/' + path}"
        else:
            uri = "/"

        records.append({
            "ts_epoch": float(pkt.time) if pkt.time else 0.0,
            "ip_src": ip_src, "method": method, "host": host,
            "uri": uri, "ua": ua, "headers": headers,
            "payload_str": " ".join([uri, ua, host, method]),
        })

    return records, {"load_ms": dt_load_ms, "n_frames": len(pkts), "n_rows": len(records)}


# ============================================================================
# 后端路由
# ============================================================================

BACKENDS = {
    "tshark": parse_pcap_tshark,
    "scapy":  parse_pcap_scapy,
}


def resolve_backend(name: str, tshark_explicit: Path | None) -> tuple[str, callable, Path | None]:
    """
    返回 (backend_name, parse_fn, tshark_path)
    parse_fn 签名: (pcap_path, *args) -> (records, stats)
    tshark_path 仅 tshark 后端需要
    """
    if name == "auto":
        try:
            tshark_path = find_tshark(tshark_explicit)
            return "tshark", parse_pcap_tshark, tshark_path
        except FileNotFoundError:
            return "scapy", parse_pcap_scapy, None

    if name == "tshark":
        return "tshark", parse_pcap_tshark, find_tshark(tshark_explicit)

    if name == "scapy":
        return "scapy", parse_pcap_scapy, None

    raise ValueError(f"未知 backend: {name}")


# ============================================================================
# CLI 入口
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="CTF 应急流量分析 - 扫描器识别",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
后端优先级 (按原则 [docs/principles.md]):
  tshark  默认 - libpcap 原生 C 解析，性能优先 (~9 秒/174MB pcap)
  scapy   fallback - 纯 Python 解析，便携优先 (~110 秒/174MB pcap)

示例:
  python tools/src/analyze.py --pcap web_attack.pcap
  python tools/src/analyze.py --pcap web_attack.pcap --backend scapy
  python tools/src/analyze.py --pcap web_attack.pcap --rules custom.yaml --out my_report.md
        """,
    )
    parser.add_argument("--pcap", required=True, type=Path, help="pcap/pcapng 文件路径")
    parser.add_argument("--rules", type=Path, default=None, help="YAML 规则库路径")
    parser.add_argument("--out", type=Path, default=None, help="Markdown 报告输出路径")
    parser.add_argument("--backend", choices=("tshark", "scapy", "auto"), default="tshark",
                        help="解析后端 (默认 tshark; auto=tshark 优先, 降级 scapy)")
    parser.add_argument("--tshark", type=Path, default=None,
                        help="tshark.exe 路径 (默认 tools/src/extend-tools/tshark/tshark.exe)")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[2]
    if args.rules is None:
        args.rules = project_root / "tools" / "rules" / "scanners.yaml"
    if args.out is None:
        out_dir = project_root / "out"
        suffix = args.backend if args.backend != "auto" else "auto"
        args.out = out_dir / f"report_{suffix}_{datetime.now():%Y%m%d_%H%M%S}.md"

    if not args.pcap.exists():
        print(f"[错误] pcap 不存在: {args.pcap}", file=sys.stderr)
        sys.exit(1)
    if not args.rules.exists():
        print(f"[错误] 规则库不存在: {args.rules}", file=sys.stderr)
        sys.exit(1)

    # 解析后端
    try:
        backend_name, parse_fn, tshark_path = resolve_backend(args.backend, args.tshark)
    except FileNotFoundError as e:
        print(f"[错误] {e}", file=sys.stderr)
        sys.exit(1)
    print(f"[backend] {backend_name}", end="")
    if tshark_path:
        print(f" ({tshark_path})", end="")
    print()

    print(f"[1/4] 加载规则库...")
    rules = load_rules(args.rules)
    print(f"  规则数: {len(rules['scanners'])}")

    print(f"[2/4] 解析 pcap ({backend_name} 后端)...")
    t0 = time.perf_counter()
    try:
        if backend_name == "tshark":
            records, parse_stats = parse_fn(args.pcap, tshark_path)
        else:
            records, parse_stats = parse_fn(args.pcap)
    except Exception as e:
        print(f"[错误] pcap 解析失败: {e}", file=sys.stderr)
        sys.exit(1)
    dt_total_ms = (time.perf_counter() - t0) * 1000
    print(f"  HTTP 请求数: {len(records)}, 解析耗时 {dt_total_ms:.0f} ms")
    if records:
        print(f"  时间: {ts_to_str(records[0]['ts_epoch'])} ~ {ts_to_str(records[-1]['ts_epoch'])}")

        from collections import Counter
        custom_h = Counter()
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