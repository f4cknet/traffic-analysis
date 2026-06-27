"""src/core/pcap_parser.py - 跨 module 共享的 pcap 解析

- find_tshark: 找 tshark.exe (项目内置 extend-tools/tshark/tshark.exe)
- parse_records: tshark 子进程 + URI 拆分 -> records list

每个 module 都从 pcap 抽 HTTP 请求, 这部分是共享的.
URI 拆分为 path/query, 防 query 污染 payload 段匹配 (所有 module 都受益).
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

from .utils import TSHARK_FIELDS, split_uri


def find_tshark() -> Path:
    """找 tshark.exe: 相对项目根 src/extend-tools/tshark/tshark.exe"""
    project_root = Path(__file__).resolve().parents[2]
    bundled = project_root / "src" / "extend-tools" / "tshark" / "tshark.exe"
    if not bundled.exists():
        raise FileNotFoundError(
            f"找不到 tshark.exe: {bundled}\n"
            f"  确认 src/extend-tools/tshark/ 已部署"
        )
    return bundled


def _parse_request_line(req_line: str) -> dict[str, str]:
    """
    拆 'GET /xxx HTTP/1.1\\r\\nHost: x\\r\\nUser-Agent: y' 成 {header_name: header_value}
    tshark 把 \\r\\n 序列转义成字面 '\\r\\n' (反斜杠 r 反斜杠 n), 不是真换行.
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


def parse_records(pcap_path: Path, tshark_path: Path) -> tuple[list[dict], dict]:
    """
    tshark 一次性导出 HTTP 字段, 拆 URI path/query, 返回 records list

    返回 records 字段:
        ts_epoch, ip_src, method, host,
        uri (完整), uri_path, uri_query (拆分后),
        ua, headers, payload_str (URI path + UA + host + method, 不含 query)

    stats dict: {run_ms, n_rows}
    """
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
        raw_uri = f.get("http.request.uri") or "/"
        ua = f.get("http.user_agent") or ""

        # URI 拆分: 防 query string 污染 payload 段
        uri_path, uri_query = split_uri(raw_uri)

        headers = _parse_request_line(f.get("http.request.line") or "")
        for k, v in (("Host", host), ("User-Agent", ua)):
            if v and k not in headers:
                headers[k] = v

        # payload_str 不含 query string
        payload_str = " ".join([uri_path, ua, host, method])

        try:
            ts_epoch = float(f.get("frame.time_epoch") or 0)
        except (TypeError, ValueError):
            ts_epoch = 0.0

        records.append({
            "ts_epoch": ts_epoch, "ip_src": ip_src,
            "method": method, "host": host,
            "uri": raw_uri, "uri_path": uri_path, "uri_query": uri_query,
            "ua": ua, "headers": headers,
            "payload_str": payload_str,
        })

    return records, {"run_ms": dt_ms, "n_rows": len(records)}