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

from .utils import TSHARK_FIELDS, hex_to_bytes, split_uri


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


def parse_records(pcap_path: Path, tshark_path: Path) -> tuple[dict, dict]:
    """
    tshark 一次性导出 HTTP request + response 帧, 按字段分流, 返回:

    - requests: list[dict] — request 帧 (含 uri/ua/headers/path/query 等)
    - responses_by_stream: dict[stream_id, status_code] — 同 TCP 流的响应状态

    字段分流逻辑:
      - http.request.method 非空 -> request 帧
      - http.response.code   非空 -> response 帧
      - 两者都为空 -> 跳过 (非 HTTP 或异常帧)

    request records 字段:
        ts_epoch, kind='request', ip_src, stream_id, method, host,
        uri (完整), uri_path, uri_query (拆分后),
        ua, headers, payload_str (URI path + UA + host + method, 不含 query)

    stats dict: {run_ms, n_requests, n_responses}
    """
    # 不带 filter, 导所有 HTTP 帧 (request + response 共享 tcp.stream)
    cmd = [str(tshark_path), "-r", str(pcap_path), "-Y", "http",
           "-T", "fields", "-E", "separator=|"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]

    t0 = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       encoding="utf-8", errors="replace")
    dt_ms = (time.perf_counter() - t0) * 1000

    if r.returncode != 0:
        raise RuntimeError(f"tshark 退出码 {r.returncode}\nstderr: {r.stderr[:500]}")

    requests = []
    responses_by_stream: dict[str, int] = {}

    for line in r.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < len(TSHARK_FIELDS):
            parts += [""] * (len(TSHARK_FIELDS) - len(parts))
        f = dict(zip(TSHARK_FIELDS, parts))

        try:
            ts_epoch = float(f.get("frame.time_epoch") or 0)
        except (TypeError, ValueError):
            ts_epoch = 0.0

        method = f.get("http.request.method") or ""
        response_code = f.get("http.response.code") or ""
        stream_id = f.get("tcp.stream") or ""

        if method:
            # request 帧
            ip_src = f.get("ip.src") or f.get("ipv6.src") or ""
            host = f.get("http.host") or ""
            raw_uri = f.get("http.request.uri") or "/"
            ua = f.get("http.user_agent") or ""

            # URI 拆分: 防 query string 污染 payload 段
            uri_path, uri_query = split_uri(raw_uri)

            headers = _parse_request_line(f.get("http.request.line") or "")
            for k, v in (("Host", host), ("User-Agent", ua)):
                if v and k not in headers:
                    headers[k] = v

            # payload_str 不含 query string (防 query 诱导)
            payload_str = " ".join([uri_path, ua, host, method])

            # POST body (http.file_data 是 hex 编码) — credential_analyze 用来提取登录凭证
            content_type = f.get("http.content_type") or ""
            post_body_bytes = hex_to_bytes(f.get("http.file_data") or "")

            requests.append({
                "kind": "request",
                "ts_epoch": ts_epoch, "ip_src": ip_src,
                "stream_id": stream_id,
                "method": method, "host": host,
                "uri": raw_uri, "uri_path": uri_path, "uri_query": uri_query,
                "ua": ua, "headers": headers,
                "content_type": content_type,
                "post_body_bytes": post_body_bytes,
                "payload_str": payload_str,
            })
        elif response_code:
            # response 帧 — 仅存 stream_id -> status_code 映射
            try:
                code = int(response_code)
            except (TypeError, ValueError):
                continue
            if stream_id:
                # 同 stream 多次响应取最后一次 (keep-alive 长连接场景)
                responses_by_stream[stream_id] = code
        # else: 既无 method 也无 code, 跳过

    return (
        {"requests": requests, "responses_by_stream": responses_by_stream},
        {"run_ms": dt_ms, "n_requests": len(requests), "n_responses": len(responses_by_stream)},
    )