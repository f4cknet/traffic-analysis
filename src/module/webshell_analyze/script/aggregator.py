"""webshell_analyze/script/aggregator.py - 上传与访问时间线关联

核心逻辑:
  1. 收集所有 multipart 上传请求 (按时间线)
  2. 收集所有 webshell 访问请求 (按时间线)
  3. 关联: 上传文件名 → 后续访问的 URI 路径
  4. 输出每个 webshell 的"上传时间 + 访问时间线"
"""
from __future__ import annotations

from collections import defaultdict
from urllib.parse import unquote

from src.core import ts_to_str

from .matcher import detect_access, detect_upload


def collect_uploads(http_data: dict) -> list[dict]:
    """
    收集所有 multipart 上传请求. 按 ts_epoch 升序.

    返回 [{filename, ts_epoch, ts_str, ip_src, ua, uri, content_type, body_size}, ...]
    """
    uploads = []
    for r in http_data["requests"]:
        u = detect_upload(r)
        if u is None:
            continue
        u["ts_str"] = ts_to_str(u["ts_epoch"])
        uploads.append(u)
    uploads.sort(key=lambda x: x["ts_epoch"])
    return uploads


def collect_accesses(http_data: dict, paths_data: dict,
                     field_aliases: dict | None = None) -> list[dict]:
    """
    收集所有 webshell 访问请求. 按 ts_epoch 升序.
    """
    accesses = []
    for r in http_data["requests"]:
        a = detect_access(r, paths_data, field_aliases)
        if a is None:
            continue
        a["ts_str"] = ts_to_str(a["ts_epoch"])
        accesses.append(a)
    accesses.sort(key=lambda x: x["ts_epoch"])
    return accesses


def link_uploads_to_accesses(uploads: list[dict],
                              accesses: list[dict]) -> list[dict]:
    """
    关联上传与访问: 对每个上传, 找时间在它之后的所有访问,
    按 URI 路径是否包含上传文件名做匹配.

    返回 [{filename, upload_ts, upload_ip, accesses: [...], first_access_ts,
           last_access_ts, unique_ips}, ...]

    关联规则:
      - 上传后 (ts >= upload_ts) 的访问才算 (排除历史访问)
      - 访问 URI 路径包含上传文件名 (例如上传 hello.html 到 /upload/, 访问 /upload/hello.html)
      - 文件名解码 (unquote) 后比较 (防 URL 编码)
    """
    # 按访问 URI 路径分组 (decoded), 方便查找
    by_path: dict = defaultdict(list)
    for a in accesses:
        path = unquote(a["uri_path"] or "").lower()
        by_path[path].append(a)

    linked = []
    for u in uploads:
        filename = unquote(u["filename"]).lower()
        # 跳过空 filename (multipart body 解析失败 / 没 filename 字段)
        if not filename:
            continue
        upload_ts = u["ts_epoch"]

        # 找 URI 路径里含 filename 的访问
        related: list[dict] = []
        for path, access_list in by_path.items():
            if filename in path:
                # 只保留上传后的访问
                post = [a for a in access_list if a["ts_epoch"] >= upload_ts]
                related.extend(post)
        related.sort(key=lambda x: x["ts_epoch"])

        if not related:
            # 没找到关联的访问 (可能上传后没人访问 — 也值得记)
            linked.append({
                "filename": filename,
                "upload": u,
                "accesses": [],
                "first_access_ts": 0,
                "last_access_ts": 0,
                "first_access_str": "",
                "last_access_str": "",
                "unique_ips": set(),
                "access_count": 0,
                "passwords_seen": set(),
                "cmds_seen": set(),
                "code_functions": u.get("functions", []),  # v0.5.1 从 body 抽
                "code_passwords": u.get("passwords", []),  # v0.5.1 从 body 抽
                "language": u.get("language", "unknown"),  # v0.5.1
            })
            continue

        unique_ips = {a["ip_src"] for a in related if a["ip_src"]}
        passwords = {a["password"] for a in related if a["password"]}
        cmds = {a["cmd"] for a in related if a["cmd"]}

        linked.append({
            "filename": filename,
            "upload": u,
            "accesses": related,
            "first_access_ts": related[0]["ts_epoch"],
            "last_access_ts": related[-1]["ts_epoch"],
            "first_access_str": related[0].get("ts_str", ""),
            "last_access_str": related[-1].get("ts_str", ""),
            "unique_ips": unique_ips,
            "access_count": len(related),
            "passwords_seen": passwords,
            "cmds_seen": cmds,
            "code_functions": u.get("functions", []),  # v0.5.1
            "code_passwords": u.get("passwords", []),  # v0.5.1
            "language": u.get("language", "unknown"),  # v0.5.1
        })

    # 按上传时间排序
    linked.sort(key=lambda x: x["upload"]["ts_epoch"])
    return linked


def find_orphan_accesses(uploads: list[dict], accesses: list[dict]) -> list[dict]:
    """
    找"被访问但没看到上传"的 webshell — 这是攻击者直接调用别人上传的 webshell,
    或者 webshell 是历史遗留, 等等.

    返回 accesses 中那些 URI 不在 uploads 文件名关联列表里的访问.
    """
    if not uploads:
        return accesses

    upload_filenames = {unquote(u["filename"]).lower() for u in uploads if u["filename"]}
    orphan = []
    for a in accesses:
        path = unquote(a["uri_path"] or "").lower()
        # 只要 URI 包含任何一个上传文件名, 就不算 orphan
        if any(fn in path for fn in upload_filenames):
            continue
        orphan.append(a)
    return orphan


def build_attacker_profiles(linked: list[dict],
                            orphan_accesses: list[dict]) -> list[dict]:
    """
    按 IP 聚合. 综合:
      - 上传 IP (来自 uploads)
      - 访问 IP (来自 linked.accesses)
      - orphan_accesses (没匹配到上传的访问 IP)

    返回 [{ip, uploaded_files, accessed_files, total_actions, first_seen, last_seen}, ...]
    """
    bucket: dict = defaultdict(lambda: {
        "uploaded_files": [],      # list of (filename, ts)
        "accessed_files": [],      # list of (filename, ts)
        "first_seen": float("inf"),
        "last_seen": 0.0,
    })

    for lk in linked:
        ip = lk["upload"].get("ip_src", "")
        if not ip:
            continue
        b = bucket[ip]
        b["uploaded_files"].append((lk["filename"], lk["upload"]["ts_epoch"]))
        for a in lk["accesses"]:
            if a.get("ip_src") == ip:
                b["accessed_files"].append((lk["filename"], a["ts_epoch"]))
        b["first_seen"] = min(b["first_seen"], lk["upload"]["ts_epoch"])
        b["last_seen"] = max(b["last_seen"], lk["upload"]["ts_epoch"])

    # 把 orphan accesses 也归到对应 IP
    for a in orphan_accesses:
        ip = a.get("ip_src", "")
        if not ip:
            continue
        b = bucket[ip]
        # 提取文件名 (从 uri_path 最后一段)
        from os.path import basename
        fname = basename(a.get("uri_path", ""))
        b["accessed_files"].append((fname, a["ts_epoch"]))
        b["first_seen"] = min(b["first_seen"], a["ts_epoch"])
        b["last_seen"] = max(b["last_seen"], a["ts_epoch"])

    profiles = []
    for ip, b in bucket.items():
        total_actions = len(b["uploaded_files"]) + len(b["accessed_files"])
        profiles.append({
            "ip": ip,
            "uploaded_files": b["uploaded_files"],
            "accessed_files": b["accessed_files"],
            "upload_count": len(b["uploaded_files"]),
            "access_count": len(b["accessed_files"]),
            "total_actions": total_actions,
            "first_seen": b["first_seen"],
            "last_seen": b["last_seen"],
            "first_seen_str": ts_to_str(b["first_seen"]) if b["first_seen"] != float("inf") else "",
            "last_seen_str": ts_to_str(b["last_seen"]) if b["last_seen"] else "",
        })
    profiles.sort(key=lambda x: x["total_actions"], reverse=True)
    return profiles