"""webshell_analyze/script/report.py - 控制台输出

回答"攻击者上传了什么 webshell + 用了什么密码":
[1] 上传 + 访问 关联摘要 (按文件聚合)
[2] 攻击者画像 (按 IP)
[3] 关键结论 — 文件名 + 上传时间 + 密码
[4] 时间线
"""
from __future__ import annotations

from src.core import ts_to_str

from .aggregator import (
    build_attacker_profiles,
    collect_accesses,
    collect_uploads,
    find_orphan_accesses,
    link_uploads_to_accesses,
)
from .field_aliases import DEFAULT_FIELDS, load_field_aliases


def _default_field_aliases_path() -> str:
    """找模块自带的 rules/webshell_fields.yaml"""
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "rules", "webshell_fields.yaml"))


def analyze(http_data: dict, paths_data: dict,
            field_aliases: dict | None = None) -> dict:
    """
    聚合分析 — dispatcher 调用入口.

    field_aliases 不传则自动加载模块自带的 rules/webshell_fields.yaml.
    """
    if field_aliases is None:
        field_aliases = load_field_aliases(_default_field_aliases_path())

    uploads = collect_uploads(http_data)
    accesses = collect_accesses(http_data, paths_data, field_aliases)
    linked = link_uploads_to_accesses(uploads, accesses)
    orphans = find_orphan_accesses(uploads, accesses)
    profiles = build_attacker_profiles(linked, orphans)

    return {
        "uploads": uploads,
        "accesses": accesses,
        "linked": linked,
        "orphan_accesses": orphans,
        "attacker_profiles": profiles,
        "field_aliases": field_aliases,
    }


def print_summary(pcap_path, records_count: int, parse_ms: float,
                  stats: dict, rules: dict,
                  field_aliases: dict | None = None):
    """打印 webshell 活动摘要"""

    if field_aliases is None:
        field_aliases = stats.get("field_aliases") or DEFAULT_FIELDS

    pwd_n = len(field_aliases.get("password", []))
    cmd_n = len(field_aliases.get("cmd", []))
    fa_hint = f"yaml 别名表 (password×{pwd_n} + cmd×{cmd_n})"

    bar = "=" * 70
    print(f"\n{bar}")
    print(f"  CTF 流量 webshell 专项 — {pcap_path.name}")
    print(f"{bar}")
    print(f"  HTTP 请求数: {records_count}, 解析: {parse_ms / 1000:.1f} s")
    print(f"  检测: multipart 上传 (filename 抽取) + URI 命中 webshell_paths.yaml + URL/body 参数 (pass/pwd/cmd)")
    print(f"  字段识别: {fa_hint}")

    uploads = stats["uploads"]
    accesses = stats["accesses"]
    linked = stats["linked"]
    orphans = stats["orphan_accesses"]
    profiles = stats["attacker_profiles"]

    # 一、关联摘要 (上传 + 后续访问)
    print(f"\n[1] 上传 + 访问 关联摘要 (按文件名聚合, 上传时间升序)")
    print(f"  {'文件名':<30} {'上传时间':<19} {'访问':>4}  {'首访/末访':<32}  {'代码/访问 密码摘要'}")
    print(f"  {'-'*30} {'-'*19} {'-'*4}  {'-'*32}  {'-'*50}")
    if linked:
        for lk in linked:
            fname = lk["filename"]
            if len(fname) > 28:
                fname = fname[:25] + "..."
            upload_ts = lk["upload"].get("ts_str", "?")
            access_cnt = lk["access_count"]
            time_range = ""
            if lk["accesses"]:
                time_range = f"{lk['first_access_str']} ~ {lk['last_access_str']}"
                if len(time_range) > 32:
                    time_range = time_range[:29] + "..."
            # 密码/命令摘要
            pwds = lk["passwords_seen"]
            cmds = lk["cmds_seen"]
            # v0.5.1: 从代码 body 抽的密码 (更可靠)
            code_pwds = lk.get("code_passwords", [])
            code_funcs = lk.get("code_functions", [])
            summary_parts = []
            if code_funcs:
                summary_parts.append(f"函数={','.join(code_funcs[:3])}")
            if code_pwds:
                summary_parts.append(f"代码pwd={','.join(code_pwds[:3])}")
            if pwds:
                summary_parts.append(f"访问pwd={','.join(list(pwds)[:2])}")
            if cmds:
                summary_parts.append(f"cmd={','.join(list(cmds)[:2])}")
            summary = " | ".join(summary_parts) if summary_parts else "(无密码/命令)"
            print(f"  {fname:<30} {upload_ts:<19} {access_cnt:>4}  {time_range:<32}  {summary[:50]}")
    else:
        print(f"  未检测到 multipart 上传")

    # 二、攻击者画像
    print(f"\n[2] 攻击者画像 (按 IP, 按 total_actions 降序)")
    print(f"  {'IP':<18} {'上传':>4} {'访问':>5}  {'首/末次':<32}")
    print(f"  {'-'*18} {'-'*4} {'-'*5}  {'-'*32}")
    for prof in profiles[:15]:
        time_range = f"{prof['first_seen_str']} ~ {prof['last_seen_str']}"
        if len(time_range) > 32:
            time_range = time_range[:29] + "..."
        print(f"  {prof['ip']:<18} {prof['upload_count']:>4} {prof['access_count']:>5}  {time_range}")

    # 三、关键结论
    print(f"\n[3] 关键结论 — webshell 文件名 + 上传时间 + 密码 (按上传时间排序):")
    if linked:
        for i, lk in enumerate(linked, 1):
            fname = lk["filename"]
            upload = lk["upload"]
            print(f"  {i}. 文件名: {fname}")
            print(f"     上传时间: {upload.get('ts_str', '?')}  IP: {upload.get('ip_src', '?')}")
            print(f"     上传 URI: {upload.get('uri', '?')}")
            # v0.5.1: 代码层面的解析
            language = lk.get("language", "unknown")
            code_funcs = lk.get("code_functions", [])
            code_pwds = lk.get("code_passwords", [])
            if code_funcs or code_pwds:
                print(f"     语言: {language}")
                print(f"     webshell 函数: {','.join(code_funcs) if code_funcs else '(无)'}")
                print(f"     代码提取的密码: {','.join(code_pwds) if code_pwds else '(无)'}")
            else:
                print(f"     (body 里没匹配到已知 webshell 函数模式)")
            if lk["accesses"]:
                pwd_set = lk["passwords_seen"]
                cmd_set = lk["cmds_seen"]
                pwd_str = ",".join(pwd_set) if pwd_set else "(无)"
                cmd_str = ",".join(cmd_set) if cmd_set else "(无)"
                print(f"     后续访问: {lk['access_count']} 次, 首访 {lk['first_access_str']}, 末访 {lk['last_access_str']}")
                print(f"     URL 参数密码: {pwd_str}")
                print(f"     URL 参数命令: {cmd_str}")
            else:
                print(f"     后续访问: 无 (上传后没人调用)")
            print()
    else:
        print(f"  未检测到 multipart 上传请求")
        if accesses:
            print(f"  但检测到 {len(accesses)} 条可疑访问请求 (URL 命中 webshell_paths 或参数含密码字段)")
            print(f"  --- orphan access 前 10 条 ---")
            for a in orphans[:10]:
                print(f"    {a.get('ts_str', '?'):<19}  {a['ip_src']:<16}  {a['method']:<5}  {a['uri'][:60]}")
                if a.get("password") or a.get("cmd"):
                    extras = []
                    if a.get("password"):
                        extras.append(f"pwd={a['password']}")
                    if a.get("cmd"):
                        extras.append(f"cmd={a['cmd']}")
                    print(f"    └─ {', '.join(extras)}")

    # 四、纯访问时间线 (top 20)
    print(f"\n[4] webshell 访问时间线 (前 {min(20, len(accesses))} 条)")
    print(f"  {'时间':<19}  {'IP':<16}  {'method':<6}  {'URI':<45}  {'密码/命令'}")
    print(f"  {'-'*19}  {'-'*16}  {'-'*6}  {'-'*45}  {'-'*30}")
    for a in accesses[:20]:
        uri_show = a["uri"]
        if len(uri_show) > 45:
            uri_show = uri_show[:42] + "..."
        extras = []
        if a.get("password"):
            extras.append(f"pwd={a['password']}")
        if a.get("cmd"):
            extras.append(f"cmd={a['cmd']}")
        extras_str = ",".join(extras) if extras else ""
        if len(extras_str) > 30:
            extras_str = extras_str[:27] + "..."
        print(f"  {a.get('ts_str', '?'):<19}  {a['ip_src']:<16}  {a['method']:<6}  "
              f"{uri_show:<45}  {extras_str}")

    print(f"\n{bar}")
    print(f"  完成。{len(uploads)} 条上传, {len(accesses)} 条访问, "
          f"{len(linked)} 个文件被关联, {len(profiles)} 个攻击者 IP。")
    print(f"{bar}\n")