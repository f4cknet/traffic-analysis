#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
src/analyze.py: CTF 应急流量分析 CLI 入口 (dispatcher)

按 --module 路由到 src/module/<name>/script/ 处理.
默认 module: scanner-analyze (扫描器识别).

数据流:
    pcap
      │ src.core.pcap_parser.parse_records (跨 module 共享)
      ▼
    records
      │ module.<name>.script.analyze
      ▼
    stats
      │ module.<name>.script.print_summary
      ▼
    控制台高可疑结果摘要

依赖:
    - src/extend-tools/tshark/tshark.exe (项目内置)
    - PyYAML

使用:
    python src/analyze.py --pcap web_attack.pcap
    python src/analyze.py --pcap web_attack.pcap --module scanner-analyze
    python src/analyze.py --pcap web_attack.pcap --rules custom.yaml
"""
from __future__ import annotations

import argparse
import importlib
import sys
import time
from collections import Counter
from pathlib import Path

# 让 src.core / src.module 都可 import — 需要项目根 (analyzer-toolkit/) 在 sys.path
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.core import STD_HEADERS, find_tshark, parse_records, ts_to_str


# ============== Module 路由表 ==============
# 每行: (module_name, default_rules_path_or_None)
# module_name 对应 src/module/<name>/script/

# CLI -m 用短名 (人类友好, 短), Python import 用下划线 (PEP 8)
MODULE_NAME_MAP = {
    "scanner":   "scanner_analyze",
    "loginpath": "login_analyze",
    "cred":      "credential_analyze",
    "webshell":  "webshell_analyze",  # v0.5.0 新增
}


AVAILABLE_MODULES = {
    "scanner":   ("scanner_analyze", "rules/scanners.yaml"),
    "loginpath": ("login_analyze",   "rules/login_paths.yaml"),
    # credential-analyze 复用 login-analyze 的 login_paths.yaml (同一套登录接口定义)
    # 默认路径用 ../ 相对, resolve() 时会自动规范化
    "cred":      ("credential_analyze", "../login_analyze/rules/login_paths.yaml"),
    "webshell":  ("webshell_analyze",  "rules/webshell_paths.yaml"),
}


def load_module(cli_name: str):
    """动态 import src.module.<name>.script"""
    if cli_name not in AVAILABLE_MODULES:
        raise ValueError(
            f"未知 module: {cli_name}. "
            f"可用: {', '.join(AVAILABLE_MODULES.keys())}"
        )
    py_name = MODULE_NAME_MAP[cli_name]
    pkg = importlib.import_module(f"src.module.{py_name}.script")
    return pkg


def resolve_rules_path(cli_name: str, custom: Path | None) -> Path:
    """规则库路径: --rules 显式 > module 默认"""
    if custom is not None:
        return custom
    py_name, default_rel = AVAILABLE_MODULES[cli_name]
    project_root = Path(__file__).resolve().parents[1]
    return (project_root / "src" / "module" / py_name / default_rel).resolve()


# ============== CLI ==============

def main():
    parser = argparse.ArgumentParser(
        description="CTF 应急流量分析 - CLI dispatcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
输出: 控制台打印高可疑结果摘要 (TOP 攻击者 + 扫描器列表 + 关键结论).
       Markdown 报告留待后续模块.

可用 module: {', '.join(AVAILABLE_MODULES.keys())}

示例:
  python src/analyze.py --pcap web_attack.pcap
  python src/analyze.py --pcap web_attack.pcap --module scanner-analyze
  python src/analyze.py --pcap web_attack.pcap -m cred --login-success-code 302
  python src/analyze.py --pcap web_attack.pcap -m cred --login-success-code 200
        """,
    )
    parser.add_argument("--pcap", required=True, type=Path, help="pcap/pcapng 文件路径")
    parser.add_argument("-m", "--module", choices=list(AVAILABLE_MODULES.keys()),
                        default="scanner", help="分析模块 (默认 scanner, 选项: scanner|loginpath|cred|webshell)")
    parser.add_argument("--rules", type=Path, default=None, help="自定义 YAML 规则库路径")
    parser.add_argument("--login-success-code", type=str, default="302,303",
                        help="登录成功的响应码 (逗号分隔), 仅 -m cred 生效. "
                             "默认 302,303 (form submit 标准); RESTful API 场景用 --login-success-code 200")
    args = parser.parse_args()

    if not args.pcap.exists():
        print(f"[错误] pcap 不存在: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    # 加载 module
    try:
        mod = load_module(args.module)
    except (ValueError, ImportError) as e:
        print(f"[错误] {e}", file=sys.stderr)
        sys.exit(1)
    print(f"[module] {args.module}", file=sys.stderr)

    # 规则库
    rules_path = resolve_rules_path(args.module, args.rules)
    if not rules_path.exists():
        print(f"[错误] 规则库不存在: {rules_path}", file=sys.stderr)
        sys.exit(1)

    # tshark
    try:
        tshark_path = find_tshark()
    except FileNotFoundError as e:
        print(f"[错误] {e}", file=sys.stderr)
        sys.exit(1)
    print(f"[tshark] {tshark_path}", file=sys.stderr)

    # 1. 加载规则
    print(f"[1/3] 加载规则库: {rules_path}", file=sys.stderr)
    rules = mod.load_rules(rules_path)
    # 通用 key: scanner-analyze 用 'scanners', login-analyze 用 'login_paths'
    rule_count = len(rules.get("scanners") or rules.get("login_paths") or [])
    print(f"  规则数: {rule_count}", file=sys.stderr)

    # 2. 解析 pcap
    print(f"[2/3] 解析 pcap...", file=sys.stderr)
    t0 = time.perf_counter()
    try:
        http_data, parse_stats = parse_records(args.pcap, tshark_path)
    except Exception as e:
        print(f"[错误] pcap 解析失败: {e}", file=sys.stderr)
        sys.exit(1)
    parse_total_ms = (time.perf_counter() - t0) * 1000
    records = http_data["requests"]
    print(f"  HTTP 请求数: {len(records)}, 响应数: {parse_stats['n_responses']}, "
          f"tshark 调用 {parse_stats['run_ms']:.0f} ms, "
          f"总耗时 {parse_total_ms:.0f} ms", file=sys.stderr)

    # 自定义 header 统计 (基于 request records)
    if records:
        custom_h = Counter()
        for r in records:
            for k in r["headers"].keys():
                if k not in STD_HEADERS:
                    custom_h[k] += 1
        print(f"  自定义 header 种类: {len(custom_h)}", file=sys.stderr)
        for k, v in custom_h.most_common(5):
            print(f"    {v:>6}  {k}", file=sys.stderr)

    # 3. module 业务处理
    print(f"[3/3] 分析中...", file=sys.stderr)

    # 解析 --login-success-code (逗号分隔 → frozenset[int]), 仅 cred 使用
    success_codes: frozenset[int] | None = None
    if args.module == "cred":
        try:
            success_codes = frozenset(
                int(x.strip()) for x in args.login_success_code.split(",") if x.strip()
            )
            if not success_codes:
                raise ValueError("空")
            print(f"  --login-success-code: {sorted(success_codes)}", file=sys.stderr)
        except ValueError:
            print(f"[错误] --login-success-code 格式错: {args.login_success_code!r} (期望逗号分隔整数, e.g. 302,303)", file=sys.stderr)
            sys.exit(1)

    # 调 module.analyze, 透传 success_codes (其他 module 忽略)
    try:
        if args.module == "cred":
            stats = mod.analyze(http_data, rules, success_codes=success_codes)
        else:
            stats = mod.analyze(http_data, rules)
    except TypeError as e:
        # module.analyze 不接 success_codes (scanner/loginpath) → 回退到默认签名
        if "success_codes" in str(e):
            stats = mod.analyze(http_data, rules)
        else:
            raise

    # 输出 (走 stdout)
    if args.module == "cred":
        mod.print_summary(args.pcap, len(records), parse_stats["run_ms"], stats, rules,
                          success_codes=success_codes)
    else:
        mod.print_summary(args.pcap, len(records), parse_stats["run_ms"], stats, rules)


if __name__ == "__main__":
    main()