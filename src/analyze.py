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

EPILOG = f"""
CTF 应急流量分析 - 4 个分析模块 (单一 dispatcher):

  scanner    答'用了什么扫描器' — UA/header/payload 三段式匹配 (e.g. AWVS / sqlmap)
  loginpath  答'哪些是登录后台'   — longest-match-first + 双重过滤 (POST + 2xx/3xx)
  cred       答'凭证被服务端接受' — 响应 302/303 过滤 + POST body 字段别名提取
  webshell   答'上传了哪个 webshell' — multipart filename + 代码内容解析 (eval/$_POST)

数据流:
  pcap
    │ tshark -T fields (协议层解析)
    ▼
  records (71k HTTP 请求 from web_attack.pcap)
    │ module.analyze
    ▼
  stats (path / credential / access / upload 聚合)
    │ module.print_summary
    ▼
  控制台高可疑结果摘要

═══════════════════════════════════════════════════════════════════════
典型用法 (以 web_attack.pcap 为例)
═══════════════════════════════════════════════════════════════════════

# ① 扫描器识别 (默认 module)
python src/analyze.py --pcap web_attack.pcap
# 等价: python src/analyze.py --pcap web_attack.pcap -m scanner
# 答: AWVS (header 命中 352) + sqlmap (UA 命中 6) + 主攻 192.168.94.59

# ② 登录后台检测
python src/analyze.py --pcap web_attack.pcap -m loginpath
# 答: /admin/login.php?rec=login (2822 POST 命中)

# ③ 登录凭证提取 (默认 302/303 算登录成功, form submit 场景)
python src/analyze.py --pcap web_attack.pcap -m cred
# 答: admin/admin!@#pass123 (16:03 302) + 人事/hr123456 (14:35 302)

# ③' RESTful API 场景: 自定义登录成功码 (200 算成功)
python src/analyze.py --pcap api.pcap -m cred --login-success-code 200

# ③'' 移动端 API: 多值
python src/analyze.py --pcap api.pcap -m cred --login-success-code 200,201

# ④ webshell 专项
python src/analyze.py --pcap web_attack.pcap -m webshell
# 答: 1.php (16:12:49 上传) → eval → 密码 1234

# 自定义 YAML 规则库
python src/analyze.py --pcap x.pcap -m scanner --rules my_scanners.yaml

═══════════════════════════════════════════════════════════════════════
完整攻击链 (v0.3.0 → v0.4.2 → v0.5.1 链接 web_attack.pcap)
═══════════════════════════════════════════════════════════════════════

14:35  伴攻 192.168.94.233  登录成功 (人事/hr123456)            ← v0.4.2
16:03  主攻 192.168.94.59   登录成功 (admin/admin!@#pass123)     ← v0.4.2
16:12  主攻  上传 1.php (eval($_POST[1234])) 到 /admin/...     ← v0.5.0 + v0.5.1

═══════════════════════════════════════════════════════════════════════
跑测试
═══════════════════════════════════════════════════════════════════════

python -m pytest src/                       # 全部 234 个测试
python -m pytest src/module/webshell_analyze/test/   # 单 module 测试

可用 module: {', '.join(AVAILABLE_MODULES.keys())}
"""


def main():
    parser = argparse.ArgumentParser(
        prog="analyze.py",
        description="CTF 应急流量分析 - CLI dispatcher (scanner / loginpath / cred / webshell)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    parser.add_argument("--pcap", required=False, type=Path, default=None,
                        help="pcap/pcapng 文件路径 (必填, 除非用 --list-modules)")
    parser.add_argument("-m", "--module", choices=list(AVAILABLE_MODULES.keys()),
                        default="scanner",
                        help="分析模块: scanner (默认, 扫描器识别) | "
                             "loginpath (登录后台) | cred (登录凭证) | webshell (webshell 专项)")
    parser.add_argument("--rules", type=Path, default=None,
                        help="自定义 YAML 规则库路径 (默认用模块自带的 yaml, "
                             "如 src/module/scanner_analyze/rules/scanners.yaml)")
    parser.add_argument("--login-success-code", type=str, default="302,303",
                        help="登录成功的响应码 (逗号分隔), 仅 -m cred 生效. "
                             "默认 302,303 (form submit 标准); "
                             "RESTful API 场景: --login-success-code 200; "
                             "移动端 API: --login-success-code 200,201")
    parser.add_argument("--list-modules", action="store_true",
                        help="列出所有可用模块并退出")
    args = parser.parse_args()

    if args.list_modules:
        print("可用模块 (按 v0.x 版本排序):")
        for cli_name, (py_name, rules_rel) in AVAILABLE_MODULES.items():
            print(f"  -m {cli_name:<10} ({py_name}) — 规则库: {rules_rel}")
        sys.exit(0)

    if args.pcap is None:
        print(f"[错误] --pcap 必填 (或用 --list-modules 看可用模块)", file=sys.stderr)
        sys.exit(1)

    if not args.pcap.exists():
        print(f"[错误] pcap 不存在: {args.pcap}", file=sys.stderr)
        sys.exit(1)

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