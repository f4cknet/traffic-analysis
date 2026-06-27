"""credential_analyze/script/report.py - 控制台输出

回答"黑客用了哪些凭证登录":
[1] 全部高度可疑登录尝试 (按时间线)
[2] 按凭证聚合 (同一组 username+password 重复多少次)
[3] 按攻击者 IP 画像
[4] 关键结论 — 提取的 username/password 明文

关键设计:
  - 三重过滤: POST + 命中登录接口 + 响应 ∈ {200, 302, 303}
  - 凭证明文输出: 不打码 (应急分析就是要看真实凭证)
  - 时间线: 按 ts_epoch 升序, 攻击链可读
"""
from __future__ import annotations

from src.core import ts_to_str

from .aggregator import (
    aggregate_by_credential,
    build_attacker_profiles,
    collect_credential_attempts,
)
from .field_aliases import load_field_aliases
from .matcher import LOGIN_SUCCESS_RESPONSE_CODES_DEFAULT


_FIELD_ALIASES_YAML_DEFAULT: str | None = None


def _default_field_aliases_path() -> str:
    """找模块自带的 rules/field_aliases.yaml (相对 __file__)"""
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "rules", "field_aliases.yaml"))


def analyze(http_data: dict, paths_data: dict,
             field_aliases: dict | None = None,
             success_codes: frozenset[int] | None = None) -> dict:
    """
    聚合分析 — dispatcher 调用入口.

    field_aliases: 不传则自动加载模块自带的 rules/field_aliases.yaml;
                  找不到 yaml 时用 DEFAULT_FIELDS 兜底.
    success_codes: 登录成功的响应码集合; 不传则用 {302, 303} (form submit 标准).
                  CLI --login-success-code 控制.
    """
    if field_aliases is None:
        field_aliases = load_field_aliases(_default_field_aliases_path())
    if success_codes is None:
        success_codes = LOGIN_SUCCESS_RESPONSE_CODES_DEFAULT
    attempts = collect_credential_attempts(http_data, paths_data, field_aliases, success_codes)
    return {
        "attempts": attempts,
        "by_credential": aggregate_by_credential(attempts),
        "attacker_profiles": build_attacker_profiles(attempts, min_attempts=1),
        "success_codes": success_codes,  # 报告输出用
    }


def print_summary(pcap_path, records_count: int, parse_ms: float,
                  stats: dict, rules: dict,
                  field_aliases: dict | None = None,
                  success_codes: frozenset[int] | None = None):
    """打印高度可疑登录凭证摘要"""

    # field_aliases / success_codes 默认值自动加载 (与 analyze() 一致)
    if field_aliases is None:
        field_aliases = load_field_aliases(_default_field_aliases_path())
    if success_codes is None:
        success_codes = LOGIN_SUCCESS_RESPONSE_CODES_DEFAULT

    # 字段别名计数 (用于顶部提示)
    user_n = len(field_aliases.get("username", []))
    pass_n = len(field_aliases.get("password", []))
    fa_hint = f"yaml 别名表 (username×{user_n} + password×{pass_n})"

    # success_codes 排序展示
    sc_str = ",".join(str(c) for c in sorted(success_codes))

    bar = "=" * 70
    print(f"\n{bar}")
    print(f"  CTF 流量登录凭证提取 — {pcap_path.name}")
    print(f"{bar}")
    print(f"  HTTP 请求数: {records_count}, 解析: {parse_ms / 1000:.1f} s")
    print(f"  过滤: POST + 命中 login_paths.yaml + 响应 ∈ {{{sc_str}}} (--login-success-code)")
    print(f"  凭证提取: form-urlencoded body, 字段名按 {fa_hint}")

    attempts = stats["attempts"]
    by_cred = stats["by_credential"]
    profiles = stats["attacker_profiles"]

    # 一、按凭证聚合 (高频尝试 = 弱密码爆破)
    print(f"\n[1] 提取的登录凭证 (按 (path_id, username, password) 聚合, 按次数降序)")
    print(f"  {'路径':<24} {'账号':<20} {'密码':<20} {'次数':>5}  {'IP数':>4}  时间范围")
    print(f"  {'-'*24} {'-'*20} {'-'*20} {'-'*5}  {'-'*4}  {'-'*32}")
    if by_cred:
        for row in by_cred[:30]:  # top 30
            pwd_show = row["password"] if row["password"] else "(空)"
            user_show = row["username"] if row["username"] else "(空)"
            time_range = f"{row['first_seen_str']} ~ {row['last_seen_str']}"
            if len(time_range) > 32:
                time_range = time_range[:29] + "..."
            print(f"  {row['path_name']:<24} {user_show:<20} {pwd_show:<20} {row['count']:>5}  "
                  f"{row['ip_count']:>4}  {time_range}")
    else:
        print(f"  未检测到任何高度可疑登录凭证")

    # 二、按攻击者 IP 画像
    print(f"\n[2] 攻击者画像 (按 IP, 总尝试次数 ≥ 1)")
    print(f"  {'IP':<18} {'尝试':>5}  {'去重凭证':>8}  {'使用的账号':<30}  {'首/末次'}")
    print(f"  {'-'*18} {'-'*5}  {'-'*8}  {'-'*30}  {'-'*32}")
    for prof in profiles[:15]:
        users = ",".join(prof["username_set"][:5])
        if len(prof["username_set"]) > 5:
            users += f"...+{len(prof['username_set']) - 5}"
        time_range = f"{prof['first_seen_str']} ~ {prof['last_seen_str']}"
        if len(time_range) > 32:
            time_range = time_range[:29] + "..."
        print(f"  {prof['ip']:<18} {prof['attempts']:>5}  {prof['unique_credentials']:>8}  "
              f"{users:<30}  {time_range}")

    # 三、关键结论 — 明文凭证清单
    print(f"\n[3] 关键结论 — 提取的明文登录凭证 (按出现次数排序, top {min(20, len(by_cred))}):")
    if by_cred:
        for i, row in enumerate(by_cred[:20], 1):
            print(f"  {i:>2}. {row['path_name']:<24} | "
                  f"username={row['username'] or '(空)':<24} | "
                  f"password={row['password'] or '(空)':<24} | "
                  f"{row['count']} 次 ({row['ip_count']} IP)")
    else:
        print(f"  未检测到高度可疑登录凭证")

    # 四、时间线 (前 30 条)
    print(f"\n[4] 登录尝试时间线 (前 {min(30, len(attempts))} 条)")
    print(f"  {'时间':<19}  {'IP':<16}  {'方法/状态':<10}  {'凭证':<40}")
    print(f"  {'-'*19}  {'-'*16}  {'-'*10}  {'-'*40}")
    for a in attempts[:30]:
        cred_str = f"u={a['username'] or '(空)'} p={a['password'] or '(空)'}"
        if len(cred_str) > 40:
            cred_str = cred_str[:37] + "..."
        ms = f"{a['method']}→{a.get('status', '?')}"
        print(f"  {a['ts_str']:<19}  {a['ip_src']:<16}  {ms:<10}  {cred_str}")
    if len(attempts) > 30:
        print(f"  ... 还有 {len(attempts) - 30} 条 (完整数据见 out/ 目录)")

    print(f"\n{bar}")
    print(f"  完成。{len(attempts)} 条高度可疑登录尝试, "
          f"提取 {len(by_cred)} 组独立凭证, "
          f"{len(profiles)} 个攻击者 IP。")
    print(f"{bar}\n")