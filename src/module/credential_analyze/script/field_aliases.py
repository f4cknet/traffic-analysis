"""credential_analyze/script/field_aliases.py - 登录表单字段别名表

设计目标: 从 POST body 里识别 username + password 两个字段.

策略: 按字段名匹配. 大小写不敏感. **第一条匹配** 作为 username/password (实际场景
同一个 form 只有一个用户名 + 一个密码字段, 罕见多字段冲突).

v0.4.x 之前: hardcoded tuple 写在代码里.
v0.4.x 之后: YAML 驱动 (rules/field_aliases.yaml), 默认值 hardcoded 兜底.

加载顺序:
  1. 显式 load_field_aliases(yaml_path) — 最高优先级
  2. DEFAULT_FIELDS — yaml 不存在或字段缺失时的兜底

字段别名规则格式:
  {
    "username": ["username", "user", "user_name", ...],   # 第一条命中胜出
    "password": ["password", "passwd", "pass_word", ...],
  }
"""
from __future__ import annotations

from pathlib import Path

import yaml


# ============== 默认字段别名 (yaml 缺失/加载失败时兜底) ==============

DEFAULT_FIELDS: dict[str, list[str]] = {
    "username": [
        "username", "user", "user_name", "name", "login", "email", "uname",
        "account", "userid", "user_id", "uid", "admin", "mobile", "phone",
        "tel", "log", "loginname", "login_id",
    ],
    "password": [
        "password", "passwd", "pass", "pass_word", "pwd", "passw",
        "userpass", "user_pass", "loginpass", "login_pass", "secret", "key",
    ],
}


def load_field_aliases(path: str | Path | None = None) -> dict[str, list[str]]:
    """
    从 YAML 加载字段别名. 如果 path 为 None 或文件不存在, 返回 DEFAULT_FIELDS 拷贝.

    YAML 格式:
        fields:
          username: [username, user, ...]
          password: [password, passwd, ...]

    返回 {category: [field_names]}. 内部查找时优先用 'username' 和 'password' 两个键.

    返回的 dict 是新拷贝, 修改不影响 DEFAULT_FIELDS / 原 yaml 数据.
    """
    if path is None:
        return {k: list(v) for k, v in DEFAULT_FIELDS.items()}

    p = Path(path)
    if not p.exists():
        return {k: list(v) for k, v in DEFAULT_FIELDS.items()}

    with open(p, "r", encoding="utf-8-sig") as f:
        data = yaml.safe_load(f)

    if not data or "fields" not in data:
        return {k: list(v) for k, v in DEFAULT_FIELDS.items()}

    fields = data["fields"]
    # 至少要有 username + password 两个键, 否则视为 yaml 不完整, 用默认值补
    result: dict[str, list[str]] = {}
    for key in ("username", "password"):
        if key in fields and isinstance(fields[key], list):
            result[key] = [str(x).strip() for x in fields[key] if str(x).strip()]
        else:
            # 缺失/格式错 → 用默认
            result[key] = list(DEFAULT_FIELDS[key])
    # 未来扩展: yaml 里额外的 key (e.g. email/csrf) 也保留
    for key, val in fields.items():
        if key not in result and isinstance(val, list):
            result[key] = [str(x).strip() for x in val if str(x).strip()]
    return result


def find_field(form: dict, category: str,
               field_aliases: dict[str, list[str]] | None = None) -> str:
    """
    在 urlencoded form dict 里找第一个匹配该 category 别名列表的字段值.

    - form: parse_urlencoded_body 输出 {key: value}
    - category: e.g. "username" / "password"
    - field_aliases: 可选, 不传则用 DEFAULT_FIELDS
    - 大小写不敏感
    - 多值字段 (key 出现多次) 取最后一个值

    返回: 字段值 (str); 没找到返回空串.
    """
    if not form:
        return ""
    aliases = (field_aliases or DEFAULT_FIELDS).get(category) or []
    if not aliases:
        return ""
    # 构建 lower -> 原 key 的映射, 大小写不敏感匹配
    lower_map = {k.lower(): k for k in form.keys()}
    for alias in aliases:
        alias_lower = alias.lower()
        if alias_lower in lower_map:
            value = form[lower_map[alias_lower]]
            if isinstance(value, list):
                value = value[-1] if value else ""
            return str(value) if value else ""
    return ""


def extract_credentials(form: dict,
                        field_aliases: dict[str, list[str]] | None = None
                        ) -> tuple[str, str]:
    """提取 (username, password). 任一字段缺失返回 ("", "")."""
    u = find_field(form, "username", field_aliases)
    p = find_field(form, "password", field_aliases)
    return u, p


# 兼容旧 API: 直接 import USERNAME_FIELDS / PASSWORD_FIELDS 也能用 (基于 DEFAULT)
USERNAME_FIELDS: tuple[str, ...] = tuple(DEFAULT_FIELDS["username"])
PASSWORD_FIELDS: tuple[str, ...] = tuple(DEFAULT_FIELDS["password"])