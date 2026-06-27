"""webshell_analyze/script/field_aliases.py - webshell 访问字段别名表

跟 credential_analyze/script/field_aliases.py 思路相同: yaml 驱动 + 默认兜底.

类别:
  - password: webshell 密码字段 (URL query 或 body)
  - cmd:      webshell 命令字段 (URL query 或 body)

实战经验 (来自菜刀/蚁剑/冰蝎/哥斯拉):
  - 中国菜刀: 字段名任意, 密码字段固定
  - 蚁剑:     默认 0 / 1
  - 冰蝎:     pass + key (AES 加密 body)
  - 哥斯拉:   类似冰蝎
"""
from __future__ import annotations

from pathlib import Path

import yaml


# ============== 默认字段别名 (yaml 缺失时兜底) ==============

DEFAULT_FIELDS: dict[str, list[str]] = {
    "password": [
        "pass", "pwd", "password", "key", "code", "x",
        "z0", "z1", "z2", "0",
    ],
    "cmd": [
        "cmd", "c", "command", "exec", "run", "action", "do", "query", "sql", "1",
    ],
}


def load_field_aliases(path: str | Path | None = None) -> dict[str, list[str]]:
    """
    从 YAML 加载字段别名. path=None 或文件不存在 → DEFAULT 拷贝.

    返回 {category: [field_names]}. 修改不影响 DEFAULT.
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
    result: dict[str, list[str]] = {}
    for key in ("password", "cmd"):
        if key in fields and isinstance(fields[key], list):
            result[key] = [str(x).strip() for x in fields[key] if str(x).strip()]
        else:
            result[key] = list(DEFAULT_FIELDS[key])
    # 额外 key (未来扩展)
    for key, val in fields.items():
        if key not in result and isinstance(val, list):
            result[key] = [str(x).strip() for x in val if str(x).strip()]
    return result


def find_field(form_or_params: dict, category: str,
               field_aliases: dict[str, list[str]] | None = None) -> str:
    """
    在 dict (URL params 或 urlencoded form) 里找第一个匹配该 category 别名的字段值.

    大小写不敏感. 多值字段取最后一个.

    返回: 字段值 (str); 没找到返回空串.
    """
    if not form_or_params:
        return ""
    aliases = (field_aliases or DEFAULT_FIELDS).get(category) or []
    if not aliases:
        return ""
    # 注意: 单字符字段 (0, 1, x, c) 不区分大小写
    # 但数字字段 (0, 1) 不能 lower() — 所以这里同时查 "原 key" 和 "lower key"
    keys_lower = {k.lower(): k for k in form_or_params.keys()}
    for alias in aliases:
        # 数字字段 (e.g. "0") 必须原样匹配
        if alias.isdigit():
            if alias in form_or_params:
                value = form_or_params[alias]
                if isinstance(value, list):
                    value = value[-1] if value else ""
                return str(value) if value else ""
        # 字母字段大小写不敏感
        alias_lower = alias.lower()
        if alias_lower in keys_lower:
            value = form_or_params[keys_lower[alias_lower]]
            if isinstance(value, list):
                value = value[-1] if value else ""
            return str(value) if value else ""
    return ""


def extract_webshell_params(params: dict,
                            field_aliases: dict[str, list[str]] | None = None
                            ) -> tuple[str, str]:
    """提取 (password, cmd)."""
    pwd = find_field(params, "password", field_aliases)
    cmd_val = find_field(params, "cmd", field_aliases)
    return pwd, cmd_val


# 兼容旧 API
PASSWORD_FIELDS: tuple[str, ...] = tuple(DEFAULT_FIELDS["password"])
CMD_FIELDS: tuple[str, ...] = tuple(DEFAULT_FIELDS["cmd"])