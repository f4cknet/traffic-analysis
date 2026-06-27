"""credential_analyze/script/field_aliases.py - 登录表单字段别名表

设计目标: 从 POST body 里识别 username + password 两个字段.

策略: 按字段名匹配. 大小写不敏感. **第一条匹配** 作为 username/password (实际场景
同一个 form 只有一个用户名 + 一个密码字段, 罕见多字段冲突).

可被 yaml 覆盖 (留给 v0.4.x 扩展), 当前版本 hardcoded.
"""
from __future__ import annotations


# 用户名字段名 (按优先级排序, 第一条命中胜出)
USERNAME_FIELDS: tuple[str, ...] = (
    "username",
    "user",
    "name",
    "login",
    "email",
    "uname",
    "account",
    "userid",
    "user_id",
    "uid",
    "admin",
    "mobile",
    "phone",
    "tel",
    "log",
    "loginname",
    "login_id",
)

# 密码字段名
PASSWORD_FIELDS: tuple[str, ...] = (
    "password",
    "passwd",
    "pass",
    "pwd",
    "passw",
    "userpass",
    "user_pass",
    "loginpass",
    "login_pass",
    "secret",
    "key",
)


def find_field(form: dict, candidates: tuple[str, ...]) -> str:
    """在 urlencoded form dict 里找第一个匹配 candidates 的字段值.

    大小写不敏感. 返回空串表示没找到.

    form 是 urlencoded parser 的输出 {key: value}. 多值字段 (key 出现多次)
    取最后一个值 (符合浏览器提交习惯).
    """
    if not form:
        return ""
    # 构建 lower -> 原 key 的映射, 大小写不敏感匹配
    lower_map = {k.lower(): k for k in form.keys()}
    for cand in candidates:
        cand_lower = cand.lower()
        if cand_lower in lower_map:
            value = form[lower_map[cand_lower]]
            # form parser 已经把 list 收敛为最后一个值, 这里直接 str
            if isinstance(value, list):
                value = value[-1] if value else ""
            return str(value) if value else ""
    return ""


def extract_credentials(form: dict) -> tuple[str, str]:
    """提取 (username, password). 任一字段缺失返回 ("", "")."""
    u = find_field(form, USERNAME_FIELDS)
    p = find_field(form, PASSWORD_FIELDS)
    return u, p