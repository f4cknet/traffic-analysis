"""test_field_aliases.py - 字段别名表单测"""
from src.module.credential_analyze.script import (
    DEFAULT_FIELDS,
    PASSWORD_FIELDS,
    USERNAME_FIELDS,
    extract_credentials,
    find_field,
    load_field_aliases,
)


# ============== find_field (新 API: form, category, field_aliases) ==============

def test_find_field_exact_match():
    """精确匹配"""
    assert find_field({"username": "admin"}, "username") == "admin"


def test_find_field_case_insensitive():
    """大小写不敏感"""
    assert find_field({"Username": "admin"}, "username") == "admin"
    assert find_field({"USERNAME": "admin"}, "username") == "admin"


def test_find_field_alias_user():
    """user 是 username 的别名"""
    assert find_field({"user": "admin"}, "username") == "admin"


def test_find_field_alias_user_name():
    """user_name (snake_case) 是 username 的别名 — 关键测试!"""
    assert find_field({"user_name": "admin"}, "username") == "admin"


def test_find_field_alias_log():
    """log 是 username 的别名 (WordPress)"""
    assert find_field({"log": "admin"}, "username") == "admin"


def test_find_field_password_pwd():
    """pwd 是 password 的别名"""
    assert find_field({"pwd": "123"}, "password") == "123"


def test_find_field_password_pass_word():
    """pass_word (snake_case) 是 password 的别名 — 关键测试!"""
    assert find_field({"pass_word": "123"}, "password") == "123"


def test_find_field_password_passwd():
    assert find_field({"passwd": "123"}, "password") == "123"


def test_find_field_password_pass():
    assert find_field({"pass": "123"}, "password") == "123"


def test_find_field_priority_username():
    """username 优先于 user (DEFAULT_FIELDS 顺序)"""
    form = {"user": "u", "username": "n"}
    assert find_field(form, "username") == "n"


def test_find_field_priority_password():
    """password 优先于 passwd"""
    form = {"passwd": "p", "password": "w"}
    assert find_field(form, "password") == "w"


def test_find_field_not_found():
    """找不到返回空串"""
    assert find_field({"csrf": "abc", "action": "submit"}, "username") == ""
    assert find_field({"csrf": "abc", "action": "submit"}, "password") == ""


def test_find_field_empty_form():
    assert find_field({}, "username") == ""
    assert find_field({}, "password") == ""


def test_find_field_empty_value_returns_empty():
    """空值不算命中"""
    assert find_field({"username": ""}, "username") == ""


def test_find_field_list_value():
    """list value (parse_qs 多值) → 取最后一个"""
    assert find_field({"username": ["first", "last"]}, "username") == "last"


def test_find_field_custom_aliases():
    """传自定义 aliases 时用自定义, 不用 DEFAULT"""
    custom = {"username": ["custom_user_field"], "password": ["custom_pass"]}
    assert find_field({"custom_user_field": "x"}, "username", custom) == "x"
    # 默认 username 不生效
    assert find_field({"username": "y"}, "username", custom) == ""


# ============== extract_credentials ==============

def test_extract_credentials_basic():
    u, p = extract_credentials({"username": "admin", "password": "123"})
    assert u == "admin"
    assert p == "123"


def test_extract_credentials_wp():
    u, p = extract_credentials({"log": "admin", "pwd": "password"})
    assert u == "admin"
    assert p == "password"


def test_extract_credentials_snake_case():
    """snake_case 字段名 (Django/Flask 风格)"""
    u, p = extract_credentials({"user_name": "alice", "pass_word": "secret"})
    assert u == "alice"
    assert p == "secret"


def test_extract_credentials_partial():
    """只有 username 没 password"""
    u, p = extract_credentials({"username": "admin"})
    assert u == "admin"
    assert p == ""


def test_extract_credentials_empty():
    u, p = extract_credentials({})
    assert u == ""
    assert p == ""


def test_extract_credentials_case_insensitive():
    u, p = extract_credentials({"Username": "admin", "PASSWORD": "123"})
    assert u == "admin"
    assert p == "123"


def test_extract_credentials_custom_aliases():
    custom = {"username": ["login_id"], "password": ["user_pass"]}
    u, p = extract_credentials({"login_id": "x", "user_pass": "y"}, custom)
    assert u == "x"
    assert p == "y"


# ============== load_field_aliases ==============

def test_load_default_when_no_path():
    """不传 path → 返回 DEFAULT 拷贝"""
    fields = load_field_aliases(None)
    assert "username" in fields
    assert "password" in fields
    assert "username" in fields["username"]
    # 应该是新拷贝, 修改不影响 DEFAULT
    fields["username"].append("MUTATED")
    assert "MUTATED" not in DEFAULT_FIELDS["username"]


def test_load_default_when_missing_file():
    """文件不存在 → 返回 DEFAULT"""
    fields = load_field_aliases("/nonexistent/path.yaml")
    assert "username" in fields
    assert "password" in fields


def test_load_yaml(tmp_path):
    """从 yaml 文件加载"""
    yaml_content = """
fields:
  username: [username, custom_user]
  password: [password, custom_pass]
"""
    p = tmp_path / "fa.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    fields = load_field_aliases(p)
    assert fields["username"] == ["username", "custom_user"]
    assert fields["password"] == ["password", "custom_pass"]


def test_load_yaml_partial_fallback(tmp_path):
    """yaml 只有 username 没 password → password 用 DEFAULT"""
    yaml_content = """
fields:
  username: [custom_user]
"""
    p = tmp_path / "fa_partial.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    fields = load_field_aliases(p)
    # username 用 yaml
    assert "custom_user" in fields["username"]
    # password 用 DEFAULT
    assert "password" in fields["password"]
    assert "pwd" in fields["password"]


def test_load_yaml_extra_keys(tmp_path):
    """yaml 包含额外类别 (未来扩展)"""
    yaml_content = """
fields:
  username: [username]
  password: [password]
  email: [email, mail]
  csrf_token: [csrf_token, _token]
"""
    p = tmp_path / "fa_extra.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    fields = load_field_aliases(p)
    assert "username" in fields
    assert "password" in fields
    assert "email" in fields
    assert fields["email"] == ["email", "mail"]
    assert fields["csrf_token"] == ["csrf_token", "_token"]


def test_load_yaml_invalid_fallback(tmp_path):
    """yaml 格式错误 (缺 fields 段) → DEFAULT"""
    yaml_content = "this is: not a field aliases yaml"
    p = tmp_path / "bad.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    fields = load_field_aliases(p)
    assert fields["username"] == DEFAULT_FIELDS["username"]


# ============== 默认 fields sanity ==============

def test_default_username_includes_user_name():
    """DEFAULT_FIELDS['username'] 必须含 user_name (snake_case 支持)"""
    assert "user_name" in DEFAULT_FIELDS["username"]


def test_default_password_includes_pass_word():
    """DEFAULT_FIELDS['password'] 必须含 pass_word (snake_case 支持)"""
    assert "pass_word" in DEFAULT_FIELDS["password"]


def test_default_username_count():
    """DEFAULT_FIELDS['username'] 至少 18 个别名"""
    assert len(DEFAULT_FIELDS["username"]) >= 18


def test_default_password_count():
    """DEFAULT_FIELDS['password'] 至少 10 个别名"""
    assert len(DEFAULT_FIELDS["password"]) >= 10


# ============== 兼容旧 API (USERNAME_FIELDS / PASSWORD_FIELDS tuple) ==============

def test_username_fields_tuple_compat():
    """USERNAME_FIELDS 还是 tuple 类型 (旧 API 兼容)"""
    assert isinstance(USERNAME_FIELDS, tuple)


def test_password_fields_tuple_compat():
    """PASSWORD_FIELDS 还是 tuple 类型 (旧 API 兼容)"""
    assert isinstance(PASSWORD_FIELDS, tuple)