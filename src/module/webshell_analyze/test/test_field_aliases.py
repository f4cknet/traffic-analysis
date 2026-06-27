"""test_field_aliases.py - 字段别名表单测"""
from src.module.webshell_analyze.script import (
    CMD_FIELDS,
    DEFAULT_FIELDS,
    PASSWORD_FIELDS,
    extract_webshell_params,
    find_field,
    load_field_aliases,
)


# ============== find_field ==============

def test_find_password_pass():
    assert find_field({"pass": "xxx"}, "password") == "xxx"


def test_find_password_pwd():
    assert find_field({"pwd": "xxx"}, "password") == "xxx"


def test_find_password_key():
    assert find_field({"key": "xxx"}, "password") == "xxx"


def test_find_password_x():
    assert find_field({"x": "xxx"}, "password") == "xxx"


def test_find_password_z0():
    assert find_field({"z0": "xxx"}, "password") == "xxx"


def test_find_password_digit_0():
    """数字字段 0 (蚁剑默认)"""
    assert find_field({"0": "antpassword"}, "password") == "antpassword"


def test_find_password_digit_1_not_password():
    """数字字段 1 不是 password 默认字段 (是 cmd 字段名)"""
    assert find_field({"1": "cmdval"}, "password") == ""


def test_find_password_case_insensitive():
    assert find_field({"Pass": "xxx"}, "password") == "xxx"


def test_find_password_not_found():
    assert find_field({"foo": "xxx", "bar": "yyy"}, "password") == ""


def test_find_password_priority():
    """pass 优先于 pwd"""
    form = {"pass": "first", "pwd": "second"}
    assert find_field(form, "password") == "first"


def test_find_cmd_cmd():
    assert find_field({"cmd": "id"}, "cmd") == "id"


def test_find_cmd_c():
    assert find_field({"c": "id"}, "cmd") == "id"


def test_find_cmd_command():
    assert find_field({"command": "id"}, "cmd") == "id"


def test_find_cmd_digit_1():
    assert find_field({"1": "cat /etc/passwd"}, "cmd") == "cat /etc/passwd"


def test_find_empty():
    assert find_field({}, "password") == ""
    assert find_field(None, "password") == ""


# ============== extract_webshell_params ==============

def test_extract_both():
    pwd, cmd_val = extract_webshell_params({"pass": "xxx", "cmd": "id"})
    assert pwd == "xxx"
    assert cmd_val == "id"


def test_extract_only_password():
    pwd, cmd_val = extract_webshell_params({"pass": "xxx"})
    assert pwd == "xxx"
    assert cmd_val == ""


def test_extract_only_cmd():
    pwd, cmd_val = extract_webshell_params({"cmd": "id"})
    assert pwd == ""
    assert cmd_val == "id"


def test_extract_empty():
    pwd, cmd_val = extract_webshell_params({})
    assert pwd == ""
    assert cmd_val == ""


def test_extract_custom_aliases():
    custom = {"password": ["my_pwd"], "cmd": ["my_cmd"]}
    pwd, cmd_val = extract_webshell_params({"my_pwd": "x", "my_cmd": "y"}, custom)
    assert pwd == "x"
    assert cmd_val == "y"


# ============== load_field_aliases ==============

def test_load_default_when_none():
    fields = load_field_aliases(None)
    assert "password" in fields
    assert "cmd" in fields


def test_load_default_when_missing():
    fields = load_field_aliases("/nonexistent.yaml")
    assert "password" in fields


def test_load_yaml(tmp_path):
    yaml_content = """
fields:
  password: [custom_pwd, my_key]
  cmd: [custom_cmd, my_c]
"""
    p = tmp_path / "fa.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    fields = load_field_aliases(p)
    assert "custom_pwd" in fields["password"]
    assert "my_key" in fields["password"]
    assert "custom_cmd" in fields["cmd"]


def test_load_yaml_partial_fallback(tmp_path):
    yaml_content = """
fields:
  password: [custom_pwd]
"""
    p = tmp_path / "fa.yaml"
    p.write_text(yaml_content, encoding="utf-8")
    fields = load_field_aliases(p)
    # cmd 用 DEFAULT
    assert "cmd" in fields["cmd"]
    assert "cmd" in fields["cmd"]


# ============== DEFAULT_FIELDS sanity ==============

def test_default_password_includes_pass():
    assert "pass" in DEFAULT_FIELDS["password"]


def test_default_password_includes_digit():
    """蚁剑默认 0"""
    assert "0" in DEFAULT_FIELDS["password"]


def test_default_cmd_includes_cmd():
    assert "cmd" in DEFAULT_FIELDS["cmd"]


def test_default_count():
    assert len(DEFAULT_FIELDS["password"]) >= 8
    assert len(DEFAULT_FIELDS["cmd"]) >= 8


# ============== 旧 API 兼容 ==============

def test_password_fields_tuple():
    assert isinstance(PASSWORD_FIELDS, tuple)


def test_cmd_fields_tuple():
    assert isinstance(CMD_FIELDS, tuple)