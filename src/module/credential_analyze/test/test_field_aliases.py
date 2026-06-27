"""test_field_aliases.py - 字段别名表单测"""
from src.module.credential_analyze.script import (
    PASSWORD_FIELDS,
    USERNAME_FIELDS,
    extract_credentials,
    find_field,
)


# ============== find_field ==============

def test_find_field_exact_match():
    """精确匹配"""
    assert find_field({"username": "admin"}, USERNAME_FIELDS) == "admin"


def test_find_field_case_insensitive():
    """大小写不敏感"""
    assert find_field({"Username": "admin"}, USERNAME_FIELDS) == "admin"
    assert find_field({"USERNAME": "admin"}, USERNAME_FIELDS) == "admin"


def test_find_field_alias_user():
    """user 是 username 的别名"""
    assert find_field({"user": "admin"}, USERNAME_FIELDS) == "admin"


def test_find_field_alias_log():
    """log 是 username 的别名 (WordPress)"""
    assert find_field({"log": "admin"}, USERNAME_FIELDS) == "admin"


def test_find_field_password_pwd():
    """pwd 是 password 的别名"""
    assert find_field({"pwd": "123"}, PASSWORD_FIELDS) == "123"


def test_find_field_password_passwd():
    assert find_field({"passwd": "123"}, PASSWORD_FIELDS) == "123"


def test_find_field_password_pass():
    assert find_field({"pass": "123"}, PASSWORD_FIELDS) == "123"


def test_find_field_priority_username():
    """username 优先于 user (USERNAME_FIELDS 顺序)"""
    form = {"user": "u", "username": "n"}
    assert find_field(form, USERNAME_FIELDS) == "n"


def test_find_field_priority_password():
    """password 优先于 passwd"""
    form = {"passwd": "p", "password": "w"}
    assert find_field(form, PASSWORD_FIELDS) == "w"


def test_find_field_not_found():
    """找不到返回空串"""
    assert find_field({"csrf": "abc", "action": "submit"}, USERNAME_FIELDS) == ""
    assert find_field({"csrf": "abc", "action": "submit"}, PASSWORD_FIELDS) == ""


def test_find_field_empty_form():
    assert find_field({}, USERNAME_FIELDS) == ""
    assert find_field({}, PASSWORD_FIELDS) == ""


def test_find_field_empty_value_returns_empty():
    """空值不算命中"""
    assert find_field({"username": ""}, USERNAME_FIELDS) == ""


def test_find_field_list_value():
    """list value (parse_qs 多值) → 取最后一个"""
    assert find_field({"username": ["first", "last"]}, USERNAME_FIELDS) == "last"


# ============== extract_credentials ==============

def test_extract_credentials_basic():
    u, p = extract_credentials({"username": "admin", "password": "123"})
    assert u == "admin"
    assert p == "123"


def test_extract_credentials_wp():
    u, p = extract_credentials({"log": "admin", "pwd": "password"})
    assert u == "admin"
    assert p == "password"


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