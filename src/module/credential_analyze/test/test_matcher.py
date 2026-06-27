"""test_matcher.py - 凭证提取单测"""
from src.module.credential_analyze.script import (
    extract_credentials_from_request,
    is_suspicious_login_success,
)


# ============== extract_credentials_from_request ==============

def test_extract_basic_username_password(paths_data):
    """基本 username/password 字段提取"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "POST",
        "host": "target.com",
        "uri": "/admin/login.php?rec=login",
        "uri_path": "/admin/login.php",
        "uri_query": "rec=login",
        "ua": "Mozilla/5.0",
        "headers": {},
        "content_type": "application/x-www-form-urlencoded",
        "post_body_bytes": b"username=admin&password=123456",
    }
    cred = extract_credentials_from_request(rec, paths_data)
    assert cred is not None
    assert cred["username"] == "admin"
    assert cred["password"] == "123456"
    assert cred["path_name"]  # 非空


def test_extract_wp_login_log_pwd(paths_data):
    """WordPress 用 log/pwd 别名"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "POST",
        "host": "target.com",
        "uri": "/wp-login.php",
        "uri_path": "/wp-login.php",
        "uri_query": "",
        "ua": "Mozilla/5.0",
        "headers": {},
        "content_type": "application/x-www-form-urlencoded",
        "post_body_bytes": b"log=admin&pwd=password&wp-submit=Log+In",
    }
    cred = extract_credentials_from_request(rec, paths_data)
    assert cred is not None
    assert cred["username"] == "admin"   # log 别名
    assert cred["password"] == "password"  # pwd 别名


def test_extract_get_returns_none(paths_data):
    """GET 请求不算登录尝试 → 返回 None"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "GET",
        "host": "target.com",
        "uri": "/admin/login.php",
        "uri_path": "/admin/login.php",
        "uri_query": "",
        "ua": "Mozilla/5.0",
        "headers": {},
        "content_type": "",
        "post_body_bytes": b"",
    }
    assert extract_credentials_from_request(rec, paths_data) is None


def test_extract_non_login_path_returns_none(paths_data):
    """非登录路径 (e.g. /api/users) → 返回 None"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "POST",
        "host": "target.com",
        "uri": "/api/users",
        "uri_path": "/api/users",
        "uri_query": "",
        "ua": "Mozilla/5.0",
        "headers": {},
        "content_type": "application/x-www-form-urlencoded",
        "post_body_bytes": b"username=admin&password=123",
    }
    assert extract_credentials_from_request(rec, paths_data) is None


def test_extract_multipart_returns_none(paths_data):
    """multipart body → v0.4.0 不支持 → 返回 None"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "POST",
        "host": "target.com",
        "uri": "/admin/login.php",
        "uri_path": "/admin/login.php",
        "uri_query": "",
        "ua": "Mozilla/5.0",
        "headers": {},
        "content_type": "multipart/form-data; boundary=xxx",
        "post_body_bytes": b"--xxx\r\nadmin\r\n--xxx--",
    }
    assert extract_credentials_from_request(rec, paths_data) is None


def test_extract_no_credentials_returns_none(paths_data):
    """body 解析成功但没找到 username/password → 返回 None"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "POST",
        "host": "target.com",
        "uri": "/admin/login.php",
        "uri_path": "/admin/login.php",
        "uri_query": "",
        "ua": "Mozilla/5.0",
        "headers": {},
        "content_type": "application/x-www-form-urlencoded",
        "post_body_bytes": b"action=submit&csrf=abc",
    }
    assert extract_credentials_from_request(rec, paths_data) is None


def test_extract_wp_login_get_allowed(paths_data):
    """WordPress 允许 GET 表单提交 — 但 GET 不带 body 字段, 返回 None (没凭证)"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "GET",
        "host": "target.com",
        "uri": "/wp-login.php?log=admin&pwd=test",
        "uri_path": "/wp-login.php",
        "uri_query": "log=admin&pwd=test",
        "ua": "Mozilla/5.0",
        "headers": {},
        "content_type": "",
        "post_body_bytes": b"",
    }
    # wp-login 允许 GET 但没 POST body → 解析失败 → None
    assert extract_credentials_from_request(rec, paths_data) is None


# ============== is_suspicious_login_success ==============

def test_suspicious_200():
    rec = {"method": "POST"}
    assert is_suspicious_login_success(rec, 200) is True


def test_suspicious_302():
    """302 是金标准登录成功"""
    rec = {"method": "POST"}
    assert is_suspicious_login_success(rec, 302) is True


def test_suspicious_303():
    rec = {"method": "POST"}
    assert is_suspicious_login_success(rec, 303) is True


def test_suspicious_404_not():
    """404 不算"""
    rec = {"method": "POST"}
    assert is_suspicious_login_success(rec, 404) is False


def test_suspicious_500_not():
    rec = {"method": "POST"}
    assert is_suspicious_login_success(rec, 500) is False


def test_suspicious_get_not():
    """GET 不算 (即使响应 200)"""
    rec = {"method": "GET"}
    assert is_suspicious_login_success(rec, 200) is False


def test_suspicious_no_status():
    """无响应状态 → 不算"""
    rec = {"method": "POST"}
    assert is_suspicious_login_success(rec, None) is False