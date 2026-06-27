"""test_matcher.py - matcher 单测"""
from src.module.webshell_analyze.script import (
    detect_access,
    detect_upload,
    extract_url_query,
    extract_urlencoded_params,
    is_multipart_upload,
    match_webshell_path,
    parse_multipart_filename,
)


# ============== load_paths / match_webshell_path ==============

def test_match_generic_php_shell(paths_data):
    """通用 PHP webshell 文件名命中"""
    hits = match_webshell_path("/shell.php", paths_data)
    assert len(hits) == 1
    assert hits[0]["path_rule"]["id"] == "generic_php"
    assert "/shell.php" in hits[0]["hit_pattern"]


def test_match_single_char_php(paths_data):
    """单字符 PHP 名 (e.g. /a.php) 命中"""
    hits = match_webshell_path("/a.php", paths_data)
    assert len(hits) == 1


def test_match_jsp(paths_data):
    """JSP webshell 命中"""
    hits = match_webshell_path("/shell.jsp", paths_data)
    assert len(hits) == 1
    assert hits[0]["path_rule"]["id"] == "generic_jsp"


def test_match_aspx(paths_data):
    hits = match_webshell_path("/cmd.aspx", paths_data)
    assert len(hits) == 1
    assert hits[0]["path_rule"]["id"] == "generic_aspx"


def test_match_ctf_known(paths_data):
    """CTF 老题路径命中"""
    hits = match_webshell_path("/songgeshigedashuaibi/hello.html", paths_data)
    assert len(hits) == 1
    assert hits[0]["path_rule"]["id"] == "ctf_known_paths"


def test_match_upload_dir(paths_data):
    """上传目录命中"""
    hits = match_webshell_path("/upload/foo.txt", paths_data)
    assert len(hits) == 1
    assert hits[0]["path_rule"]["id"] == "upload_dir"


def test_match_longest_match_first(paths_data):
    """longest-match-first: /songgeshigedashuaibi/hello.html 应该命中 ctf_known_paths
    (/songgeshigedashuaibi/ 20字 > /upload/ 8字即便没匹配, ctf_known 覆盖更长)"""
    hits = match_webshell_path("/upload/songgeshigedashuaibi/hello.html", paths_data)
    # /songgeshigedashuaibi/ 20字最长, 胜出
    assert len(hits) == 1
    assert hits[0]["path_rule"]["id"] == "ctf_known_paths"


def test_no_match_normal(paths_data):
    """正常路径不命中"""
    assert match_webshell_path("/index.html", paths_data) == []
    assert match_webshell_path("/api/users", paths_data) == []


def test_match_case_insensitive(paths_data):
    """大小写不敏感"""
    hits = match_webshell_path("/Shell.PHP", paths_data)
    assert len(hits) == 1


def test_match_query_excluded(paths_data):
    """query string 不参与匹配 (uri_path 已剥离)"""
    hits = match_webshell_path("/shell.php?pass=xxx&cmd=id", paths_data)
    assert len(hits) == 1


# ============== is_multipart_upload ==============

def test_is_multipart_true():
    rec = {"content_type": "multipart/form-data; boundary=xxx"}
    assert is_multipart_upload(rec) is True


def test_is_multipart_uppercase():
    """Content-Type 大小写不敏感"""
    rec = {"content_type": "MULTIPART/FORM-DATA; BOUNDARY=xxx"}
    assert is_multipart_upload(rec) is True


def test_is_not_multipart_urlencoded():
    rec = {"content_type": "application/x-www-form-urlencoded"}
    assert is_multipart_upload(rec) is False


def test_is_not_multipart_empty():
    rec = {"content_type": ""}
    assert is_multipart_upload(rec) is False


def test_is_not_multipart_none():
    rec = {}
    assert is_multipart_upload(rec) is False


# ============== parse_multipart_filename ==============

def test_parse_multipart_filename_quoted():
    """filename="xxx" (带引号)"""
    body = (
        b"------BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="hello.html"\r\n'
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html></html>\r\n"
        b"------BOUNDARY--\r\n"
    )
    ct = "multipart/form-data; boundary=----BOUNDARY"
    assert parse_multipart_filename(body, ct) == "hello.html"


def test_parse_multipart_filename_unquoted():
    """filename=xxx (无引号)"""
    body = (
        b"------BOUNDARY\r\n"
        b"Content-Disposition: form-data; name=file; filename=hello.html\r\n"
        b"\r\n"
        b"data\r\n"
        b"------BOUNDARY--\r\n"
    )
    ct = "multipart/form-data; boundary=----BOUNDARY"
    assert parse_multipart_filename(body, ct) == "hello.html"


def test_parse_multipart_filename_path():
    """filename 包含路径 (Windows 风格)"""
    body = (
        b"------BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="C:\\shell.php"\r\n'
        b"\r\n"
        b"<?php system($_GET['cmd']); ?>\r\n"
        b"------BOUNDARY--\r\n"
    )
    ct = "multipart/form-data; boundary=----BOUNDARY"
    assert parse_multipart_filename(body, ct) == "C:\\shell.php"


def test_parse_multipart_filename_not_found():
    """没 filename 字段"""
    body = (
        b"------BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"\r\n'
        b"\r\n"
        b"plain text\r\n"
        b"------BOUNDARY--\r\n"
    )
    ct = "multipart/form-data; boundary=----BOUNDARY"
    assert parse_multipart_filename(body, ct) is None


def test_parse_multipart_empty_body():
    ct = "multipart/form-data; boundary=----BOUNDARY"
    assert parse_multipart_filename(b"", ct) is None


def test_parse_multipart_no_boundary():
    """没 boundary 字段"""
    body = b"some random bytes"
    ct = "multipart/form-data"  # 没 boundary
    assert parse_multipart_filename(body, ct) is None


# ============== extract_url_query ==============

def test_extract_url_query_basic():
    assert extract_url_query("/foo.php?pass=xxx&cmd=id") == {"pass": "xxx", "cmd": "id"}


def test_extract_url_query_no_query():
    assert extract_url_query("/foo.php") == {}


def test_extract_url_query_empty_value():
    """pass= (空值) 仍要拿到"""
    assert extract_url_query("/foo.php?pass=&cmd=id") == {"pass": "", "cmd": "id"}


def test_extract_url_query_duplicate_key():
    """同名 key 多次取最后一个"""
    assert extract_url_query("/foo.php?pass=a&pass=b") == {"pass": "b"}


def test_extract_url_query_special_chars():
    """特殊字符 URL 编码"""
    assert extract_url_query("/foo.php?cmd=cat+%2Fetc%2Fpasswd") == {"cmd": "cat /etc/passwd"}


# ============== extract_urlencoded_params ==============

def test_extract_urlencoded_basic():
    body = b"pass=xxx&cmd=id"
    assert extract_urlencoded_params(body, "application/x-www-form-urlencoded") == {"pass": "xxx", "cmd": "id"}


def test_extract_urlencoded_no_content_type():
    """无 Content-Type 也尝试"""
    body = b"pass=xxx&cmd=id"
    assert extract_urlencoded_params(body, "") == {"pass": "xxx", "cmd": "id"}


def test_extract_urlencoded_not_urlencoded():
    """非 urlencoded 返回空"""
    body = b'{"pass": "xxx"}'
    assert extract_urlencoded_params(body, "application/json") == {}


def test_extract_urlencoded_empty():
    assert extract_urlencoded_params(b"", "application/x-www-form-urlencoded") == {}


# ============== detect_upload ==============

def test_detect_upload_success():
    """multipart 上传 + filename 抽取成功"""
    body = (
        b"------BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="hello.html"\r\n'
        b"\r\n"
        b"data\r\n"
        b"------BOUNDARY--\r\n"
    )
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "POST",
        "host": "t.com",
        "uri": "/upload/upload.php",
        "uri_path": "/upload/upload.php",
        "content_type": "multipart/form-data; boundary=----BOUNDARY",
        "post_body_bytes": body,
        "ua": "",
    }
    u = detect_upload(rec)
    assert u is not None
    assert u["filename"] == "hello.html"
    assert u["ip_src"] == "1.2.3.4"


def test_detect_upload_not_multipart():
    rec = {
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "post_body_bytes": b"pass=xxx",
    }
    assert detect_upload(rec) is None


def test_detect_upload_multipart_no_filename():
    """multipart 但没 filename 字段 (普通表单)"""
    body = (
        b"------BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="username"\r\n'
        b"\r\n"
        b"admin\r\n"
        b"------BOUNDARY--\r\n"
    )
    rec = {
        "method": "POST",
        "content_type": "multipart/form-data; boundary=----BOUNDARY",
        "post_body_bytes": body,
    }
    assert detect_upload(rec) is None


# ============== detect_access ==============

def test_detect_access_by_path(paths_data, field_aliases):
    """路径命中 + 无密码参数 → 仍算访问"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "GET",
        "host": "t.com",
        "uri": "/shell.php",
        "uri_path": "/shell.php",
        "content_type": "",
        "post_body_bytes": b"",
        "ua": "",
    }
    a = detect_access(rec, paths_data, field_aliases)
    assert a is not None
    assert a["path_id"] == "generic_php"
    assert a["source"] == "path_match"
    assert a["password"] == ""  # 没密码参数


def test_detect_access_by_url_param(paths_data, field_aliases):
    """URL 参数含密码字段 (路径不命中)"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "GET",
        "host": "t.com",
        "uri": "/api?pass=xxx&cmd=id",
        "uri_path": "/api",
        "content_type": "",
        "post_body_bytes": b"",
        "ua": "",
    }
    a = detect_access(rec, paths_data, field_aliases)
    assert a is not None
    assert a["password"] == "xxx"
    assert a["cmd"] == "id"
    assert a["source"] == "url_param"


def test_detect_access_by_body_param(paths_data, field_aliases):
    """body 参数含密码字段 (路径不命中 + URL 无密码)"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "POST",
        "host": "t.com",
        "uri": "/api/users",
        "uri_path": "/api/users",
        "content_type": "application/x-www-form-urlencoded",
        "post_body_bytes": b"pass=xxx&cmd=whoami",
        "ua": "",
    }
    a = detect_access(rec, paths_data, field_aliases)
    assert a is not None
    assert a["password"] == "xxx"
    assert a["cmd"] == "whoami"
    assert a["source"] == "body_param"


def test_detect_access_no_match(paths_data, field_aliases):
    """路径不命中 + 无密码参数 → 不算访问"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "GET",
        "host": "t.com",
        "uri": "/index.html",
        "uri_path": "/index.html",
        "content_type": "",
        "post_body_bytes": b"",
        "ua": "",
    }
    assert detect_access(rec, paths_data, field_aliases) is None


def test_detect_access_path_and_password(paths_data, field_aliases):
    """路径命中 + 密码参数都有 → source=path_match (优先)"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "POST",
        "host": "t.com",
        "uri": "/shell.php?pass=xxx&cmd=id",
        "uri_path": "/shell.php",
        "content_type": "application/x-www-form-urlencoded",
        "post_body_bytes": b"pass=xxx&cmd=id",
        "ua": "",
    }
    a = detect_access(rec, paths_data, field_aliases)
    assert a is not None
    assert a["source"] == "path_match"
    assert a["password"] == "xxx"
    assert a["cmd"] == "id"


def test_detect_access_numerics(paths_data, field_aliases):
    """数字字段 (0, 1) — 蚁剑默认密码字段"""
    rec = {
        "ts_epoch": 1700000000,
        "ip_src": "1.2.3.4",
        "stream_id": "s1",
        "method": "POST",
        "host": "t.com",
        "uri": "/shell.php",
        "uri_path": "/shell.php",
        "content_type": "application/x-www-form-urlencoded",
        "post_body_bytes": b"0=antpassword&1=cat+/etc/passwd",
        "ua": "",
    }
    a = detect_access(rec, paths_data, field_aliases)
    assert a is not None
    assert a["password"] == "antpassword"
    assert a["cmd"] == "cat /etc/passwd"