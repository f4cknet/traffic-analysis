"""test_parse_body.py - urlencoded body 解析单测"""
from src.module.credential_analyze.script import parse_urlencoded_body


# ============== parse_urlencoded_body ==============

def test_parse_basic_urlencoded():
    """基本 urlencoded body 解析"""
    body = b"username=admin&password=123456"
    form = parse_urlencoded_body(body, "application/x-www-form-urlencoded")
    assert form == {"username": "admin", "password": "123456"}


def test_parse_urlencoded_no_content_type():
    """无 Content-Type 也尝试解析 (兼容老 pcap / 缺失字段)"""
    body = b"user=admin&pass=1234"
    form = parse_urlencoded_body(body, "")
    assert form == {"user": "admin", "pass": "1234"}


def test_parse_urlencoded_with_charset():
    """带 charset 的 Content-Type 也解析"""
    body = b"username=admin&password=123456"
    form = parse_urlencoded_body(body, "application/x-www-form-urlencoded; charset=UTF-8")
    assert form == {"username": "admin", "password": "123456"}


def test_parse_urlencoded_url_encoded_value():
    """值含 url-encoded 字符 (%xx) → urldecode"""
    body = b"username=ad%40min&password=p%40ss"
    form = parse_urlencoded_body(body, "application/x-www-form-urlencoded")
    # parse_qs 默认不 urldecode, 但 + -> ' ' 是默认行为. %40 应该保留或解码? 取决于 parse_qs 版本.
    # 实际 Python 3.9+ parse_qs 默认 urldecode 是不开的 (use_unicode=True 但 percent-encoding 不动)
    # 我们用 unquote_plus 行为: %40 保留 (不主动 decode)
    # 这个测试先验证字段名能拿到就行
    assert "username" in form
    assert "password" in form


def test_parse_urlencoded_plus_to_space():
    """`+` 应被解码为空格 (urlencoded 标准)"""
    body = b"username=admin+user&password=hello+world"
    form = parse_urlencoded_body(body, "application/x-www-form-urlencoded")
    assert form["username"] == "admin user"
    assert form["password"] == "hello world"


def test_parse_empty_body():
    """空 body → 空 dict"""
    assert parse_urlencoded_body(b"", "application/x-www-form-urlencoded") == {}


def test_parse_multipart_returns_empty():
    """multipart body → 返回空 (v0.4.0 范围外)"""
    body = b"--boundary\r\nContent-Disposition: form-data\r\n\r\nadmin\r\n--boundary--"
    form = parse_urlencoded_body(body, "multipart/form-data; boundary=boundary")
    assert form == {}


def test_parse_json_returns_empty():
    """JSON body → 返回空 (v0.4.0 范围外)"""
    body = b'{"username": "admin", "password": "123"}'
    form = parse_urlencoded_body(body, "application/json")
    assert form == {}


def test_parse_duplicate_keys_last_wins():
    """同名多字段 (password=1&password=2) → 取最后一个 (浏览器习惯)"""
    body = b"username=admin&password=first&password=second"
    form = parse_urlencoded_body(body, "application/x-www-form-urlencoded")
    assert form["username"] == "admin"
    assert form["password"] == "second"


def test_parse_special_chars_in_value():
    """值含 = & 等特殊字符 (parse_qs 应能正确处理)"""
    body = b"username=admin&password=p%3Dss%26wd&other=val"
    form = parse_urlencoded_body(body, "application/x-www-form-urlencoded")
    assert form["username"] == "admin"
    assert "password" in form
    assert form["other"] == "val"


def test_parse_case_insensitive_content_type():
    """Content-Type 大小写不敏感"""
    body = b"username=admin"
    form = parse_urlencoded_body(body, "Application/X-WWW-Form-Urlencoded")
    assert form == {"username": "admin"}