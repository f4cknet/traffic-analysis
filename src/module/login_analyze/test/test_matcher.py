"""test_matcher.py - 测单条记录路径匹配 (含 query 污染防护 + 大小写不敏感)"""
import pytest

from src.module.login_analyze.script import match_login_path


def test_match_admin_login(paths_data, make_record):
    """/admin/login 应命中 login_generic (yaml 内具体 pattern 优先)"""
    rec = make_record(0, "1.2.3.4", "POST", "x.com", "/admin/login")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    assert "login_generic" in ids


def test_match_wp_login(paths_data, make_record):
    rec = make_record(0, "1.2.3.4", "POST", "x.com", "/wp-login.php")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    assert "wordpress" in ids


def test_match_phpmyadmin(paths_data, make_record):
    rec = make_record(0, "1.2.3.4", "POST", "x.com", "/phpmyadmin/index.php")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    assert "phpmyadmin" in ids


def test_match_drupal(paths_data, make_record):
    """/user/login 命中 login_generic (drupal rule 已删除, 被 login_generic 覆盖)"""
    rec = make_record(0, "1.2.3.4", "POST", "x.com", "/user/login")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    assert "login_generic" in ids


def test_match_weblogic_console(paths_data, make_record):
    """/console/login (长度 14) 比 /login (长度 6) 长 → longest-match 让 weblogic 胜出"""
    rec = make_record(0, "1.2.3.4", "POST", "x.com", "/console/login")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    assert "weblogic" in ids


def test_match_normal_page_no_hit(paths_data, make_record):
    """普通页面不应触发 (不是登录接口, 不在 yaml)"""
    for uri in ("/index.html", "/static/main.css", "/api/products", "/about",
                "/admin", "/admin/", "/user/register", "/dede/index.php"):
        rec = make_record(0, "1.2.3.4", "POST", "x.com", uri)
        hits = match_login_path(rec, paths_data)
        assert hits == [], f"{uri} 意外触发: {[h['path_rule']['id'] for h in hits]}"


def test_match_case_insensitive(paths_data, make_record):
    """大小写不敏感 (匹配时 lower 比较)"""
    rec = make_record(0, "1.2.3.4", "POST", "x.com", "/ADMIN/Login.PHP")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    # URI lower 后 = /admin/login.php → login_generic (精确先)
    assert "login_generic" in ids


# ============== Query 污染防护 (与 scanner 一致) ==============

def test_match_query_string_NOT_trigger(paths_data, make_record):
    """query string 含登录路径关键字时不触发 (防题目诱导)"""
    rec = make_record(0, "1.2.3.4", "POST", "x.com", "/api?id=/admin/login&next=phpmyadmin")
    hits = match_login_path(rec, paths_data)
    # uri_path = '/api', 不含登录关键字 -> 不触发
    assert hits == [], f"query 不应触发: {[h['path_rule']['id'] for h in hits]}"


def test_match_path_keyword_triggers(paths_data, make_record):
    """URI path 上含登录路径关键字应触发 (合法访问)"""
    rec = make_record(0, "1.2.3.4", "POST", "x.com", "/admin/login.php?next=dashboard")
    hits = match_login_path(rec, paths_data)
    assert any(h["path_rule"]["id"] == "login_generic" for h in hits)


def test_match_empty_uri_path(paths_data, make_record):
    """空 uri_path 不应崩溃"""
    rec = make_record(0, "1.2.3.4", "POST", "x.com", "")
    rec["uri_path"] = ""
    hits = match_login_path(rec, paths_data)
    assert hits == []


def test_match_only_one_path_rule_per_record(paths_data, make_record):
    """一条记录只触发 yaml 顺序中第一个 path_rule (精确优先, 避免 overlap)"""
    rec = make_record(0, "1.2.3.4", "POST", "x.com", "/admin/login")
    hits = match_login_path(rec, paths_data)
    # /admin/login 精确匹配 login_generic 的 "/admin/login" pattern (排在前)
    ids = [h["path_rule"]["id"] for h in hits]
    assert ids == ["login_generic"]
