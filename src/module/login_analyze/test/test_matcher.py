"""test_matcher.py - 测单条记录路径匹配 (含 query 污染防护)"""
import pytest

from src.module.login_analyze.script import match_login_path


def test_match_admin_login(paths_data, make_record):
    rec = make_record(0, "1.2.3.4", "GET", "x.com", "/admin/login")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    assert "admin_generic" in ids


def test_match_wp_login(paths_data, make_record):
    rec = make_record(0, "1.2.3.4", "GET", "x.com", "/wp-login.php")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    assert "wordpress" in ids


def test_match_phpmyadmin(paths_data, make_record):
    rec = make_record(0, "1.2.3.4", "GET", "x.com", "/phpmyadmin/index.php")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    assert "phpmyadmin" in ids


def test_match_tomcat_manager(paths_data, make_record):
    rec = make_record(0, "1.2.3.4", "GET", "x.com", "/manager/html")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    assert "tomcat" in ids


def test_match_spring_boot_actuator(paths_data, make_record):
    rec = make_record(0, "1.2.3.4", "GET", "x.com", "/actuator/env")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    assert "spring_boot" in ids


def test_match_normal_page_no_hit(paths_data, make_record):
    """普通页面不应触发"""
    for uri in ("/index.html", "/static/main.css", "/api/products", "/about"):
        rec = make_record(0, "1.2.3.4", "GET", "x.com", uri)
        hits = match_login_path(rec, paths_data)
        assert hits == [], f"{uri} 意外触发: {[h['path_rule']['id'] for h in hits]}"


def test_match_case_insensitive(paths_data, make_record):
    """大小写不敏感 (匹配时 lower 比较)"""
    rec = make_record(0, "1.2.3.4", "GET", "x.com", "/ADMIN/Login.PHP")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    assert "admin_generic" in ids


# ============== Query 污染防护 (与 scanner 一致) ==============

def test_match_query_string_NOT_trigger(paths_data, make_record):
    """query string 含登录路径关键字时不触发 (防题目诱导)"""
    rec = make_record(0, "1.2.3.4", "GET", "x.com", "/api?id=/admin/login&next=phpmyadmin")
    hits = match_login_path(rec, paths_data)
    # uri_path = '/api', 不含 admin/login 或 phpmyadmin -> 不触发
    assert hits == [], f"query 不应触发: {[h['path_rule']['id'] for h in hits]}"


def test_match_path_keyword_still_triggers(paths_data, make_record):
    """URI path 上含登录路径关键字应触发 (合法访问)"""
    rec = make_record(0, "1.2.3.4", "GET", "x.com", "/admin/login.php?next=dashboard")
    hits = match_login_path(rec, paths_data)
    assert any(h["path_rule"]["id"] == "admin_generic" for h in hits)


def test_match_empty_uri_path(paths_data, make_record):
    """空 uri_path 不应崩溃"""
    rec = make_record(0, "1.2.3.4", "GET", "x.com", "")
    # _make_record 用 split_uri("") 返回 ("", "")
    rec["uri_path"] = ""
    hits = match_login_path(rec, paths_data)
    assert hits == []


def test_match_only_one_path_rule_per_record(paths_data, make_record):
    """一条记录只触发 yaml 顺序中第一个 path_rule (精确优先, 避免 overlap)"""
    rec = make_record(0, "1.2.3.4", "GET", "x.com", "/admin/login")
    hits = match_login_path(rec, paths_data)
    ids = [h["path_rule"]["id"] for h in hits]
    # admin_generic 在 yaml 里排第一, 优先匹配
    # /admin/login 不会再触发 login_generic (因为 yaml 顺序里 admin_generic 先)
    assert ids == ["admin_generic"]