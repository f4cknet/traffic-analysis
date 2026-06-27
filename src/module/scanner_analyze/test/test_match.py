"""test_match_scanner.py - 测三段式匹配逻辑 (重点: query 污染防护)"""
import pytest

from src.module.scanner_analyze.script import match_scanner


def _hit_for(rules, request, scanner_id: str):
    """辅助: 拿指定扫描器对 request 的命中结果 (单条)"""
    hits = match_scanner(request, rules)
    for sc, segs, w in hits:
        if sc["id"] == scanner_id:
            return (sc, segs, w)
    return None


# ============== UA 段触发 ==============

def test_match_awvs_header_segment(rules, awvs_request):
    """AWVS 主要靠 header 段触发 (Acunetix-Aspect)"""
    hit = _hit_for(rules, awvs_request, "acunetix_wvs")
    assert hit is not None
    sc, segs, w = hit
    assert "header" in segs, f"应触发 header 段, 实际: {segs}"


def test_match_awvs_payload_not_triggered_when_uri_clean(rules, awvs_request):
    """awvs_request 的 uri='/some/path?id=1' (path 无 acunetix), payload 段不应触发"""
    hit = _hit_for(rules, awvs_request, "acunetix_wvs")
    assert hit is not None
    # query 含 id=1, 不含 acunetix; path /some/path 不含 acunetix → payload 不触发
    assert "payload" not in hit[1]


def test_match_sqlmap_ua_segment(rules, sqlmap_request):
    """sqlmap UA 自带版本号, 应触发 ua 段"""
    hit = _hit_for(rules, sqlmap_request, "sqlmap")
    assert hit is not None
    sc, segs, w = hit
    assert "ua" in segs
    assert w >= 10


def test_match_nessus_ua_segment(rules, nessus_request):
    """nessus UA 'Nessus SOAP' 应触发 ua 段"""
    hit = _hit_for(rules, nessus_request, "nessus")
    assert hit is not None
    sc, segs, w = hit
    assert "ua" in segs


def test_match_normal_browser_no_hit(rules, normal_browser_request):
    """正常 Chrome 浏览器请求不应触发任何扫描器"""
    hits = match_scanner(normal_browser_request, rules)
    assert hits == [], f"正常浏览器意外触发: {[h[0]['id'] for h in hits]}"


def test_match_xff_injector(rules, awvs_request):
    """带 X-Forwarded-For 的请求应触发 xff_injector (header 段)"""
    hit = _hit_for(rules, awvs_request, "xff_injector")
    assert hit is not None
    sc, segs, w = hit
    assert "header" in segs


def test_match_returns_sorted_results(rules, mixed_records):
    """match_scanner 返回 [(sc, segs, w), ...] 列表, 每项是 3 元组"""
    for rec in mixed_records:
        hits = match_scanner(rec, rules)
        for item in hits:
            assert len(item) == 3
            assert isinstance(item[1], list)
            assert isinstance(item[2], int)


def test_match_weight_accumulation(rules, awvs_request):
    """weight 应按段累加: header 段必触发"""
    hit = _hit_for(rules, awvs_request, "acunetix_wvs")
    assert hit is not None
    sc, segs, w = hit
    # fixture 中 header 段必触发 (Acunetix-Aspect)
    assert w == sc["weight"]["header"], f"header 段 weight 累加错误: {w}"


# ============== Query 污染防护 (v0.2.0 修复重点) ==============

def test_match_query_string_NOT_trigger_payload(rules):
    """query string 含扫描器关键字时, payload 段**不**应触发 (防诱导)

    这是 v0.2.0 修复的重点: 题目可能故意把扫描器关键字塞 query 参数里
    诱导 payload_keywords 触发弱辅证, 修复后 query 不进 payload_str
    """
    rec = {
        "ts_epoch": 0, "ip_src": "1.2.3.4", "method": "GET",
        "host": "x.com",
        "uri": "/?id=$acunetix=1&tool=sqlmap",  # query 含 acunetix 和 sqlmap
        "uri_path": "/",  # path 完全干净
        "uri_query": "id=$acunetix=1&tool=sqlmap",
        "ua": "Mozilla/5.0 Chrome/120.0",
        "headers": {"Host": "x.com", "User-Agent": "Mozilla/5.0 Chrome/120.0"},
        "payload_str": "/ Mozilla/5.0 Chrome/120.0 x.com GET",  # 不含 query
    }
    hits = match_scanner(rec, rules)
    hit_ids = [h[0]["id"] for h in hits]
    # AWVS 不应触发 (payload 段; UA 段不命中; header 段不命中)
    assert "acunetix_wvs" not in hit_ids, \
        f"query 含 acunetix 不应触发 AWVS payload 段, 实际触发: {hit_ids}"
    # sqlmap 不应触发 (UA 段; query 不进 payload)
    assert "sqlmap" not in hit_ids, \
        f"query 含 sqlmap 不应触发 sqlmap payload 段, 实际触发: {hit_ids}"


def test_match_path_scanner_keyword_still_triggers(rules):
    """URI path 上含扫描器关键字时, payload 段**应**触发 (这才是合法的弱辅证)"""
    rec = {
        "ts_epoch": 0, "ip_src": "1.2.3.4", "method": "GET",
        "host": "x.com",
        "uri": "/acunetix-wvs-test-for-some-inexistent-file",  # path 含 acunetix
        "uri_path": "/acunetix-wvs-test-for-some-inexistent-file",
        "uri_query": "",
        "ua": "Mozilla/5.0 Chrome/120.0",
        "headers": {"Host": "x.com", "User-Agent": "Mozilla/5.0 Chrome/120.0"},
        "payload_str": "/acunetix-wvs-test-for-some-inexistent-file Mozilla/5.0 Chrome/120.0 x.com GET",
    }
    hit = _hit_for(rules, rec, "acunetix_wvs")
    assert hit is not None
    sc, segs, w = hit
    # path 上的 acunetix 是合法的弱辅证
    assert "payload" in segs


# ============== 边界情况 ==============

def test_match_empty_ua(rules):
    """空 UA 不应崩溃, 也不应误触发"""
    rec = {
        "ts_epoch": 0, "ip_src": "1.2.3.4", "method": "GET",
        "host": "x.com", "uri": "/", "uri_path": "/", "uri_query": "",
        "ua": "",
        "headers": {"Host": "x.com"}, "payload_str": "/ x.com GET",
    }
    hits = match_scanner(rec, rules)
    for sc, segs, w in hits:
        assert "ua" not in segs


def test_match_split_uri_helper():
    """单元测 split_uri helper (按 ? 切分, tshark 输出 path-only)"""
    from src.core import split_uri
    # 简单 path
    assert split_uri("/api/users") == ("/api/users", "")
    # path + query
    assert split_uri("/api/users?id=1&tool=sqlmap") == ("/api/users", "id=1&tool=sqlmap")
    # 只有 query (根路径 + query)
    assert split_uri("/?id=1") == ("/", "id=1")
    # query 多参数
    assert split_uri("/api?a=1&b=2&c=3") == ("/api", "a=1&b=2&c=3")
    # 空
    assert split_uri("") == ("", "")